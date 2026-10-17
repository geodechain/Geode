// This file is part of Substrate.

// Copyright (C) 2018-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use libp2p::{
	bandwidth,
	core::{
		either::EitherTransport,
		muxing::StreamMuxerBox,
		transport::{Boxed, OptionalTransport},
		upgrade,
	},
	dns, identity, noise, tcp, websocket, PeerId, Transport,
};
use std::{sync::Arc, time::Duration};

pub use self::bandwidth::BandwidthSinks;

/// Builds the transport that serves as a common ground for all connections.
///
/// If `memory_only` is true, then only communication within the same process are allowed. Only
/// addresses with the format `/memory/...` are allowed.
///
/// `yamux_window_size` is the maximum size of the Yamux receive windows. `None` to leave the
/// default (256kiB).
///
/// `yamux_maximum_buffer_size` is the maximum allowed size of the Yamux buffer. This should be
/// set either to the maximum of all the maximum allowed sizes of messages frames of all
/// high-level protocols combined, or to some generously high value if you are sure that a maximum
/// size is enforced on all high-level protocols.
///
/// Returns a `BandwidthSinks` object that allows querying the average bandwidth produced by all
/// the connections spawned with this transport.
pub fn build_transport(
	keypair: identity::Keypair,
	memory_only: bool,
	yamux_window_size: Option<u32>,
	yamux_maximum_buffer_size: usize,
) -> (Boxed<(PeerId, StreamMuxerBox)>, Arc<BandwidthSinks>) {
	// Build the base layer of the transport.
	let transport = if !memory_only {
		let tcp_config = tcp::GenTcpConfig::new().nodelay(true);
		let desktop_trans = tcp::TokioTcpTransport::new(tcp_config.clone());
		let desktop_trans = websocket::WsConfig::new(desktop_trans)
			.or_transport(tcp::TokioTcpTransport::new(tcp_config.clone()));
		let dns_init = dns::TokioDnsConfig::system(desktop_trans);
		EitherTransport::Left(if let Ok(dns) = dns_init {
			EitherTransport::Left(dns)
		} else {
			let desktop_trans = tcp::TokioTcpTransport::new(tcp_config.clone());
			let desktop_trans = websocket::WsConfig::new(desktop_trans)
				.or_transport(tcp::TokioTcpTransport::new(tcp_config));
			EitherTransport::Right(desktop_trans.map_err(dns::DnsErr::Transport))
		})
	} else {
		EitherTransport::Right(OptionalTransport::some(
			libp2p::core::transport::MemoryTransport::default(),
		))
	};

	let (transport, bandwidth) = bandwidth::BandwidthLogging::new(transport);

	let authentication_config =
		{
			// For more information about these two panics, see in "On the Importance of
			// Checking Cryptographic Protocols for Faults" by Dan Boneh, Richard A. DeMillo,
			// and Richard J. Lipton.
			let noise_keypair = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&keypair)
			.expect("can only fail in case of a hardware bug; since this signing is performed only \
				once and at initialization, we're taking the bet that the inconvenience of a very \
				rare panic here is basically zero");

			// Legacy noise configurations for backward compatibility.
			let noise_legacy =
				noise::LegacyConfig { recv_legacy_handshake: true, ..Default::default() };

			let mut xx_config = noise::NoiseConfig::xx(noise_keypair);
			xx_config.set_legacy_config(noise_legacy);
			xx_config.into_authenticated()
		};

	// Only yamux is offered: mplex has no flow control and unbounded per-stream buffers.
	let multiplexing_config = {
		let mut yamux_config = libp2p::yamux::YamuxConfig::default();
		// Enable proper flow-control: window updates are only sent when
		// buffered data has been consumed.
		yamux_config.set_window_update_mode(libp2p::yamux::WindowUpdateMode::on_read());
		yamux_config.set_max_buffer_size(yamux_maximum_buffer_size);

		if let Some(yamux_window_size) = yamux_window_size {
			yamux_config.set_receive_window_size(yamux_window_size);
		}

		yamux_config
	};

	let transport = transport
		.upgrade(upgrade::Version::V1Lazy)
		.authenticate(authentication_config)
		.multiplex(multiplexing_config)
		.timeout(Duration::from_secs(20))
		.boxed();

	(transport, bandwidth)
}

#[cfg(test)]
mod tests {
	use super::*;
	use futures::prelude::*;
	use libp2p::{
		core::transport::{MemoryTransport, TransportEvent},
		mplex, Multiaddr,
	};

	const MAX_BUFFER: usize = 16 * 1024 * 1024;

	#[tokio::test]
	async fn mplex_only_dialer_cannot_connect() {
		let (mut listener, _) =
			build_transport(identity::Keypair::generate_ed25519(), true, None, MAX_BUFFER);
		let addr: Multiaddr = "/memory/917263541".parse().unwrap();
		listener.listen_on(addr.clone()).unwrap();
		tokio::spawn(async move {
			loop {
				if let TransportEvent::Incoming { upgrade, .. } = listener.select_next_some().await
				{
					tokio::spawn(async move {
						let _ = upgrade.await;
					});
				}
			}
		});

		let noise_config = || {
			let keypair = identity::Keypair::generate_ed25519();
			let keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&keypair).unwrap();
			noise::NoiseConfig::xx(keys).into_authenticated()
		};

		// Control: the same dialer offering yamux connects, so the failure below is the muxer.
		let mut yamux_dialer = MemoryTransport::default()
			.upgrade(upgrade::Version::V1)
			.authenticate(noise_config())
			.multiplex(libp2p::yamux::YamuxConfig::default())
			.timeout(Duration::from_secs(5))
			.boxed();
		assert!(yamux_dialer.dial(addr.clone()).unwrap().await.is_ok());

		// A peer that only offers mplex (F193) fails to negotiate a muxer.
		let mut mplex_dialer = MemoryTransport::default()
			.upgrade(upgrade::Version::V1)
			.authenticate(noise_config())
			.multiplex(mplex::MplexConfig::new())
			.timeout(Duration::from_secs(5))
			.boxed();
		assert!(mplex_dialer.dial(addr.clone()).unwrap().await.is_err());

		// A normal (yamux) peer still connects.
		let (mut dialer, _) =
			build_transport(identity::Keypair::generate_ed25519(), true, None, MAX_BUFFER);
		assert!(dialer.dial(addr).unwrap().await.is_ok());
	}
}
