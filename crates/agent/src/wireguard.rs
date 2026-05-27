//! WireGuard mesh management for the Forge agent.
//!
//! When the `wireguard` feature is enabled, the agent can bring up a WireGuard
//! interface and participate in a secure overlay mesh managed by the control plane.

use crate::config::AgentConfig;
use tracing::warn;

#[cfg(feature = "wireguard")]
use defguard_wireguard_rs::{host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, WGApi, WireguardInterfaceApi};

pub fn initialize_wireguard(config: &AgentConfig) -> anyhow::Result<()> {
    if !config.enable_wireguard {
        return Ok(());
    }

    if config.wireguard_private_key.is_empty() {
        warn!("WireGuard enabled but no private key provided — skipping interface creation (will be populated during enrollment)");
        return Ok(());
    }

    #[cfg(all(feature = "wireguard", target_os = "linux"))]
    {
        use defguard_wireguard_rs::{host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, WGApi, WireguardInterfaceApi};

        info!(
            interface = %config.wireguard_interface,
            "Bringing up WireGuard interface (defguard backend)"
        );

        let api = WGApi::new(config.wireguard_interface.clone(), false)?;

        let private_key = Key::from_str(&config.wireguard_private_key)?;

        let mut host = defguard_wireguard_rs::host::Host::new(
            private_key,
            Some(config.wireguard_listen_port),
            vec![], // will be populated from control plane later
        );

        // Parse bootstrap peers if any (format: "pubkey@endpoint")
        for peer_str in &config.wireguard_peers {
            if let Some((pubkey, endpoint)) = peer_str.split_once('@') {
                if let Ok(key) = Key::from_str(pubkey) {
                    let mut peer = Peer::new(key);
                    peer.endpoint = Some(endpoint.parse()?);
                    peer.allowed_ips = vec![IpAddrMask::from_str("0.0.0.0/0")?];
                    host.peers.push(peer);
                }
            }
        }

        let ifcfg = InterfaceConfiguration {
            name: config.wireguard_interface.clone(),
            address: "10.42.0.2".parse()?, // placeholder — real IP comes from control plane
            port: config.wireguard_listen_port,
            peers: host.peers.clone(),
        };

        api.create_interface(&ifcfg)?;

        if let Some(first_peer) = host.peers.first() {
            api.configure_peer(first_peer)?;
        }

        info!("WireGuard interface {} created successfully", config.wireguard_interface);
    }

    #[cfg(not(all(feature = "wireguard", target_os = "linux")))]
    {
        warn!(
            "WireGuard requested but not available on this platform / without the `wireguard` feature — skipping interface creation"
        );
    }

    Ok(())
}
