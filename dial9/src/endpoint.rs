// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The plain far-side tunnel endpoint, spawned on the peer machine by `gotatun-dial9 run`
//! over ssh, under the peer's sudo. It only creates a TUN device, answers the tunnel, and
//! exits when interrupted or when its lease expires; nothing here is profiled.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use clap::Args as ClapArgs;
use gotatun::{
    device::{DeviceBuilder, Peer},
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use tokio::{process::Command, time::sleep};

use crate::util::decode_key;

#[derive(Debug, ClapArgs)]
pub struct EndpointArgs {
    #[arg(long, default_value = "d9gotatun0", value_parser = crate::util::validate_interface_name)]
    interface: String,
    #[arg(long)]
    private_key: String,
    #[arg(long)]
    peer_public_key: String,
    #[arg(long)]
    preshared_key: String,
    #[arg(long)]
    peer_endpoint: SocketAddr,
    #[arg(long, default_value = "10.0.1.2")]
    tunnel_address: Ipv4Addr,
    #[arg(long, default_value = "10.0.1.1")]
    peer_tunnel_address: Ipv4Addr,
    #[arg(long, default_value_t = 51821)]
    listen_port: u16,
    #[arg(long, default_value_t = 1420)]
    mtu: u16,
    #[arg(long, default_value_t = 600)]
    lease_seconds: u64,
}

pub async fn run_endpoint(args: EndpointArgs) -> Result<()> {
    let private_key = StaticSecret::from(decode_key(&args.private_key)?);
    let peer_public_key = PublicKey::from(decode_key(&args.peer_public_key)?);
    let preshared_key = decode_key(&args.preshared_key)?;
    let allowed_ip: IpNetwork = format!("{}/32", args.peer_tunnel_address).parse()?;
    let peer = Peer::new(peer_public_key)
        .with_endpoint(args.peer_endpoint)
        .with_allowed_ip(allowed_ip)
        .with_preshared_key(preshared_key);

    let mut device = DeviceBuilder::new()
        .with_private_key(private_key)
        .with_peer(peer)
        .with_default_udp()
        .with_listen_port(args.listen_port)
        .udp_recv_buffer_size(7 * 1024 * 1024)
        .udp_send_buffer_size(7 * 1024 * 1024)
        .create_tun(&args.interface)
        .context("failed to create TUN device")?
        .build()
        .await
        .context("failed to build gotatun device")?;

    run_ip(&[
        "address",
        "replace",
        &format!("{}/32", args.tunnel_address),
        "dev",
        &args.interface,
    ])
    .await?;
    run_ip(&[
        "link",
        "set",
        "dev",
        &args.interface,
        "mtu",
        &args.mtu.to_string(),
        "up",
    ])
    .await?;
    run_ip(&[
        "route",
        "replace",
        &format!("{}/32", args.peer_tunnel_address),
        "dev",
        &args.interface,
    ])
    .await?;

    // The controller waits for this line before starting the profiled tunnel.
    println!("DIAL9_ENDPOINT_READY {}", std::process::id());

    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("failed to wait for shutdown signal")?;
        }
        // A lease so an abandoned endpoint eventually removes its interface.
        _ = sleep(Duration::from_secs(args.lease_seconds)) => {}
        _ = device.wait() => bail!("gotatun device stopped unexpectedly"),
    }
    device.stop().await;
    Ok(())
}

#[tokio::main]
pub async fn run(args: EndpointArgs) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    run_endpoint(args).await
}

async fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .context("failed to execute ip")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "ip {} failed with {}: {}",
        args.join(" "),
        output.status,
        stderr.trim()
    );
}
