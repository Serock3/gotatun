// This Source Code Form is subject to the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Leased kernel WireGuard peer. Only the controller's owned interface is removed.
use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use benchy_runner::{
    checked_output,
    process::{remote_command, with_cleanup},
};
use serde_json::Value;
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    signal::unix::{SignalKind, signal},
    time::{sleep, timeout},
};

use super::{EndpointArgs, READY_MARKER, append_endpoint_values, decode_key};

#[derive(clap::Args)]
pub(super) struct Args {
    #[command(flatten)]
    endpoint: EndpointArgs,
    #[arg(long)]
    owner: String,
}

pub(super) fn command_args(endpoint: &EndpointArgs, owner: &str) -> Vec<String> {
    let mut values = vec!["kernel-peer".into(), "--owner".into(), owner.into()];
    append_endpoint_values(&mut values, endpoint);
    values
}

pub(super) fn validate_interface(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 15
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid benchmark interface name"
    );
    Ok(())
}

pub(super) async fn ensure_absent(interface: &str) -> Result<()> {
    validate_interface(interface)?;
    let output = checked_output("ip", ["-j", "link", "show"]).await?;
    let links: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    ensure!(
        !links
            .iter()
            .any(|link| link["ifname"].as_str() == Some(interface)),
        "refusing to attach an existing interface"
    );
    Ok(())
}

pub(super) async fn run(args: Args) -> Result<()> {
    let Args { endpoint, owner } = args;
    ensure!(
        owner.starts_with("benchy-kernel-")
            && owner.len() <= 64
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid kernel peer ownership label"
    );
    ensure!(
        (1..=600).contains(&endpoint.lease_seconds),
        "kernel peer lease must be 1–600 seconds"
    );
    // Install handlers before creating a persistent kernel interface.
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    ensure_absent(&endpoint.interface).await?;
    let private_key = STANDARD.encode(decode_key(&endpoint.private_key)?);
    let public_key = STANDARD.encode(decode_key(&endpoint.peer_public_key)?);
    let preshared_key = STANDARD.encode(decode_key(&endpoint.preshared_key)?);
    checked_output(
        "ip",
        ["link", "add", &endpoint.interface, "type", "wireguard"],
    )
    .await?;
    let setup_and_wait = async {
        checked_output(
            "ip",
            ["link", "set", "dev", &endpoint.interface, "alias", &owner],
        )
        .await?;
        let config = format!(
            "[Interface]\nPrivateKey = {private_key}\nListenPort = {}\n[Peer]\nPublicKey = {public_key}\nPresharedKey = {preshared_key}\nAllowedIPs = {}/32\nEndpoint = {}\n",
            endpoint.listen_port, endpoint.peer_tunnel_address, endpoint.peer_endpoint,
        );
        let mut command = Command::new("wg")
            .args(["setconf", &endpoint.interface, "/dev/stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            // wg errors can echo configuration lines containing key material.
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start wg setconf")?;
        let mut input = command.stdin.take().context("missing wg stdin")?;
        input.write_all(config.as_bytes()).await?;
        drop(input);
        let status = timeout(Duration::from_secs(5), command.wait())
            .await
            .context("wg setconf timed out")??;
        ensure!(status.success(), "wg setconf failed ({status})");
        checked_output(
            "ip",
            [
                "address",
                "add",
                &format!("{}/24", endpoint.tunnel_address),
                "dev",
                &endpoint.interface,
            ],
        )
        .await?;
        checked_output(
            "ip",
            [
                "link",
                "set",
                "dev",
                &endpoint.interface,
                "mtu",
                &endpoint.mtu.to_string(),
                "up",
            ],
        )
        .await?;
        println!("{READY_MARKER}");
        sleep(Duration::from_secs(endpoint.lease_seconds)).await;
        Ok(())
    };
    let result = tokio::select! {
        result = setup_and_wait => result,
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
    };
    let cleanup = checked_output("ip", ["link", "del", "dev", &endpoint.interface])
        .await
        .map(|_| ());
    with_cleanup(result, cleanup)
}

/// Also covers interrupted startup or a helper that needed forced shutdown.
/// Reading the full link list distinguishes an absent interface from an SSH error.
pub(super) async fn cleanup(peer: &str, interface: &str, owner: &str) -> Result<()> {
    let output = checked_output(
        "ssh",
        [
            peer,
            &remote_command("ip", &["-j".into(), "link".into(), "show".into()]),
        ],
    )
    .await?;
    let links: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    if let Some(link) = links
        .iter()
        .find(|link| link["ifname"].as_str() == Some(interface))
    {
        ensure!(
            link["ifalias"].as_str() == Some(owner),
            "refusing to remove an unowned peer interface"
        );
        checked_output(
            "ssh",
            [
                peer,
                &remote_command(
                    "sudo",
                    &[
                        "-n".into(),
                        "ip".into(),
                        "link".into(),
                        "del".into(),
                        "dev".into(),
                        interface.into(),
                    ],
                ),
            ],
        )
        .await?;
    }
    Ok(())
}
