// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The controller that runs on the benchmark controller host (unprivileged): it claims the
//! machines, builds an ephemeral WireGuard pair, deploys the endpoint to the peer over ssh,
//! starts the profiled near-side tunnel through sudo, waits for it to finish, and tears
//! the peer side back down.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use anyhow::{Context as _, Result, bail};
use benchy_runner::{
    MachineLock, checked_output,
    process::{Process, shell_quote, stop_all, with_cleanup},
};
use clap::Args as ClapArgs;
use gotatun::x25519::{PublicKey, StaticSecret};

const REMOTE_DIR_PREFIX: &str = "benchy-dial9";

#[derive(Debug, ClapArgs)]
pub struct RunArgs {
    #[arg(long, default_value = "mole@10.0.0.2")]
    peer: String,
    #[arg(long, default_value = "10.0.0.1")]
    alice_address: IpAddr,
    #[arg(long, default_value = "10.0.0.2")]
    bob_address: IpAddr,
    #[arg(long, default_value_t = 51821)]
    listen_port: u16,
    /// The peer machine's listen port, when it differs from ours.
    #[arg(long)]
    peer_port: Option<u16>,
    #[arg(
        long,
        default_value = "d9gotatun0",
        value_parser = crate::util::validate_interface_name
    )]
    interface: String,
    #[arg(long, default_value = "10.0.1.1")]
    tunnel_address: Ipv4Addr,
    #[arg(long, default_value = "10.0.1.2")]
    peer_tunnel_address: Ipv4Addr,
    #[arg(long, default_value_t = 1420)]
    mtu: u16,
    /// Directory the profiled tunnel writes dial9 trace segments to.
    #[arg(long, default_value = "dial9-traces")]
    trace_dir: std::path::PathBuf,
    #[arg(long, default_value_t = 999, value_parser = clap::value_parser!(u64).range(1..=4000))]
    cpu_sample_hz: u64,
    /// Seconds per iperf3 direction (send and receive each).
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u16).range(1..=60))]
    iperf_seconds: u16,
    /// Port of the iperf3 server started on the peer.
    #[arg(long, default_value_t = 5209)]
    iperf_port: u16,
}

/// The ephemeral key material of one run; held in memory only.
struct KeyMaterial {
    alice_private_hex: String,
    bob_private_hex: String,
    alice_public: PublicKey,
    bob_public: PublicKey,
    preshared_key_hex: String,
}

#[tokio::main]
pub async fn run(mut args: RunArgs) -> Result<()> {
    // The workflow passes the BENCHY_* variables from GitHub vars, which arrive empty when
    // they are not visible to the repository. Empty must not beat the defaults - the
    // throughput benchmark's env_value filters them the same way.
    override_from_env(&mut args)?;
    // Benchmark and profiling runs share the controller host and the peer machine.
    let _machine_lock = MachineLock::acquire("/tmp/benchy.lock")?;

    let keys = generate_keys();
    let executable = std::env::current_exe().context("failed to locate the harness executable")?;
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| std::process::id().to_string());
    let remote_dir = format!("/tmp/{REMOTE_DIR_PREFIX}-{run_id}");
    let remote_executable = format!("{remote_dir}/gotatun-dial9");

    tokio::fs::create_dir_all(&args.trace_dir).await?;
    if tokio::fs::read_dir(&args.trace_dir)
        .await?
        .next_entry()
        .await?
        .is_some()
    {
        bail!(
            "trace directory must be empty: {}",
            args.trace_dir.display()
        );
    }
    let manifest_path = args.trace_dir.join("run.json");
    let sha = std::env::var("GITHUB_SHA").ok().or_else(|| {
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    });
    let mut manifest = serde_json::json!({
        "schema_version": 1, "source_sha": sha, "run_id": std::env::var("GITHUB_RUN_ID").ok(),
        "run_attempt": std::env::var("GITHUB_RUN_ATTEMPT").ok(), "status": "running",
        "profiled_host": "alice", "directions": ["send", "receive"],
        "seconds_per_direction": args.iperf_seconds, "cpu_sample_hz": args.cpu_sample_hz,
        "mtu": args.mtu, "aead_backend": "aws-lc-rs", "trace_limit_mib": 512
    });
    tokio::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?).await?;
    let outcome = async {
        deploy(&args.peer, &executable, &remote_dir, &remote_executable).await?;
        orchestrate(&args, &keys, &remote_executable).await?;
        verify_trace_files(&args.trace_dir).await
    }
    .await;
    let outcome = with_cleanup(outcome, cleanup(&args.peer, &remote_dir).await);
    manifest["status"] = serde_json::json!(if outcome.is_ok() { "success" } else { "failed" });
    tokio::fs::write(manifest_path, serde_json::to_vec_pretty(&manifest)?).await?;
    outcome
}

fn override_from_env(args: &mut RunArgs) -> Result<()> {
    let value = |key| std::env::var(key).ok().filter(|value| !value.is_empty());
    if let Some(peer) = value("BENCHY_PEER") {
        args.peer = peer;
    }
    for (key, destination) in [
        ("BENCHY_ALICE_ADDRESS", &mut args.alice_address),
        ("BENCHY_BOB_ADDRESS", &mut args.bob_address),
    ] {
        if let Some(address) = value(key) {
            let address: IpAddr = address.parse().with_context(|| format!("invalid {key}"))?;
            if address.is_unspecified() {
                bail!("{key} must be a concrete host address");
            }
            *destination = address;
        }
    }
    if let Some(port) = value("BENCHY_WIREGUARD_PORT") {
        args.listen_port = port.parse().context("invalid BENCHY_WIREGUARD_PORT")?;
        if args.listen_port == 0 {
            bail!("BENCHY_WIREGUARD_PORT must be nonzero");
        }
    }
    Ok(())
}

fn generate_keys() -> KeyMaterial {
    let alice_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let bob_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let alice_public = PublicKey::from(&alice_private);
    let bob_public = PublicKey::from(&bob_private);
    KeyMaterial {
        alice_private_hex: hex::encode(alice_private.to_bytes()),
        bob_private_hex: hex::encode(bob_private.to_bytes()),
        alice_public,
        bob_public,
        preshared_key_hex: hex::encode(rand::random::<[u8; 32]>()),
    }
}

async fn orchestrate(args: &RunArgs, keys: &KeyMaterial, remote_executable: &str) -> Result<()> {
    let peer_port = args.peer_port.unwrap_or(args.listen_port);
    let mut processes: Vec<Process> = Vec::new();
    let run = async {
        let mut values = vec!["endpoint".to_owned()];
        values.extend(endpoint_values(
            args,
            &keys.bob_private_hex,
            &keys.alice_public,
            &keys.preshared_key_hex,
            peer_port,
        ));
        processes.push(
            Process::command(remote_executable)
                .args(values)
                .on_peer(&args.peer)
                .sudo()
                .ready_when("DIAL9_ENDPOINT_READY")
                .spawn()
                .await?,
        );
        processes.push(
            Process::command("iperf3")
                .args([
                    "--server".to_owned(),
                    "--bind".into(),
                    args.peer_tunnel_address.to_string(),
                    "--port".into(),
                    args.iperf_port.to_string(),
                ])
                .on_peer(&args.peer)
                .spawn()
                .await?,
        );
        processes
            .last_mut()
            .unwrap()
            .wait_tcp(SocketAddr::new(
                args.peer_tunnel_address.into(),
                args.iperf_port,
            ))
            .await?;
        let mut values = vec!["tunnel".to_owned()];
        values.extend(tunnel_values(args, keys, peer_port));
        processes.push(
            Process::command(std::env::current_exe()?)
                .args(values)
                .sudo()
                .ready_when("DIAL9_TUNNEL_READY")
                .spawn()
                .await?,
        );
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(u64::from(args.iperf_seconds) * 2 + 60),
            processes.last_mut().unwrap().wait_output(),
        )
        .await
        .context("profiled workload timed out")??;
        anyhow::ensure!(
            output.status.success(),
            "profiled tunnel exited with {}",
            output.status
        );
        Ok(())
    };
    let outcome = tokio::select! {
        result = run => result,
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for Ctrl-C")
                .and_then(|()| Err(anyhow::anyhow!("profiling interrupted")))
        }
    };
    with_cleanup(outcome, stop_all(&mut processes).await)?;
    println!(
        "profiling run finished; traces in {}; owned processes stopped",
        args.trace_dir.display()
    );
    Ok(())
}

fn endpoint_values(
    args: &RunArgs,
    bob_private_hex: &str,
    alice_public: &PublicKey,
    preshared_key_hex: &str,
    peer_port: u16,
) -> Vec<String> {
    [
        "--interface".to_owned(),
        args.interface.clone(),
        "--private-key".to_owned(),
        bob_private_hex.to_owned(),
        "--peer-public-key".to_owned(),
        hex::encode(alice_public.as_bytes()),
        "--preshared-key".to_owned(),
        preshared_key_hex.to_owned(),
        "--peer-endpoint".to_owned(),
        format!("{}:{}", args.alice_address, args.listen_port),
        "--tunnel-address".to_owned(),
        args.peer_tunnel_address.to_string(),
        "--peer-tunnel-address".to_owned(),
        args.tunnel_address.to_string(),
        "--listen-port".to_owned(),
        peer_port.to_string(),
        "--mtu".to_owned(),
        args.mtu.to_string(),
        "--lease-seconds".to_owned(),
        (u64::from(args.iperf_seconds) * 2 + 90).to_string(),
    ]
    .to_vec()
}

fn tunnel_values(args: &RunArgs, keys: &KeyMaterial, peer_port: u16) -> Vec<String> {
    [
        "--interface".to_owned(),
        args.interface.clone(),
        "--private-key".to_owned(),
        keys.alice_private_hex.clone(),
        "--peer-public-key".to_owned(),
        hex::encode(keys.bob_public.as_bytes()),
        "--preshared-key".to_owned(),
        keys.preshared_key_hex.clone(),
        "--peer-endpoint".to_owned(),
        format!("{}:{}", args.bob_address, peer_port),
        "--tunnel-address".to_owned(),
        args.tunnel_address.to_string(),
        "--peer-tunnel-address".to_owned(),
        args.peer_tunnel_address.to_string(),
        "--listen-port".to_owned(),
        args.listen_port.to_string(),
        "--mtu".to_owned(),
        args.mtu.to_string(),
        "--trace-dir".to_owned(),
        args.trace_dir.to_string_lossy().into_owned(),
        "--cpu-sample-hz".to_owned(),
        args.cpu_sample_hz.to_string(),
        "--iperf-seconds".to_owned(),
        args.iperf_seconds.to_string(),
        "--iperf-port".to_owned(),
        args.iperf_port.to_string(),
    ]
    .to_vec()
}

async fn verify_trace_files(directory: &Path) -> Result<()> {
    let mut entries = tokio::fs::read_dir(directory).await?;
    let mut indices = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(index) = name
            .strip_prefix("trace.")
            .and_then(|s| s.strip_suffix(".bin.gz").or_else(|| s.strip_suffix(".bin")))
        {
            indices.push(
                index
                    .parse::<usize>()
                    .context("invalid trace segment name")?,
            );
        }
    }
    indices.sort_unstable();
    if indices.is_empty() || indices.iter().copied().ne(0..indices.len()) {
        bail!(
            "trace segments are missing or were rolled out of the buffer: {indices:?}; lower event volume or shorten the run"
        );
    }
    Ok(())
}

async fn deploy(
    peer: &str,
    executable: &Path,
    remote_dir: &str,
    remote_executable: &str,
) -> Result<()> {
    checked_output(
        "ssh",
        [
            peer.to_owned(),
            format!("mkdir -p {}", shell_quote(remote_dir)),
        ],
    )
    .await?;
    checked_output(
        "scp",
        [
            executable.as_os_str().to_string_lossy().into_owned(),
            format!("{peer}:{remote_executable}"),
        ],
    )
    .await?;
    checked_output(
        "ssh",
        [
            peer.to_owned(),
            format!("chmod 755 {}", shell_quote(remote_executable)),
        ],
    )
    .await?;
    Ok(())
}

async fn cleanup(peer: &str, remote_dir: &str) -> Result<()> {
    checked_output(
        "ssh",
        [peer, &format!("rm -rf -- {}", shell_quote(remote_dir))],
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::verify_trace_files;

    #[tokio::test]
    async fn rejects_traces_with_rolled_out_or_missing_segments() {
        let dir = std::env::temp_dir().join(format!("dial9-segments-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        assert!(verify_trace_files(&dir).await.is_err());
        tokio::fs::write(dir.join("trace.1.bin.gz"), b"test")
            .await
            .unwrap();
        assert!(verify_trace_files(&dir).await.is_err());
        tokio::fs::write(dir.join("trace.0.bin.gz"), b"test")
            .await
            .unwrap();
        assert!(verify_trace_files(&dir).await.is_ok());
        tokio::fs::write(dir.join("trace.3.bin.gz"), b"test")
            .await
            .unwrap();
        assert!(verify_trace_files(&dir).await.is_err());
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
