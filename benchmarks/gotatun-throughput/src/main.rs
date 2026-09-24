// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    env,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use benchy_runner::{
    BenchmarkDefinition, MachineLock, Recorder, checked_output, default_output_path,
    parse_iperf_output,
};
use clap::{Args, Parser, Subcommand};
use gotatun::{
    device::{DeviceBuilder, Peer},
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::{sleep, timeout},
};

const DEFINITION: BenchmarkDefinition = BenchmarkDefinition {
    repository: "gotatun",
    name: "gotatun-throughput",
    description: "GotaTun tunnel throughput measured with iperf3",
};
const READY_MARKER: &str = "BENCHY_READY";

#[derive(Parser)]
#[command(version, about = "Two-host GotaTun throughput benchmark")]
struct Cli {
    #[arg(long)]
    output: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Endpoint(EndpointArgs),
}

#[derive(Args, Clone)]
struct EndpointArgs {
    #[arg(long)]
    interface: String,
    #[arg(long)]
    private_key: String,
    #[arg(long)]
    peer_public_key: String,
    #[arg(long)]
    preshared_key: String,
    #[arg(long)]
    peer_endpoint: SocketAddr,
    #[arg(long)]
    tunnel_address: Ipv4Addr,
    #[arg(long)]
    peer_tunnel_address: Ipv4Addr,
    #[arg(long)]
    listen_port: u16,
    #[arg(long, default_value_t = 1440)]
    mtu: u16,
    #[arg(long, default_value_t = 300)]
    lease_seconds: u64,
}

#[derive(Clone)]
struct ControllerConfig {
    peer: String,
    alice_address: IpAddr,
    bob_address: IpAddr,
    interface: String,
    listen_port: u16,
    iperf_port: u16,
    duration: u64,
    mtu: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    if let Some(Commands::Endpoint(args)) = cli.command {
        return run_endpoint(args).await;
    }

    let output = cli
        .output
        .unwrap_or_else(|| default_output_path(DEFINITION.name));
    let mut recorder = Recorder::new(DEFINITION, output).await;
    let config = controller_config()?;
    recorder.parameter("duration_seconds", config.duration);
    recorder.parameter("mtu", config.mtu);
    recorder.parameter("listen_port", config.listen_port);

    match run_controller(&config).await {
        Ok(iperf) => {
            recorder.record_iperf(&iperf);
            recorder.success().await
        }
        Err(error) => {
            recorder.failure(&error).await?;
            Err(error)
        }
    }
}

fn controller_config() -> Result<ControllerConfig> {
    Ok(ControllerConfig {
        peer: env_value("BENCHY_PEER", "mole@10.0.0.2"),
        alice_address: env_value("BENCHY_ALICE_ADDRESS", "10.0.0.1").parse()?,
        bob_address: env_value("BENCHY_BOB_ADDRESS", "10.0.0.2").parse()?,
        interface: env_value("BENCHY_INTERFACE", "bench0"),
        listen_port: env_value("BENCHY_WIREGUARD_PORT", "51821").parse()?,
        iperf_port: env_value("BENCHY_IPERF_PORT", "5201").parse()?,
        duration: env_value("BENCHY_DURATION", "30").parse()?,
        mtu: env_value("BENCHY_MTU", "1440").parse()?,
    })
}

async fn run_controller(config: &ControllerConfig) -> Result<benchy_lib::iperf::Output> {
    let _machine_lock = MachineLock::acquire("/tmp/benchy.lock")?;
    let alice_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let bob_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let alice_public = PublicKey::from(&alice_private);
    let bob_public = PublicKey::from(&bob_private);
    let preshared_key = rand::random::<[u8; 32]>();

    let local_args = EndpointArgs {
        interface: config.interface.clone(),
        private_key: hex::encode(alice_private.to_bytes()),
        peer_public_key: hex::encode(bob_public.as_bytes()),
        preshared_key: hex::encode(preshared_key),
        peer_endpoint: SocketAddr::new(config.bob_address, config.listen_port),
        tunnel_address: Ipv4Addr::new(10, 0, 1, 1),
        peer_tunnel_address: Ipv4Addr::new(10, 0, 1, 2),
        listen_port: config.listen_port,
        mtu: config.mtu,
        lease_seconds: config.duration + 120,
    };
    let remote_args = EndpointArgs {
        private_key: hex::encode(bob_private.to_bytes()),
        peer_public_key: hex::encode(alice_public.as_bytes()),
        peer_endpoint: SocketAddr::new(config.alice_address, config.listen_port),
        tunnel_address: local_args.peer_tunnel_address,
        peer_tunnel_address: local_args.tunnel_address,
        ..local_args.clone()
    };

    let executable = env::current_exe().context("failed to locate benchmark executable")?;
    let run_id = env::var("GITHUB_RUN_ID").unwrap_or_else(|_| std::process::id().to_string());
    let remote_dir = format!("/tmp/benchy-{run_id}");
    let remote_executable = format!("{remote_dir}/gotatun-throughput");
    deploy(&config.peer, &executable, &remote_dir, &remote_executable).await?;

    let mut local = spawn_local_endpoint(&executable, &local_args)?;
    let local_pid = wait_ready(&mut local)
        .await
        .context("local endpoint failed to start")?;

    let mut remote = spawn_remote_endpoint(&config.peer, &remote_executable, &remote_args)?;
    let remote_pid = wait_ready(&mut remote)
        .await
        .context("remote endpoint failed to start")?;

    wait_for_tunnel(&config.peer, local_args.tunnel_address).await?;

    let mut iperf_server = Command::new("iperf3")
        .args([
            "--server",
            "--bind",
            &local_args.tunnel_address.to_string(),
            "--port",
            &config.iperf_port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("failed to start local iperf3 server")?;

    sleep(Duration::from_millis(250)).await;
    let iperf_command = remote_command(
        "iperf3",
        &[
            "--client".to_owned(),
            local_args.tunnel_address.to_string(),
            "--port".to_owned(),
            config.iperf_port.to_string(),
            "--time".to_owned(),
            config.duration.to_string(),
            "--json".to_owned(),
        ],
    );
    let output = checked_output("ssh", [&config.peer, &iperf_command]).await;

    stop_endpoint(None, local_pid).await;
    stop_endpoint(Some(&config.peer), remote_pid).await;
    let _ = local.wait().await;
    let _ = remote.wait().await;
    let _ = iperf_server.kill().await;

    parse_iperf_output(output?).await
}

async fn run_endpoint(args: EndpointArgs) -> Result<()> {
    let private_key = StaticSecret::from(decode_key(&args.private_key)?);
    let public_key = PublicKey::from(decode_key(&args.peer_public_key)?);
    let preshared_key = decode_key(&args.preshared_key)?;
    let allowed_ip: IpNetwork = format!("{}/32", args.peer_tunnel_address).parse()?;
    let peer = Peer::new(public_key)
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
        .context("failed to build GotaTun device")?;

    checked_output(
        "ip",
        [
            "address".to_owned(),
            "replace".to_owned(),
            format!("{}/24", args.tunnel_address),
            "dev".to_owned(),
            args.interface.clone(),
        ],
    )
    .await?;
    checked_output(
        "ip",
        [
            "link".to_owned(),
            "set".to_owned(),
            "dev".to_owned(),
            args.interface.clone(),
            "mtu".to_owned(),
            args.mtu.to_string(),
            "up".to_owned(),
        ],
    )
    .await?;

    println!("{READY_MARKER} {}", std::process::id());
    std::io::stdout().flush()?;

    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("failed to wait for shutdown signal")?,
        _ = sleep(Duration::from_secs(args.lease_seconds)) => {}
        _ = device.wait() => bail!("GotaTun device stopped unexpectedly"),
    }
    device.stop().await;
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
        [peer, &format!("mkdir -p {}", shell_quote(remote_dir))],
    )
    .await?;
    checked_output(
        "scp",
        [
            executable.as_os_str(),
            std::ffi::OsStr::new(&format!("{peer}:{remote_executable}")),
        ],
    )
    .await?;
    checked_output(
        "ssh",
        [
            peer,
            &format!("chmod 755 {}", shell_quote(remote_executable)),
        ],
    )
    .await?;
    Ok(())
}

fn spawn_local_endpoint(executable: &Path, args: &EndpointArgs) -> Result<Child> {
    let mut command = Command::new("sudo");
    command.arg("-n").arg(executable).arg("endpoint");
    append_endpoint_args(&mut command, args);
    spawn_endpoint(command, "local")
}

fn spawn_remote_endpoint(peer: &str, executable: &str, args: &EndpointArgs) -> Result<Child> {
    let mut endpoint_args = vec!["endpoint".to_owned()];
    append_endpoint_values(&mut endpoint_args, args);
    let remote = format!("sudo -n {}", remote_command(executable, &endpoint_args));
    let mut command = Command::new("ssh");
    command.arg(peer).arg(remote);
    spawn_endpoint(command, "remote")
}

fn spawn_endpoint(mut command: Command, host: &str) -> Result<Child> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start {host} endpoint"))
}

async fn wait_ready(child: &mut Child) -> Result<u32> {
    let stdout = child
        .stdout
        .take()
        .context("endpoint stdout was not captured")?;
    let mut lines = BufReader::new(stdout).lines();
    timeout(Duration::from_secs(20), async {
        while let Some(line) = lines.next_line().await? {
            if let Some(pid) = line.strip_prefix(&format!("{READY_MARKER} ")) {
                return pid.parse().context("endpoint returned an invalid PID");
            }
        }
        bail!("endpoint exited before becoming ready")
    })
    .await
    .context("timed out waiting for endpoint readiness")?
}

async fn wait_for_tunnel(peer: &str, destination: Ipv4Addr) -> Result<()> {
    let command = remote_command(
        "ping",
        &[
            "-c".to_owned(),
            "1".to_owned(),
            "-W".to_owned(),
            "1".to_owned(),
            destination.to_string(),
        ],
    );
    for _ in 0..10 {
        if checked_output("ssh", [peer, &command]).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(500)).await;
    }
    bail!("tunnel did not become ready")
}

async fn stop_endpoint(peer: Option<&str>, pid: u32) {
    let pid = pid.to_string();
    match peer {
        Some(peer) => {
            let command = remote_command(
                "sudo",
                &["-n".to_owned(), "kill".to_owned(), "-INT".to_owned(), pid],
            );
            let _ = checked_output("ssh", [peer, &command]).await;
        }
        None => {
            let _ = checked_output("sudo", ["-n", "kill", "-INT", &pid]).await;
        }
    }
}

fn append_endpoint_args(command: &mut Command, args: &EndpointArgs) {
    let mut values = Vec::new();
    append_endpoint_values(&mut values, args);
    command.args(values);
}

fn append_endpoint_values(values: &mut Vec<String>, args: &EndpointArgs) {
    values.extend([
        "--interface".to_owned(),
        args.interface.clone(),
        "--private-key".to_owned(),
        args.private_key.clone(),
        "--peer-public-key".to_owned(),
        args.peer_public_key.clone(),
        "--preshared-key".to_owned(),
        args.preshared_key.clone(),
        "--peer-endpoint".to_owned(),
        args.peer_endpoint.to_string(),
        "--tunnel-address".to_owned(),
        args.tunnel_address.to_string(),
        "--peer-tunnel-address".to_owned(),
        args.peer_tunnel_address.to_string(),
        "--listen-port".to_owned(),
        args.listen_port.to_string(),
        "--mtu".to_owned(),
        args.mtu.to_string(),
        "--lease-seconds".to_owned(),
        args.lease_seconds.to_string(),
    ]);
}

fn remote_command(program: &str, args: &[String]) -> String {
    std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("invalid hexadecimal key")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))
}

fn env_value(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{decode_key, remote_command, shell_quote};

    #[test]
    fn shell_arguments_are_single_quoted() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(
            remote_command("some command", &["an argument".to_owned()]),
            "'some command' 'an argument'"
        );
    }

    #[test]
    fn keys_must_be_exactly_32_bytes() {
        assert!(decode_key(&"01".repeat(32)).is_ok());
        assert!(decode_key(&"01".repeat(31)).is_err());
    }
}
