// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use benchy_lib::Unit;
use benchy_runner::{
    BenchmarkDefinition, IPERF_CPU, MachineLock, MeasurementDefinition, Recorder, THROUGHPUT,
    checked_output,
    cpu::ProcessCpu,
    default_output_path, parse_iperf_output,
    process::{Process, remote_command, shell_quote},
};
use clap::{Args, Parser, Subcommand};
use gotatun::{
    device::{DeviceBuilder, Peer},
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

pub use benchy_runner::Direction;

fn benchmark_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Upload => "gotatun-upload",
        Direction::Download => "gotatun-download",
    }
}
const GOTATUN_CPU: MeasurementDefinition = MeasurementDefinition {
    id: "cpu.gotatun",
    label: "GotaTun CPU",
    unit: Unit::Percent,
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

struct BenchmarkOutput {
    iperf: benchy_lib::iperf::Output,
    gotatun_cpu_percent: f64,
}

#[tokio::main]
pub async fn run(direction: Direction) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    if let Some(Commands::Endpoint(args)) = cli.command {
        return run_endpoint(args).await;
    }

    let definition = BenchmarkDefinition {
        repository: "gotatun",
        name: benchmark_name(direction),
        description: "TCP throughput and CPU usage measured on Alice",
    };
    let output = cli
        .output
        .unwrap_or_else(|| default_output_path(definition.name));
    let mut recorder = Recorder::new(definition, output).await;
    let result = async {
        let config = controller_config()?;
        anyhow::ensure!(
            (1..=120).contains(&config.duration),
            "BENCHY_DURATION must be 1–120 seconds"
        );
        recorder.parameter("duration_seconds", config.duration);
        recorder.parameter("mtu", config.mtu);
        recorder.parameter("listen_port", config.listen_port);
        recorder.parameter("direction", direction.name());
        recorder.parameter("measured_host", "alice");
        recorder.parameter("aead_backend", "aws-lc-rs");
        let output = run_controller(&config, direction).await?;
        let throughput = if direction.sender() {
            output.iperf.end.sum_sent.bits_per_second
        } else {
            output.iperf.end.sum_received.bits_per_second
        };
        recorder.iperf_throughput(
            THROUGHPUT,
            throughput,
            &output.iperf.interval_output,
            direction.sender(),
        )?;
        recorder.measurement(
            IPERF_CPU,
            output.iperf.end.cpu_utilization_percent.host_total,
        )?;
        recorder.measurement(GOTATUN_CPU, output.gotatun_cpu_percent)?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => recorder.success().await,
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

async fn run_controller(
    config: &ControllerConfig,
    direction: Direction,
) -> Result<BenchmarkOutput> {
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
    let mut processes: Vec<Process> = Vec::new();
    let result = async {
        deploy(&config.peer, &executable, &remote_dir, &remote_executable).await?;
        processes.push(
            Process::command(&executable)
                .args(endpoint_args(&local_args))
                .sudo()
                .ready_when(READY_MARKER)
                .spawn()
                .await?,
        );
        let local_pid = processes.last().unwrap().pid();
        processes.push(
            Process::command(&remote_executable)
                .args(endpoint_args(&remote_args))
                .on_peer(&config.peer)
                .sudo()
                .ready_when(READY_MARKER)
                .spawn()
                .await?,
        );
        wait_for_tunnel(&config.peer, local_args.tunnel_address).await?;
        processes.push(
            Process::command("iperf3")
                .args([
                    "--server".to_owned(),
                    "--bind".into(),
                    remote_args.tunnel_address.to_string(),
                    "--port".into(),
                    config.iperf_port.to_string(),
                ])
                .on_peer(&config.peer)
                .spawn()
                .await?,
        );
        processes
            .last_mut()
            .unwrap()
            .wait_tcp(SocketAddr::new(
                remote_args.tunnel_address.into(),
                config.iperf_port,
            ))
            .await?;
        let cpu = ProcessCpu::start(local_pid).await?;
        let mut client = Command::new("iperf3");
        client.args([
            "--client",
            &remote_args.tunnel_address.to_string(),
            "--port",
            &config.iperf_port.to_string(),
            "--time",
            &config.duration.to_string(),
            "--json",
            "--interval",
            "1",
        ]);
        if !direction.sender() {
            client.arg("--reverse");
        }
        let output = timeout(
            Duration::from_secs(config.duration + 30),
            client.kill_on_drop(true).output(),
        )
        .await
        .context("iperf client timed out")??;
        if !output.status.success() {
            bail!(
                "iperf client failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let gotatun_cpu_percent = cpu.finish().await?;
        let iperf = parse_iperf_output(output).await?;
        Ok(BenchmarkOutput {
            iperf,
            gotatun_cpu_percent,
        })
    };
    let result = tokio::select! {
        result = result => result,
        _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("benchmark interrupted")),
    };
    let cleanup = benchy_runner::process::stop_all(&mut processes).await;
    let result = benchy_runner::process::with_cleanup(result, cleanup);
    let cleanup = checked_output(
        "ssh",
        [
            &config.peer,
            &format!("rm -rf -- {}", shell_quote(&remote_dir)),
        ],
    )
    .await
    .map(|_| ());
    benchy_runner::process::with_cleanup(result, cleanup)
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

fn endpoint_args(args: &EndpointArgs) -> Vec<String> {
    let mut values = vec!["endpoint".to_owned()];
    append_endpoint_values(&mut values, args);
    values
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
    #[test]
    fn keys_must_be_exactly_32_bytes() {
        assert!(super::decode_key(&"00".repeat(32)).is_ok());
        assert!(super::decode_key("00").is_err());
    }
}
