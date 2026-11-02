// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Optional real-NIC TCP comparison. Kernel helpers own a leased, temporary interface.
use crate::{
    Endpoint,
    packets::{ALICE_TUN, BOB_TUN},
    worker,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use benchy_runner::{
    MachineLock, checked_output,
    cpu::ProcessCpu,
    parse_iperf_output,
    process::{Process, remote_command, shell_quote, stop_all, with_cleanup},
};
use clap::{Args, ValueEnum};
use gotatun::x25519::{PublicKey, StaticSecret};
use serde::Serialize;
use serde_json::Value;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    signal::unix::{SignalKind, signal},
    time::{sleep, timeout},
};

const WG_PORT: u16 = 51831;
const IPERF_PORT: u16 = 19432;
const MTU: u16 = 1440;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Traffic {
    Download,
    Upload,
}

impl Traffic {
    fn name(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    KernelKernel,
    GotatunKernel,
    GotatunGotatun,
}

impl Case {
    fn kernel(self, bob: bool) -> bool {
        self == Self::KernelKernel || (bob && self == Self::GotatunKernel)
    }
}

#[derive(Args, Serialize)]
pub struct Settings {
    #[arg(long, default_value = "download")]
    direction: Traffic,
    #[arg(long, default_value = "mole@10.0.0.2")]
    peer: String,
    #[arg(long, default_value = "10.0.0.1")]
    alice: Ipv4Addr,
    #[arg(long, default_value = "10.0.0.2")]
    bob: Ipv4Addr,
    #[arg(long, default_value = "eno2")]
    nic: String,
    #[arg(long, default_value = "bgio0")]
    interface: String,
    #[arg(long, default_value_t=30, value_parser=clap::value_parser!(u16).range(2..=60))]
    duration: u16,
    #[arg(long, default_value_t=3, value_parser=clap::value_parser!(u16).range(0..=10))]
    warmup: u16,
    #[arg(long, default_value_t=5, value_parser=clap::value_parser!(u16).range(1..=10))]
    repetitions: u16,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "kernel-kernel,gotatun-kernel,gotatun-gotatun"
    )]
    cases: Vec<Case>,
    #[arg(long, default_value = "kernel-tcp.json")]
    output: PathBuf,
}

#[derive(Serialize)]
struct Study {
    schema_version: u32,
    status: &'static str,
    source_sha: String,
    direction: &'static str,
    measured_host: &'static str,
    mtu: u16,
    aead_backend: &'static str,
    cpu_scope: &'static str,
    settings: Settings,
    trials: Vec<Trial>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Trial {
    case: Case,
    repetition: u16,
    alice_payload_gbps: f64,
    alice_gotatun_cpu_percent: Option<f64>,
    alice_iperf_cpu_percent: f64,
    cpu_window_seconds: f64,
    sender_retransmits: Option<u64>,
    iperf: Value,
}

fn validate_interface(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 15
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid interface name"
    );
    Ok(())
}

/// Register shutdown before creating the persistent kernel interface. No key file is written.
pub async fn endpoint(args: Endpoint) -> Result<()> {
    validate_interface(&args.interface)?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    ensure!(
        checked_output("ip", ["link", "show", &args.interface])
            .await
            .is_err(),
        "refusing an existing interface"
    );
    let private = STANDARD.encode(worker::key(&args.private_key)?);
    let public = STANDARD.encode(worker::key(&args.peer_public_key)?);
    let (local_tun, peer_tun) = if args.bob {
        (BOB_TUN, ALICE_TUN)
    } else {
        (ALICE_TUN, BOB_TUN)
    };
    checked_output("ip", ["link", "add", &args.interface, "type", "wireguard"]).await?;
    let work = async {
        checked_output("ip", ["link", "set", "dev", &args.interface, "alias", &owner(std::process::id())]).await?;
        let config = format!("[Interface]\nPrivateKey = {private}\nListenPort = {}\n[Peer]\nPublicKey = {public}\nAllowedIPs = {peer_tun}/32\nEndpoint = {}\n", args.bind.port(), args.peer);
        let mut child = Command::new("wg").args(["setconf", &args.interface, "/dev/stdin"])
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn()?;
        let mut stdin = child.stdin.take().context("wg stdin missing")?;
        stdin.write_all(config.as_bytes()).await?;
        drop(stdin);
        let status = timeout(Duration::from_secs(5), child.wait()).await.context("wg setconf timed out")??;
        // Suppress configuration diagnostics: some wg errors can echo key material.
        ensure!(status.success(), "wg setconf failed ({status})");
        checked_output("ip", ["address", "add", &format!("{local_tun}/24"), "dev", &args.interface]).await?;
        checked_output("ip", ["link", "set", "dev", &args.interface, "mtu", &MTU.to_string(), "up"]).await?;
        println!("ENDPOINT_READY");
        tokio::select! {
            _=interrupt.recv()=>{},
            _=terminate.recv()=>{},
            _=sleep(Duration::from_secs(120))=>{},
        }
        Ok(())
    }.await;
    with_cleanup(
        work,
        checked_output("ip", ["link", "del", "dev", &args.interface])
            .await
            .map(|_| ()),
    )
}

fn owner(pid: u32) -> String {
    format!("benchy-kernel-peer-{pid}")
}

pub async fn run(settings: Settings) -> Result<()> {
    validate_interface(&settings.interface)?;
    ensure!(
        !settings.cases.is_empty() && settings.cases.len() <= 3,
        "select 1–3 cases"
    );
    for (i, case) in settings.cases.iter().enumerate() {
        ensure!(!settings.cases[..i].contains(case), "duplicate case");
    }
    let _lock = MachineLock::acquire("/tmp/benchy.lock")?;
    crate::run::verify_underlay(
        &settings.peer,
        settings.alice,
        settings.bob,
        &settings.nic,
        u64::from(MTU) + 60,
    )
    .await?;
    let source_sha = String::from_utf8(checked_output("git", ["rev-parse", "HEAD"]).await?.stdout)?
        .trim()
        .to_owned();
    let mut study = Study {
        schema_version: 2,
        status: "running",
        source_sha,
        direction: settings.direction.name(),
        measured_host: "alice",
        mtu: MTU,
        aead_backend: "aws-lc-rs for GotaTun; Linux WireGuard for kernel endpoints",
        cpu_scope: "Alice GotaTun process only, whole iperf invocation including connection setup and omitted warmup; kernel endpoint helper CPU is not a datapath metric",
        settings,
        trials: Vec::new(),
        error: None,
    };
    let binary = std::env::current_exe()?;
    let remote_dir = format!(
        "/tmp/benchy-kernel-tcp-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let remote_binary = format!("{remote_dir}/experiment");
    save(&study).await?;
    let result = async {
        checked_output("ssh", [&study.settings.peer, &format!("umask 077; mkdir {}", shell_quote(&remote_dir))]).await?;
        checked_output("scp", [binary.to_string_lossy().as_ref(), &format!("{}:{remote_binary}", study.settings.peer)]).await?;
        for repetition in 1..=study.settings.repetitions {
            // Rotate the order so a configuration is not always first/last.
            for index in 0..study.settings.cases.len() {
                let case = study.settings.cases[(index + usize::from(repetition-1)) % study.settings.cases.len()];
                let trial = trial(&study.settings, &binary, &remote_binary, case, repetition).await?;
                eprintln!("{case:?} {} repetition={repetition} Alice={:.3} Gb/s GotaTun CPU={:?} iperf CPU={:.1}% sender retransmits={:?}",
                    study.direction, trial.alice_payload_gbps, trial.alice_gotatun_cpu_percent, trial.alice_iperf_cpu_percent, trial.sender_retransmits);
                study.trials.push(trial);
                save(&study).await?;
                tokio::select! {_=sleep(Duration::from_secs(2))=>{}, _=tokio::signal::ctrl_c()=>bail!("experiment interrupted")}
            }
        }
        Ok(())
    }.await;
    let cleanup = checked_output(
        "ssh",
        [
            &study.settings.peer,
            &format!("rm -rf -- {}", shell_quote(&remote_dir)),
        ],
    )
    .await
    .map(|_| ());
    let result = with_cleanup(result, cleanup);
    study.status = if result.is_ok() { "success" } else { "failed" };
    if let Err(error) = &result {
        study.error = Some(format!("{error:#}"));
    }
    save(&study).await?;
    result
}

async fn trial(
    settings: &Settings,
    binary: &Path,
    remote_binary: &str,
    case: Case,
    repetition: u16,
) -> Result<Trial> {
    let alice_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let bob_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let mut processes = Vec::new();
    let mut owners = Vec::new();
    let work = async {
        let mut alice_pid = None;
        for bob in [false, true] {
            let kernel = case.kernel(bob);
            let (private, public, bind, peer) = if bob {
                (
                    &bob_private,
                    PublicKey::from(&alice_private),
                    settings.bob,
                    settings.alice,
                )
            } else {
                (
                    &alice_private,
                    PublicKey::from(&bob_private),
                    settings.alice,
                    settings.bob,
                )
            };
            let mut values = vec![
                if kernel {
                    "kernel-endpoint"
                } else {
                    "endpoint"
                }
                .into(),
                "--interface".into(),
                settings.interface.clone(),
                "--private-key".into(),
                hex::encode(private.to_bytes()),
                "--peer-public-key".into(),
                hex::encode(public.as_bytes()),
                "--bind".into(),
                SocketAddrV4::new(bind, WG_PORT).to_string(),
                "--peer".into(),
                SocketAddrV4::new(peer, WG_PORT).to_string(),
            ];
            if bob {
                values.push("--bob".into());
            }
            let builder = if bob {
                Process::command(remote_binary).on_peer(&settings.peer)
            } else {
                Process::command(binary)
            };
            processes.push(
                builder
                    .args(values)
                    .sudo()
                    .ready_when("ENDPOINT_READY")
                    .spawn()
                    .await?,
            );
            let pid = processes.last().unwrap().pid();
            if kernel {
                owners.push((bob, pid));
            } else if !bob {
                alice_pid = Some(pid);
            }
        }
        let mut ready = false;
        for _ in 0..10 {
            if checked_output(
                "ping",
                [
                    "-I",
                    &settings.interface,
                    "-c",
                    "1",
                    "-W",
                    "1",
                    &BOB_TUN.to_string(),
                ],
            )
            .await
            .is_ok()
            {
                ready = true;
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }
        ensure!(ready, "tunnel failed its ping probe");
        for bob in [false, true] {
            let dest = if bob { ALICE_TUN } else { BOB_TUN };
            let output = host(
                settings,
                bob,
                false,
                "ip",
                &["-j".into(), "route".into(), "get".into(), dest.to_string()],
            )
            .await?;
            let routes: Vec<Value> = serde_json::from_slice(&output.stdout)?;
            ensure!(
                routes.first().and_then(|r| r["dev"].as_str()) == Some(settings.interface.as_str()),
                "unexpected tunnel route"
            );
        }
        processes.push(
            Process::command("iperf3")
                .args([
                    "--server".into(),
                    "--bind".into(),
                    BOB_TUN.to_string(),
                    "--port".into(),
                    IPERF_PORT.to_string(),
                ])
                .on_peer(&settings.peer)
                .capture_stdout()
                .spawn()
                .await?,
        );
        processes
            .last_mut()
            .unwrap()
            .wait_tcp(SocketAddrV4::new(BOB_TUN, IPERF_PORT).into())
            .await?;
        let cpu_start = Instant::now();
        let cpu = if let Some(pid) = alice_pid {
            Some(ProcessCpu::start(pid).await?)
        } else {
            None
        };
        let mut client = Command::new("iperf3");
        client.args([
            "--client".into(),
            BOB_TUN.to_string(),
            "--bind".into(),
            ALICE_TUN.to_string(),
            "--port".into(),
            IPERF_PORT.to_string(),
            "--time".into(),
            settings.duration.to_string(),
            "--omit".into(),
            settings.warmup.to_string(),
            "--json".into(),
            "--interval".into(),
            "1".into(),
        ]);
        if settings.direction == Traffic::Download {
            client.arg("--reverse");
        }
        let output = timeout(
            Duration::from_secs(u64::from(settings.duration + settings.warmup) + 20),
            client.kill_on_drop(true).output(),
        )
        .await
        .context("iperf timed out")??;
        let cpu_percent = if let Some(cpu) = cpu {
            Some(cpu.finish().await?)
        } else {
            None
        };
        let cpu_window_seconds = cpu_start.elapsed().as_secs_f64();
        let raw: Value = serde_json::from_slice(&output.stdout).context("iperf JSON")?;
        ensure!(
            raw.get("error").is_none(),
            "iperf reported an error: {}",
            raw["error"]
        );
        let parsed = parse_iperf_output(output).await?;
        let alice_payload_gbps = match settings.direction {
            Traffic::Download => parsed.end.sum_received.bits_per_second,
            Traffic::Upload => parsed.end.sum_sent.bits_per_second,
        } / 1e9;
        ensure!(
            alice_payload_gbps.is_finite() && alice_payload_gbps > 0.0,
            "no TCP payload measured on Alice"
        );
        Ok(Trial {
            case,
            repetition,
            alice_payload_gbps,
            alice_gotatun_cpu_percent: cpu_percent,
            alice_iperf_cpu_percent: parsed.end.cpu_utilization_percent.host_total,
            cpu_window_seconds,
            sender_retransmits: raw["end"]["sum_sent"]["retransmits"].as_u64(),
            iperf: raw,
        })
    };
    let result = tokio::select! {result=work=>result,_=tokio::signal::ctrl_c()=>Err(anyhow::anyhow!("experiment interrupted"))};
    let mut result = with_cleanup(result, stop_all(&mut processes).await);
    for (bob, pid) in owners {
        result = with_cleanup(result, cleanup_kernel(settings, bob, pid).await);
    }
    result
}

async fn host(
    settings: &Settings,
    bob: bool,
    sudo: bool,
    program: &str,
    args: &[String],
) -> Result<std::process::Output> {
    let (program, args) = if sudo {
        (
            "sudo",
            [vec!["-n".into(), program.into()], args.to_vec()].concat(),
        )
    } else {
        (program, args.to_vec())
    };
    if bob {
        checked_output("ssh", [&settings.peer, &remote_command(program, &args)]).await
    } else {
        checked_output(program, args).await
    }
}

async fn cleanup_kernel(settings: &Settings, bob: bool, pid: u32) -> Result<()> {
    let output = host(
        settings,
        bob,
        false,
        "ip",
        &["-j".into(), "link".into(), "show".into()],
    )
    .await?;
    let links: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    if let Some(link) = links
        .iter()
        .find(|link| link["ifname"].as_str() == Some(&settings.interface))
    {
        ensure!(
            link["ifalias"].as_str() == Some(owner(pid).as_str()),
            "refusing to remove an unowned interface"
        );
        host(
            settings,
            bob,
            true,
            "ip",
            &[
                "link".into(),
                "del".into(),
                "dev".into(),
                settings.interface.clone(),
            ],
        )
        .await?;
    }
    Ok(())
}

async fn save(study: &Study) -> Result<()> {
    if let Some(parent) = study
        .settings
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temporary = study.settings.output.with_extension("json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(study)?).await?;
    tokio::fs::rename(temporary, &study.settings.output).await?;
    Ok(())
}
