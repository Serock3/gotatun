// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    Mode, Run,
    batch::SendReport,
    packets::{ALICE_TUN, wire_len},
    sink::{self, Sink, Stats},
    worker::run_sink_port,
};
use anyhow::{Context, Result, ensure};
use benchy_runner::{
    MachineLock, checked_output,
    cpu::ProcessCpu,
    process::{Process, remote_command, shell_quote, stop_all, with_cleanup},
};
use gotatun::x25519::{PublicKey, StaticSecret};
use serde::Serialize;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

const WG_PORT: u16 = 51831;

#[derive(Serialize)]
struct Study {
    schema_version: u32,
    status: String,
    source_sha: String,
    aead_backend: &'static str,
    cpu_scope: &'static str,
    settings: Run,
    trials: Vec<Trial>,
    error: Option<String>,
}

#[derive(Serialize)]
struct Trial {
    mode: Mode,
    requested_payload_gbps: f64,
    repetition: u16,
    sender: SendReport,
    receiver: Stats,
    delivered_payload_gbps: f64,
    delivery_window_seconds: f64,
    payload_per_send_window_gbps: f64,
    loss_percent: f64,
    gotatun_cpu_percent: Option<f64>,
    cpu_window_seconds: Option<f64>,
    gotatun_cpu_seconds_per_payload_gigabit: Option<f64>,
    gotatun_outer_socket_drops: Option<u64>,
    gotatun_receive_buffer_bytes: Option<u64>,
}

pub async fn run(args: Run) -> Result<()> {
    ensure!(
        !args.peer_kernel_drop,
        "peer-kernel-drop applies only to upload"
    );
    ensure!(
        args.input_loops == 1,
        "input-loops applies only to upload, never to encrypted download pools"
    );
    validate(&args)?;
    let _lock = MachineLock::acquire("/tmp/benchy.lock")?;
    verify_physical_route(&args).await?;
    let source_sha = String::from_utf8(checked_output("git", ["rev-parse", "HEAD"]).await?.stdout)?
        .trim()
        .to_owned();
    let mut study = Study {
        schema_version: 1,
        status: "running".into(),
        source_sha,
        aead_backend: "aws-lc-rs",
        cpu_scope: "Alice GotaTun process only; START through receiver drain, including idle tail; CPU seconds/Gbit uses delivered payload",
        settings: args,
        trials: Vec::new(),
        error: None,
    };
    let remote_dir = format!(
        "/tmp/benchy-buffered-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let binary = std::env::current_exe()?;
    let remote_binary = format!("{remote_dir}/buffered-download");
    save(&study).await?;
    let result=async {
        checked_output("ssh",[&study.settings.peer,&format!("umask 077; mkdir {}",shell_quote(&remote_dir))]).await?;
        checked_output("scp",[binary.to_string_lossy().as_ref(),&format!("{}:{remote_binary}",study.settings.peer)]).await?;
        let mut trial_id=0;
        for repetition in 1..=study.settings.repetitions {
            for &rate in &study.settings.rates {
                for &mode in &study.settings.modes {
                    let trial=trial(&study.settings,&binary,&remote_binary,mode,rate,repetition,19440+trial_id).await?;
                    trial_id+=1;
                    eprintln!("{mode:?} requested={rate:.2} offered={:.3} delivered={:.3} Gb/s loss={:.2}% sink_drops={} outer_drops={:?} cpu={:?}",
                        trial.sender.offered_payload_gbps,trial.delivered_payload_gbps,trial.loss_percent,
                        trial.receiver.kernel_socket_drops,trial.gotatun_outer_socket_drops,trial.gotatun_cpu_percent);
                    study.trials.push(trial);
                    save(&study).await?;
                }
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
    study.status = if result.is_ok() { "success" } else { "failed" }.into();
    if let Err(error) = &result {
        study.error = Some(format!("{error:#}"));
    }
    save(&study).await?;
    result
}

pub(crate) fn validate(args: &Run) -> Result<()> {
    ensure!(
        args.alice != args.bob && !args.alice.is_loopback() && !args.bob.is_loopback(),
        "use two physical hosts"
    );
    ensure!(
        args.interface.len() <= 15
            && !args.interface.is_empty()
            && args
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid interface name"
    );
    ensure!(
        !args.rates.is_empty()
            && args.rates.len() <= 16
            && args
                .rates
                .iter()
                .all(|r| r.is_finite() && (*r == 0.0 || (0.5..=9.0).contains(r))),
        "rates must be 0 (unpaced) or 0.5–9 Gb/s"
    );
    ensure!(
        !args.modes.is_empty()
            && args.modes.len() <= 2
            && (args.modes.len() == 1 || args.modes[0] != args.modes[1]),
        "select one or both distinct modes"
    );
    ensure!(
        (args.packets as usize) * wire_len(args.payload as usize) <= 2 * 1024 * 1024 * 1024,
        "packet pool exceeds 2 GiB"
    );
    if let Some(cpus) = &args.endpoint_cpus {
        ensure!(
            !cpus.is_empty()
                && cpus
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b',' || b == b'-'),
            "invalid taskset CPU list"
        );
    }
    Ok(())
}

pub(crate) async fn verify_physical_route(args: &Run) -> Result<()> {
    let local = checked_output("ip", ["-j", "route", "get", &args.bob.to_string()]).await?;
    let remote = checked_output(
        "ssh",
        [
            &args.peer,
            &remote_command(
                "ip",
                &[
                    "-j".into(),
                    "route".into(),
                    "get".into(),
                    args.alice.to_string(),
                ],
            ),
        ],
    )
    .await?;
    for output in [local, remote] {
        let routes: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
        ensure!(
            routes.first().and_then(|r| r["dev"].as_str()) == Some(args.nic.as_str()),
            "both underlay routes must use {}",
            args.nic
        );
    }
    let device = PathBuf::from("/sys/class/net")
        .join(&args.nic)
        .join("device");
    ensure!(
        device.exists(),
        "controller's selected NIC has no physical device"
    );
    let mtu: u64 = std::fs::read_to_string(device.parent().unwrap().join("mtu"))?
        .trim()
        .parse()?;
    ensure!(
        mtu >= wire_len(args.payload as usize) as u64 + 28,
        "underlay MTU would fragment the test datagrams"
    );
    Ok(())
}

async fn trial(
    args: &Run,
    binary: &Path,
    remote_binary: &str,
    mode: Mode,
    rate: f64,
    repetition: u16,
    control_port: u16,
) -> Result<Trial> {
    let private = StaticSecret::from(rand::random::<[u8; 32]>());
    let peer_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let public = PublicKey::from(&private);
    let peer_public = PublicKey::from(&peer_private);
    let mut processes = Vec::new();
    let work = async {
        let endpoint_pid = if mode == Mode::Gotatun {
            let mut values = vec![
                "endpoint".into(),
                "--receive-buffer-mib".into(),
                args.receive_buffer_mib.to_string(),
                "--private-key".into(),
                hex::encode(private.to_bytes()),
                "--peer-public-key".into(),
                hex::encode(peer_public.as_bytes()),
                "--bind".into(),
                SocketAddrV4::new(args.alice, WG_PORT).to_string(),
                "--peer".into(),
                SocketAddrV4::new(args.bob, WG_PORT).to_string(),
                "--interface".into(),
                args.interface.clone(),
            ];
            let builder = if let Some(cpus) = &args.endpoint_cpus {
                let mut taskset = vec![
                    "-c".to_owned(),
                    cpus.clone(),
                    binary.to_string_lossy().into_owned(),
                ];
                taskset.append(&mut values);
                Process::command("taskset").args(taskset)
            } else {
                Process::command(binary).args(values)
            };
            processes.push(builder.sudo().ready_when("ENDPOINT_READY").spawn().await?);
            Some(processes.last().unwrap().pid())
        } else {
            None
        };
        let gotatun_receive_buffer_bytes = if mode == Mode::Gotatun {
            let output = checked_output(
                "ss",
                ["-u", "-a", "-n", "-m", &format!("sport = :{WG_PORT}")],
            )
            .await?;
            let text = String::from_utf8(output.stdout)?;
            let memory = text
                .split("skmem:(")
                .nth(1)
                .context("missing socket memory information")?;
            Some(
                memory
                    .split(',')
                    .find_map(|part| part.strip_prefix("rb"))
                    .context("missing actual receive buffer")?
                    .parse()?,
            )
        } else {
            None
        };
        let bind = SocketAddrV4::new(
            if mode == Mode::Direct {
                args.alice
            } else {
                ALICE_TUN
            },
            run_sink_port(),
        );
        let sink = Sink::start(
            bind,
            args.packets as usize,
            if mode == Mode::Direct {
                wire_len(args.payload as usize)
            } else {
                args.payload as usize
            },
        )?;
        let target = SocketAddrV4::new(
            args.alice,
            if mode == Mode::Direct {
                run_sink_port()
            } else {
                WG_PORT
            },
        );
        let values = vec![
            "sender".into(),
            "--mode".into(),
            if mode == Mode::Direct {
                "direct"
            } else {
                "gotatun"
            }
            .into(),
            "--private-key".into(),
            hex::encode(peer_private.to_bytes()),
            "--peer-public-key".into(),
            hex::encode(public.as_bytes()),
            "--bind".into(),
            SocketAddrV4::new(args.bob, WG_PORT).to_string(),
            "--target".into(),
            target.to_string(),
            "--control".into(),
            SocketAddrV4::new(args.bob, control_port).to_string(),
            "--packets".into(),
            args.packets.to_string(),
            "--payload".into(),
            args.payload.to_string(),
            "--batch".into(),
            args.batch.to_string(),
            "--rate".into(),
            rate.to_string(),
        ];
        processes.push(
            Process::command(remote_binary)
                .args(values)
                .on_peer(&args.peer)
                .ready_when("BUFFER_READY")
                .spawn()
                .await?,
        );
        processes
            .last_mut()
            .unwrap()
            .wait_tcp(SocketAddrV4::new(args.bob, control_port).into())
            .await?;
        let mut control = TcpStream::connect(SocketAddrV4::new(args.bob, control_port)).await?;
        control.set_nodelay(true)?;
        let cpu_start = Instant::now();
        let cpu = if let Some(pid) = endpoint_pid {
            Some(ProcessCpu::start(pid).await?)
        } else {
            None
        };
        control.write_all(b"STARTv1\n").await?;
        let mut report = String::new();
        let mut reader = BufReader::new(control);
        tokio::time::timeout(Duration::from_secs(65), reader.read_line(&mut report))
            .await
            .context("sender timed out")??;
        ensure!(report.len() < 64 * 1024, "sender report too large");
        let mut control = reader.into_inner();
        control.shutdown().await?;
        drop(control);
        let sender: SendReport = serde_json::from_str(&report).context("sender report")?;
        ensure!(
            sender.packets == args.packets as usize,
            "incomplete packet train"
        );
        let receiver = sink.finish()?;
        let cpu_percent = if let Some(cpu) = cpu {
            Some(cpu.finish().await?)
        } else {
            None
        };
        let cpu_window = cpu_percent.map(|_| cpu_start.elapsed().as_secs_f64());
        let delivered_gigabits = receiver.unique as f64 * f64::from(args.payload) * 8.0 / 1e9;
        ensure!(
            receiver.unique > 0 && receiver.invalid == 0,
            "no valid payload, or unexpected packets: received={} invalid={}",
            receiver.unique,
            receiver.invalid
        );
        let outer_drops = if mode == Mode::Gotatun {
            Some(sink::socket_drops(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                WG_PORT,
            ))?)
        } else {
            None
        };
        let cpu_cost = cpu_percent
            .zip(cpu_window)
            .map(|(pct, seconds)| pct / 100.0 * seconds / delivered_gigabits);
        // Count any post-send draining as processing time, rather than apparent capacity.
        let delivery_window_seconds = sender.send_seconds.max(receiver.arrival_span_seconds);
        Ok(Trial {
            mode,
            requested_payload_gbps: rate,
            repetition,
            delivered_payload_gbps: delivered_gigabits / delivery_window_seconds,
            delivery_window_seconds,
            payload_per_send_window_gbps: delivered_gigabits / sender.send_seconds,
            loss_percent: 100.0 * (1.0 - receiver.unique as f64 / args.packets as f64),
            sender,
            receiver,
            gotatun_cpu_percent: cpu_percent,
            cpu_window_seconds: cpu_window,
            gotatun_cpu_seconds_per_payload_gigabit: cpu_cost,
            gotatun_outer_socket_drops: outer_drops,
            gotatun_receive_buffer_bytes,
        })
    };
    let result = tokio::select! {result=work=>result,_=tokio::signal::ctrl_c()=>Err(anyhow::anyhow!("experiment interrupted"))};
    with_cleanup(result, stop_all(&mut processes).await)
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
