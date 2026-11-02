// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Upload: normal Alice device, locally counted transport output, raw peer drain.
use crate::{
    Mode, Run,
    batch::{self, SendReport},
    outgoing,
    packets::{self, ALICE_TUN, BOB_TUN, MAGIC, Pool},
    worker,
};
use anyhow::{Context, Result, ensure};
use benchy_runner::{
    MachineLock, checked_output,
    cpu::ProcessCpu,
    process::{Process, shell_quote, stop_all, with_cleanup},
};
use clap::Args;
use gotatun::{
    noise::TunnResult,
    packet::{Decoder, Ipv4, Ipv4Decoder, Ipv4PayloadDecoder, Packet, Udp, UdpDecoder},
    x25519::{PublicKey, StaticSecret},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{SocketAddrV4, TcpListener, UdpSocket},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

const PORT: u16 = 51831;
const PROBE: &[u8; 8] = b"UPPROBE1";

#[derive(Args)]
pub struct DrainArgs {
    #[arg(long)]
    kernel_drop: bool,
    #[arg(long)]
    mode: Mode,
    #[arg(long)]
    bind: SocketAddrV4,
    #[arg(long)]
    target: SocketAddrV4,
    #[arg(long)]
    control: SocketAddrV4,
    #[arg(long)]
    private_key: String,
    #[arg(long)]
    peer_public_key: String,
    #[arg(long)]
    packets: u32,
    #[arg(long)]
    payload: u16,
}

#[derive(Default, Serialize, Deserialize)]
pub struct DrainReport {
    kernel_drop: bool,
    received_datagrams: u64,
    packets: u64,
    duplicates: u64,
    invalid: u64,
    socket_drops: u64,
    receive_buffer_bytes: usize,
    probe_authenticated: bool,
}

pub fn drain(args: DrainArgs) -> Result<()> {
    ensure!(
        (1_000..=40_000_000).contains(&args.packets) && (64..=1400).contains(&args.payload),
        "invalid drain geometry"
    );
    let socket = UdpSocket::bind(args.bind)?;
    socket.connect(args.target)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let receive_buffer_bytes = batch::receive_buffer(&socket)?;
    let mut tunnel = if args.mode == Mode::Gotatun {
        Some(worker::handshake(
            &socket,
            &args.private_key,
            &args.peer_public_key,
        )?)
    } else {
        None
    };
    println!("DRAIN_HANDSHAKE_READY");
    if let Some(tunnel) = &mut tunnel {
        let start = Instant::now();
        let mut raw = [0u8; 2048];
        loop {
            ensure!(
                start.elapsed() < Duration::from_secs(5),
                "authenticated upload probe timed out"
            );
            let n = match socket.recv(&mut raw) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let packet = Packet::copy_from(&raw[..n])
                .try_into_wg()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if let TunnResult::WriteToTunnel(plain) = tunnel.handle_incoming_packet(packet) {
                let ip: Packet<Ipv4> = Ipv4Decoder::CHECK_ALL
                    .decode_owned(plain)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let packet: Packet<Ipv4<Udp>> = Ipv4PayloadDecoder::<UdpDecoder>::CHECK_ALL
                    .decode_owned(ip)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                ensure!(
                    packet.payload.payload.len() == 32 && &packet.payload.payload[..8] == PROBE,
                    "unexpected authenticated probe"
                );
                break;
            }
        }
    }
    // Drop the tunnel before the measured phase. Data is never decrypted below.
    let authenticated = tunnel.is_some();
    drop(tunnel);
    let done = Arc::new(AtomicBool::new(false));
    let stop = done.clone();
    let (thread, bind) = (
        std::thread::spawn(move || -> Result<DrainReport> {
            let mut report = DrainReport {
                kernel_drop: args.kernel_drop,
                receive_buffer_bytes,
                probe_authenticated: authenticated,
                ..Default::default()
            };
            let mut batch = batch::ReceiveBatch::new(64, 2048);
            let mut seen = vec![false; args.packets as usize + 4096];
            let until = Instant::now() + Duration::from_secs(90);
            while !stop.load(Relaxed) {
                ensure!(Instant::now() < until, "peer drain lease expired");
                if args.kernel_drop {
                    // Keep the UDP port open to avoid ICMP errors. Once its queue
                    // fills Linux drops data; there is no userspace receive/decrypt workload.
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                batch.receive(&socket, |data| {
                    if args.mode == Mode::Gotatun
                        && data.first() == Some(&4)
                        && data.len() != packets::wire_len(args.payload as usize)
                    {
                        return;
                    }
                    let valid = data.len() == packets::wire_len(args.payload as usize)
                        && if args.mode == Mode::Direct {
                            &data[..8] == MAGIC
                        } else {
                            data[..4] == [4, 0, 0, 0]
                        };
                    if !valid {
                        report.invalid += 1;
                        return;
                    }
                    report.received_datagrams += 1;
                    let seq = u64::from_le_bytes(data[8..16].try_into().unwrap());
                    let Some(seen) = usize::try_from(seq).ok().and_then(|i| seen.get_mut(i)) else {
                        report.invalid += 1;
                        return;
                    };
                    if *seen {
                        report.duplicates += 1;
                    } else {
                        *seen = true;
                        report.packets += 1;
                    }
                })?;
            }
            report.socket_drops = crate::sink::socket_drops(args.bind)?;
            Ok(report)
        }),
        args.control,
    );
    let mut thread = Some(thread);
    // Guard the receiver even if the control channel fails.
    let control_result = (|| -> Result<()> {
        let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut client = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            ensure!(
                Instant::now() < deadline,
                "controller did not connect to peer drain"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        client.set_read_timeout(Some(Duration::from_secs(70)))?;
        client.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut command = [0u8; 8];
        client.read_exact(&mut command)?;
        ensure!(&command == b"STOPv1\n\n", "unexpected drain command");
        done.store(true, Relaxed);
        let report = thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("drain panicked"))??;
        serde_json::to_writer(&mut client, &report)?;
        client.write_all(b"\n")?;
        client.flush()?;
        let mut end = [0u8; 1];
        ensure!(
            client.read(&mut end)? == 0,
            "unexpected trailing drain command"
        );
        Ok(())
    })();
    done.store(true, Relaxed);
    let cleanup = if let Some(thread) = thread.take() {
        thread
            .join()
            .map_err(|_| anyhow::anyhow!("drain panicked"))
            .and_then(|r| r.map(|_| ()))
    } else {
        Ok(())
    };
    with_cleanup(control_result, cleanup)
}

struct Generator {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<SendReport>>>,
}
impl Generator {
    fn start(
        socket: UdpSocket,
        pool: Pool,
        payload: usize,
        batch: usize,
        rate: f64,
        loops: u16,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || -> Result<SendReport> {
            let start = Instant::now();
            let mut total = SendReport {
                packets: 0,
                datagram_bytes: pool.stride,
                prepare_seconds: pool.prepare_seconds,
                send_seconds: 0.0,
                offered_payload_gbps: 0.0,
                syscalls: 0,
                partial_sends: 0,
            };
            for _ in 0..loops {
                let report =
                    batch::send_cancellable(&socket, &pool, payload, batch, rate, Some(&flag))?;
                total.packets += report.packets;
                total.syscalls += report.syscalls;
                total.partial_sends += report.partial_sends;
            }
            total.send_seconds = start.elapsed().as_secs_f64();
            total.offered_payload_gbps =
                total.packets as f64 * payload as f64 * 8.0 / total.send_seconds / 1e9;
            Ok(total)
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
    async fn finish(mut self) -> Result<SendReport> {
        while !self.thread.as_ref().unwrap().is_finished() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("generator panicked"))?
    }
}
impl Drop for Generator {
    fn drop(&mut self) {
        self.stop.store(true, Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "benchy-upload-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Serialize)]
struct Study {
    schema_version: u32,
    direction: &'static str,
    status: String,
    source_sha: String,
    settings: Run,
    trials: Vec<Trial>,
    error: Option<String>,
}
#[derive(Serialize)]
struct Trial {
    mode: Mode,
    requested_payload_gbps: f64,
    repetition: u16,
    offered: SendReport,
    local_output: Option<outgoing::Report>,
    local_output_payload_gbps: f64,
    cpu_percent: Option<f64>,
    cpu_window_seconds: Option<f64>,
    cpu_seconds_per_output_gigabit: Option<f64>,
    peer_drain: DrainReport,
    nic_delta: Nic,
}
#[derive(Serialize)]
struct Nic {
    tx_packets: u64,
    tx_bytes: u64,
    tx_dropped: u64,
    tx_errors: u64,
}
impl Nic {
    fn read(nic: &str) -> Result<Self> {
        let p = PathBuf::from("/sys/class/net").join(nic).join("statistics");
        let read = |name: &str| -> Result<u64> {
            Ok(std::fs::read_to_string(p.join(name))?.trim().parse()?)
        };
        Ok(Self {
            tx_packets: read("tx_packets")?,
            tx_bytes: read("tx_bytes")?,
            tx_dropped: read("tx_dropped")?,
            tx_errors: read("tx_errors")?,
        })
    }
    fn delta(self, before: Self) -> Result<Self> {
        Ok(Self {
            tx_packets: self
                .tx_packets
                .checked_sub(before.tx_packets)
                .context("NIC counter reset")?,
            tx_bytes: self
                .tx_bytes
                .checked_sub(before.tx_bytes)
                .context("NIC counter reset")?,
            tx_dropped: self
                .tx_dropped
                .checked_sub(before.tx_dropped)
                .context("NIC counter reset")?,
            tx_errors: self
                .tx_errors
                .checked_sub(before.tx_errors)
                .context("NIC counter reset")?,
        })
    }
}

pub async fn run(args: Run) -> Result<()> {
    crate::run::validate(&args)?;
    ensure!(
        args.payload_receive_buffer_mib == 0,
        "payload-receive-buffer-mib applies only to download"
    );
    for rate in &args.rates {
        ensure!(
            *rate == 0.0
                || args.packets as f64 * args.payload as f64 * 8.0 * args.input_loops as f64
                    / (*rate * 1e9)
                    <= 55.0,
            "paced upload train would exceed 55 seconds"
        );
    }
    let _lock = MachineLock::acquire("/tmp/benchy.lock")?;
    crate::run::verify_physical_route(&args).await?;
    let source_sha = String::from_utf8(checked_output("git", ["rev-parse", "HEAD"]).await?.stdout)?
        .trim()
        .to_owned();
    let mut study = Study {
        schema_version: 1,
        direction: "upload",
        status: "running".into(),
        source_sha,
        settings: args,
        trials: Vec::new(),
        error: None,
    };
    let remote_dir = format!(
        "/tmp/benchy-upload-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let remote_binary = format!("{remote_dir}/buffered-io");
    let binary = std::env::current_exe()?;
    save(&study).await?;
    let result=async {
        checked_output("ssh",[&study.settings.peer,&format!("umask 077; mkdir {}",shell_quote(&remote_dir))]).await?;
        checked_output("scp",[binary.to_string_lossy().as_ref(),&format!("{}:{remote_binary}",study.settings.peer)]).await?;
        let mut id=0;
        for repetition in 1..=study.settings.repetitions {for &rate in &study.settings.rates {for &mode in &study.settings.modes {
            let t=trial(&study.settings,&binary,&remote_binary,mode,rate,repetition,20440+id).await?;id+=1;
            eprintln!("Upload {mode:?} requested={rate:.2} offered={:.3} output={:.3} Gb/s peer_received={} nic_packets={} cpu={:?}",t.offered.offered_payload_gbps,t.local_output_payload_gbps,t.peer_drain.received_datagrams,t.nic_delta.tx_packets,t.cpu_percent);
            study.trials.push(t);save(&study).await?;
        }}}
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

async fn trial(
    args: &Run,
    binary: &Path,
    remote_binary: &str,
    mode: Mode,
    rate: f64,
    repetition: u16,
    port: u16,
) -> Result<Trial> {
    let private = StaticSecret::from(rand::random::<[u8; 32]>());
    let peer_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let public = PublicKey::from(&private);
    let peer_public = PublicKey::from(&peer_private);
    let scratch = Scratch::new()?;
    let report_path = scratch.0.join("sent.json");
    let mut processes = Vec::new();
    let work = async {
        let pid = if mode == Mode::Gotatun {
            let mut values = vec![
                "endpoint".into(),
                "--receive-buffer-mib".into(),
                args.receive_buffer_mib.to_string(),
                "--private-key".into(),
                hex::encode(private.to_bytes()),
                "--peer-public-key".into(),
                hex::encode(peer_public.as_bytes()),
                "--bind".into(),
                SocketAddrV4::new(args.alice, PORT).to_string(),
                "--peer".into(),
                SocketAddrV4::new(args.bob, PORT).to_string(),
                "--interface".into(),
                args.interface.clone(),
                "--send-report".into(),
                report_path.to_string_lossy().into_owned(),
                "--data-wire-len".into(),
                packets::wire_len(args.payload as usize).to_string(),
            ];
            let builder = if let Some(cpus) = &args.endpoint_cpus {
                let mut v = vec![
                    "-c".to_owned(),
                    cpus.clone(),
                    binary.to_string_lossy().into_owned(),
                ];
                v.append(&mut values);
                Process::command("taskset").args(v)
            } else {
                Process::command(binary).args(values)
            };
            processes.push(builder.sudo().ready_when("ENDPOINT_READY").spawn().await?);
            Some(processes[0].pid())
        } else {
            None
        };
        let mut values = vec![
            "drain".into(),
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
            SocketAddrV4::new(args.bob, PORT).to_string(),
            "--target".into(),
            SocketAddrV4::new(args.alice, PORT).to_string(),
            "--control".into(),
            SocketAddrV4::new(args.bob, port).to_string(),
            "--packets".into(),
            (args.packets * args.input_loops as u32).to_string(),
            "--payload".into(),
            args.payload.to_string(),
        ];
        if args.peer_kernel_drop {
            values.push("--kernel-drop".into());
        }
        processes.push(
            Process::command(remote_binary)
                .args(values)
                .on_peer(&args.peer)
                .ready_when("DRAIN_HANDSHAKE_READY")
                .spawn()
                .await?,
        );
        if mode == Mode::Gotatun {
            let probe = UdpSocket::bind(SocketAddrV4::new(ALICE_TUN, 0))?;
            probe.connect(SocketAddrV4::new(BOB_TUN, worker::run_sink_port()))?;
            let mut data = [0u8; 32];
            data[..8].copy_from_slice(PROBE);
            for _ in 0..3 {
                probe.send(&data)?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        processes
            .last_mut()
            .unwrap()
            .wait_tcp(SocketAddrV4::new(args.bob, port).into())
            .await?;
        let mut control = TcpStream::connect(SocketAddrV4::new(args.bob, port)).await?;
        control.set_nodelay(true)?;
        let pool = if mode == Mode::Gotatun {
            packets::payload_pool(args.packets as usize, args.payload as usize)?
        } else {
            packets::prepare(
                None,
                args.packets as usize,
                args.payload as usize,
                worker::run_sink_port(),
            )?
        };
        let socket = UdpSocket::bind(SocketAddrV4::new(
            if mode == Mode::Gotatun {
                ALICE_TUN
            } else {
                args.alice
            },
            if mode == Mode::Direct { PORT } else { 0 },
        ))?;
        socket.connect(SocketAddrV4::new(
            if mode == Mode::Gotatun {
                BOB_TUN
            } else {
                args.bob
            },
            if mode == Mode::Gotatun {
                worker::run_sink_port()
            } else {
                PORT
            },
        ))?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        let nic_before = Nic::read(&args.nic)?;
        let cpu_start = Instant::now();
        let cpu = if let Some(pid) = pid {
            Some(ProcessCpu::start(pid).await?)
        } else {
            None
        };
        let offered = tokio::time::timeout(
            Duration::from_secs(60),
            Generator::start(
                socket,
                pool,
                args.payload as usize,
                args.batch as usize,
                rate,
                args.input_loops,
            )
            .finish(),
        )
        .await
        .context("upload generator exceeded 60 seconds")??;
        let mut last = Nic::read(&args.nic)?.tx_packets;
        let mut quiet = 0;
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let now = Nic::read(&args.nic)?.tx_packets;
            if now == last {
                quiet += 1;
            } else {
                quiet = 0;
            }
            last = now;
            if quiet >= 2 {
                break;
            }
        }
        ensure!(quiet >= 2, "local transmission did not drain");
        let nic_delta = Nic::read(&args.nic)?.delta(nic_before)?;
        let cpu_percent = if let Some(cpu) = cpu {
            Some(cpu.finish().await?)
        } else {
            None
        };
        let cpu_window = cpu_percent.map(|_| cpu_start.elapsed().as_secs_f64());
        control.write_all(b"STOPv1\n\n").await?;
        let mut reader = BufReader::new(control);
        let mut data = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut data)).await??;
        let mut control = reader.into_inner();
        control.shutdown().await?;
        drop(control);
        let peer_drain: DrainReport = serde_json::from_str(&data)?;
        ensure!(
            peer_drain.invalid == 0 && (mode == Mode::Direct || peer_drain.probe_authenticated),
            "peer diagnostics invalid"
        );
        if mode == Mode::Gotatun {
            processes[0].stop().await?;
        }
        let local_output: Option<outgoing::Report> = if mode == Mode::Gotatun {
            Some(serde_json::from_slice(&std::fs::read(&report_path)?)?)
        } else {
            None
        };
        if let Some(report) = &local_output {
            ensure!(
                !report.transport_error
                    && report.packets > 0
                    && report.packets <= offered.packets as u64,
                "invalid local transport report"
            );
        }
        let output_packets = local_output
            .as_ref()
            .map_or(offered.packets as u64, |r| r.packets);
        let span = offered
            .send_seconds
            .max(local_output.as_ref().map_or(0.0, |r| r.send_span_seconds));
        let gigabits = output_packets as f64 * args.payload as f64 * 8.0 / 1e9;
        Ok(Trial {
            mode,
            requested_payload_gbps: rate,
            repetition,
            local_output_payload_gbps: gigabits / span,
            cpu_seconds_per_output_gigabit: cpu_percent
                .zip(cpu_window)
                .map(|(p, s)| p / 100.0 * s / gigabits),
            cpu_percent,
            cpu_window_seconds: cpu_window,
            offered,
            local_output,
            peer_drain,
            nic_delta,
        })
    };
    let result = tokio::select! {r=work=>r,_=tokio::signal::ctrl_c()=>Err(anyhow::anyhow!("upload experiment interrupted"))};
    with_cleanup(result, stop_all(&mut processes).await)
}

async fn save(study: &Study) -> Result<()> {
    if let Some(p) = study
        .settings
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(p).await?;
    }
    let temporary = study.settings.output.with_extension("json.tmp");
    tokio::fs::write(&temporary, serde_json::to_vec_pretty(study)?).await?;
    tokio::fs::rename(temporary, &study.settings.output).await?;
    Ok(())
}
