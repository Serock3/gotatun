// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    Endpoint, Mode, Sender, batch,
    packets::{self, ALICE_TUN, BOB_TUN},
};
use anyhow::{Context, Result, bail, ensure};
use benchy_runner::checked_output;
use gotatun::{
    device::{DeviceBuilder, Peer},
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::{Packet, WgKind},
    udp::{
        UdpTransportFactory, UdpTransportFactoryParams,
        socket::{UdpSocket as GotatunSocket, UdpSocketFactory},
    },
    x25519::{PublicKey, StaticSecret},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    os::fd::AsRawFd,
    sync::Arc,
    time::{Duration, Instant},
};

/// Bind-time configuration only; packet I/O still uses the production socket.
struct Factory {
    force_bytes: u32,
    sent: Option<Arc<crate::outgoing::Counters>>,
}
impl UdpTransportFactory for Factory {
    type Send = crate::outgoing::CountedSend<GotatunSocket>;
    type Recv = GotatunSocket;
    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> std::io::Result<(Self::Send, Self::Recv)> {
        let (send, recv) = UdpSocketFactory {
            recv_buffer_size: Some(7 * 1024 * 1024),
            send_buffer_size: Some(7 * 1024 * 1024),
        }
        .bind(params)
        .await?;
        if self.force_bytes > 0 {
            let bytes = self.force_bytes as libc::c_int;
            // SAFETY: the live socket and initialized option value are borrowed
            // for this synchronous syscall. Only this owned socket is changed.
            let result = unsafe {
                libc::setsockopt(
                    recv.socket().as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUFFORCE,
                    (&bytes as *const libc::c_int).cast(),
                    size_of_val(&bytes) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok((
            crate::outgoing::CountedSend {
                inner: send,
                counters: self.sent.clone(),
            },
            recv,
        ))
    }
}

pub fn key(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected a 32-byte key"))
}

pub async fn endpoint(args: Endpoint) -> Result<()> {
    let (local_tun, peer_tun) = if args.bob {
        (BOB_TUN, ALICE_TUN)
    } else {
        (ALICE_TUN, BOB_TUN)
    };
    let counters = Arc::new(crate::outgoing::Counters::new(args.data_wire_len));
    ensure!(
        args.receive_buffer_mib <= 64,
        "receive buffer exceeds experiment limit"
    );
    ensure!(
        checked_output("ip", ["link", "show", &args.interface])
            .await
            .is_err(),
        "refusing to attach an existing interface"
    );
    let peer = Peer::new(PublicKey::from(key(&args.peer_public_key)?))
        .with_endpoint(args.peer.into())
        .with_allowed_ip(format!("{peer_tun}/32").parse::<ipnetwork::IpNetwork>()?);
    let mut device = DeviceBuilder::new()
        .with_private_key(StaticSecret::from(key(&args.private_key)?))
        .with_peer(peer)
        .with_udp(Factory {
            force_bytes: args.receive_buffer_mib * 1024 * 1024,
            sent: args.send_report.as_ref().map(|_| counters.clone()),
        })
        .with_listen_port(args.bind.port())
        .create_tun(&args.interface)
        .context("create experimental TUN")?
        .build()
        .await?;
    let result = async {
        checked_output(
            "ip",
            [
                "address",
                "add",
                &format!("{local_tun}/24"),
                "dev",
                &args.interface,
            ],
        )
        .await?;
        checked_output(
            "ip",
            ["link", "set", "dev", &args.interface, "mtu", "1440", "up"],
        )
        .await?;
        println!("ENDPOINT_READY");
        tokio::select! {
            result=tokio::signal::ctrl_c()=>result.context("endpoint signal"),
            _=tokio::time::sleep(Duration::from_secs(120))=>Ok(()),
            _=device.wait()=>Err(anyhow::anyhow!("endpoint stopped unexpectedly")),
        }
    }
    .await;
    device.stop().await;
    if let Some(path) = args.send_report {
        std::fs::write(path, serde_json::to_vec_pretty(&counters.snapshot())?)?;
    }
    result
}

pub fn sender(args: Sender) -> Result<()> {
    ensure!(
        (1..=256).contains(&args.batch) && args.payload >= 64 && args.payload <= 1400,
        "invalid sender geometry"
    );
    ensure!(
        args.rate.is_finite() && (args.rate == 0.0 || (0.5..=9.0).contains(&args.rate)),
        "invalid offered rate"
    );
    ensure!(
        args.bind.ip() != args.target.ip() && !args.target.ip().is_loopback(),
        "sender requires two real hosts"
    );
    let socket = UdpSocket::bind(args.bind)?;
    socket.connect(args.target)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut tunnel = if args.mode == Mode::Gotatun {
        Some(handshake(
            &socket,
            &args.private_key,
            &args.peer_public_key,
        )?)
    } else {
        None
    };
    let prepared_at = Instant::now();
    let pool = packets::prepare(
        tunnel.as_mut(),
        args.packets as usize,
        args.payload as usize,
        run_sink_port(),
    )?;
    ensure!(
        prepared_at.elapsed() < Duration::from_secs(45),
        "pool preparation took too long for a fresh session"
    );
    let control = TcpListener::bind(args.control)?;
    control.set_nonblocking(true)?;
    println!(
        "BUFFER_READY bytes={} prepare_seconds={:.3}",
        pool.bytes.len(),
        pool.prepare_seconds
    );
    let wait = Instant::now();
    let mut client = loop {
        match control.accept() {
            Ok((client, _)) => break client,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(
            wait.elapsed() < Duration::from_secs(30),
            "controller did not start the packet train"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_write_timeout(Some(Duration::from_secs(5)))?;
    client.set_nodelay(true)?;
    let mut start = [0u8; 8];
    client.read_exact(&mut start)?;
    ensure!(&start == b"STARTv1\n", "unexpected controller command");
    let send = if args.no_catch_up {
        batch::send_without_catch_up
    } else {
        batch::send
    };
    let report = send(
        &socket,
        &pool,
        args.payload as usize,
        args.batch as usize,
        args.rate,
    )?;
    serde_json::to_writer(&mut client, &report)?;
    client.write_all(b"\n")?;
    client.flush()?;
    // Let Alice actively close the control connection, so Bob's listening port
    // does not enter TIME_WAIT and block a subsequent experiment.
    let mut end = [0u8; 1];
    ensure!(
        client.read(&mut end)? == 0,
        "unexpected trailing controller command"
    );
    Ok(())
}

pub const fn run_sink_port() -> u16 {
    19432
}

pub(crate) fn handshake(
    socket: &UdpSocket,
    private_key: &str,
    peer_public_key: &str,
) -> Result<Tunn> {
    let private = StaticSecret::from(key(private_key)?);
    let public = PublicKey::from(&private);
    let mut tunnel = Tunn::new(
        private,
        PublicKey::from(key(peer_public_key)?),
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&public, 100)),
    );
    let init = tunnel
        .format_handshake_initiation(false)
        .context("create handshake")?;
    socket.send(&init.into_bytes())?;
    let mut buffer = [0u8; 2048];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        ensure!(Instant::now() < deadline, "WireGuard handshake timed out");
        let n = match socket.recv(&mut buffer) {
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
        let packet = Packet::copy_from(&buffer[..n])
            .try_into_wg()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if !matches!(packet, WgKind::HandshakeResp(_)) {
            continue;
        }
        match tunnel.handle_incoming_packet(packet) {
            TunnResult::WriteToNetwork(keepalive) => {
                let packet: Packet = keepalive.into();
                socket.send(&packet)?;
                return Ok(tunnel);
            }
            other => bail!("handshake failed: {other:?}"),
        }
    }
}
