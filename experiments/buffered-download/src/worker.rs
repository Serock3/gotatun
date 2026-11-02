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
    x25519::{PublicKey, StaticSecret},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    sync::Arc,
    time::{Duration, Instant},
};

pub fn key(value: &str) -> Result<[u8; 32]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected a 32-byte key"))
}

pub async fn endpoint(args: Endpoint) -> Result<()> {
    ensure!(
        checked_output("ip", ["link", "show", &args.interface])
            .await
            .is_err(),
        "refusing to attach an existing interface"
    );
    let peer = Peer::new(PublicKey::from(key(&args.peer_public_key)?))
        .with_endpoint(args.peer.into())
        .with_allowed_ip(format!("{BOB_TUN}/32").parse::<ipnetwork::IpNetwork>()?);
    let mut device = DeviceBuilder::new()
        .with_private_key(StaticSecret::from(key(&args.private_key)?))
        .with_peer(peer)
        .with_default_udp()
        .with_listen_port(args.bind.port())
        .udp_recv_buffer_size(7 * 1024 * 1024)
        .udp_send_buffer_size(7 * 1024 * 1024)
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
                &format!("{ALICE_TUN}/24"),
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
    result
}

pub fn sender(args: Sender) -> Result<()> {
    ensure!(
        (1..=256).contains(&args.batch) && args.payload >= 64 && args.payload <= 1400,
        "invalid sender geometry"
    );
    ensure!(
        args.rate.is_finite() && (0.0..=9.0).contains(&args.rate),
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
        Some(handshake(&socket, &args)?)
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
    let report = batch::send(
        &socket,
        &pool,
        args.payload as usize,
        args.batch as usize,
        args.rate,
    )?;
    serde_json::to_writer(&mut client, &report)?;
    client.flush()?;
    Ok(())
}

pub const fn run_sink_port() -> u16 {
    19432
}

fn handshake(socket: &UdpSocket, args: &Sender) -> Result<Tunn> {
    let private = StaticSecret::from(key(&args.private_key)?);
    let public = PublicKey::from(&private);
    let mut tunnel = Tunn::new(
        private,
        PublicKey::from(key(&args.peer_public_key)?),
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
