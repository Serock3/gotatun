// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{net::Ipv4Addr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, bail};
use benchy_runner::{
    BenchmarkDefinition, MachineLock, Recorder, default_output_path, hotpath::record_hotpath_report,
};
use bytes::BytesMut;
use clap::Parser;
use gotatun::{
    noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
    packet::{IpNextProtocol, Ipv4, Ipv4Header, Packet, WgKind},
    x25519::{PublicKey, StaticSecret},
};
use zerocopy::FromBytes;

const DEFINITION: BenchmarkDefinition = BenchmarkDefinition {
    repository: "gotatun",
    name: "gotatun-hotpath",
    description: "GotaTun data-path profile of the noise functions measured with hotpath-rs",
};

#[global_allocator]
static ALLOCATOR: hotpath::CountingAllocator = hotpath::CountingAllocator::new();

const HANDSHAKE_RATE_LIMIT: u64 = 100;
const PACKETS_PER_DIRECTION: usize = 200_000;
const WARMUP_PACKETS_PER_DIRECTION: usize = 10_000;
const PAYLOAD_LEN: usize = 1200;

#[derive(Parser)]
#[command(version, about = "In-process GotaTun data-path profiling benchmark")]
struct Cli {
    #[arg(long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let output = cli
        .output
        .unwrap_or_else(|| default_output_path(DEFINITION.name));

    // Keep the data-path machines exclusive: a concurrent tunnel run would skew the timings.
    let _machine_lock = MachineLock::acquire("/tmp/benchy.lock")?;

    // Keep the raw profile next to the result, under a subdirectory ignored by the exporter.
    let report_dir = output
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("profiles");
    tokio::fs::create_dir_all(&report_dir).await?;
    let report_path = report_dir.join("gotatun-hotpath.json");
    let mut recorder = Recorder::new(DEFINITION, &output).await;
    recorder.parameter("packets_per_direction", PACKETS_PER_DIRECTION);
    recorder.parameter("warmup_packets_per_direction", WARMUP_PACKETS_PER_DIRECTION);
    recorder.parameter("payload_len", PAYLOAD_LEN);
    recorder.parameter("aead_backend", "aws-lc-rs");
    recorder.parameter("hotpath_version", "0.30.1");
    recorder.parameter(
        "profiling",
        "inclusive timing and exclusive allocation bytes; serial locks",
    );
    recorder.parameter("lock_scope", "handshake, warmup and measured packets");
    recorder.parameter("profile", "profiles/gotatun-hotpath.json");
    let result = run_data_path(&report_path).and_then(|()| {
        let report = std::fs::read(&report_path)
            .with_context(|| format!("failed to read {}", report_path.display()))?;
        let parsed = benchy_runner::hotpath::parse_hotpath_report(&report)?;
        let timing = parsed
            .functions_timing
            .as_ref()
            .context("missing function timings")?;
        for name in [
            "handle_outgoing_packet",
            "format_packet_data",
            "handle_incoming_packet",
            "receive_packet_data",
        ] {
            anyhow::ensure!(
                timing.data.iter().any(|entry| entry.name.ends_with(name)
                    && entry.calls == 2 * PACKETS_PER_DIRECTION as u64
                    && entry.sampled_calls == entry.calls),
                "missing or incorrect call count for {name}"
            );
        }
        anyhow::ensure!(
            parsed.functions_alloc.is_some(),
            "missing allocation measurements"
        );
        record_hotpath_report(&mut recorder, None, &report)
    });

    match result {
        Ok(()) => recorder.success().await,
        Err(error) => {
            recorder.failure(&error).await?;
            Err(error)
        }
    }
}

/// Exchanges packets through both tunnel directions between two in-process tunnels: no TUN
/// devices, network, or privileges, so the measurements isolate the noise data path.
fn run_data_path(report_path: &std::path::Path) -> Result<()> {
    let make_tunn = |private: StaticSecret, peer_public: PublicKey| {
        let public = PublicKey::from(&private);
        let rate_limiter = Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT));
        Tunn::new(
            private,
            peer_public,
            None,
            None,
            IndexTable::from_os_rng(),
            rate_limiter,
        )
    };

    let alice_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let bob_private = StaticSecret::from(rand::random::<[u8; 32]>());
    let alice_public = PublicKey::from(&alice_private);
    let bob_public = PublicKey::from(&bob_private);
    let mut alice = make_tunn(alice_private, bob_public);
    let mut bob = make_tunn(bob_private, alice_public);

    let packet_template = {
        let payload = vec![0u8; PAYLOAD_LEN];
        let mut buf = BytesMut::zeroed(Ipv4Header::LEN + payload.len());
        let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).expect("buffer fits an IPv4 header");
        ipv4.header = Ipv4Header::new(
            Ipv4Addr::new(10, 0, 1, 1),
            Ipv4Addr::new(10, 0, 1, 2),
            IpNextProtocol::Udp,
            &payload,
        );
        ipv4.payload.copy_from_slice(&payload);
        buf.freeze()
    };

    let handshake_init = alice
        .format_handshake_initiation(false)
        .context("failed to format handshake initiation")?;
    let TunnResult::WriteToNetwork(handshake) =
        bob.handle_incoming_packet(WgKind::HandshakeInit(handshake_init))
    else {
        bail!("expected a handshake response");
    };
    let WgKind::HandshakeResp(handshake) = handshake else {
        bail!("expected a handshake response packet");
    };
    match alice.handle_incoming_packet(WgKind::HandshakeResp(handshake)) {
        TunnResult::WriteToNetwork(WgKind::Data(keepalive)) => {
            let _ = bob.handle_incoming_packet(WgKind::Data(keepalive));
        }
        result => bail!("handshake did not complete: {result:?}"),
    }

    let mut exchange = || -> Result<()> {
        // The packet buffers are consumed by encapsulation, so every iteration needs a fresh
        // copy of the template.
        let packet = Packet::from_bytes(BytesMut::from(&packet_template[..]));
        let Some(wg_packet) = alice.handle_outgoing_packet(packet, None) else {
            bail!("failed to encapsulate a packet");
        };
        let WgKind::Data(wg_packet) = wg_packet else {
            bail!("expected an encapsulated data packet");
        };
        match bob.handle_incoming_packet(WgKind::Data(wg_packet)) {
            TunnResult::WriteToTunnel(decrypted) => {
                std::hint::black_box(&decrypted);
            }
            result => bail!("failed to decapsulate a packet: {result:?}"),
        }

        let packet = Packet::from_bytes(BytesMut::from(&packet_template[..]));
        let Some(wg_packet) = bob.handle_outgoing_packet(packet, None) else {
            bail!("failed to encapsulate a packet");
        };
        let WgKind::Data(wg_packet) = wg_packet else {
            bail!("expected an encapsulated data packet");
        };
        match alice.handle_incoming_packet(WgKind::Data(wg_packet)) {
            TunnResult::WriteToTunnel(decrypted) => {
                std::hint::black_box(&decrypted);
            }
            result => bail!("failed to decapsulate a packet: {result:?}"),
        }
        Ok(())
    };
    for _ in 0..WARMUP_PACKETS_PER_DIRECTION {
        exchange()?;
    }
    // Handshake and warmup are outside the function measurement region. The report check
    // rejects environment overrides that change the requested full timing sample.
    let _guard = hotpath::HotpathGuardBuilder::new("gotatun-hotpath")
        .format(hotpath::Format::Json)
        .time_sampling_rate(1.0)
        .output_path(report_path)
        .build();
    for _ in 0..PACKETS_PER_DIRECTION {
        exchange()?;
    }
    Ok(())
}
