// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Fresh authenticated packets for a single live session; never replay an encrypted pool.
use anyhow::{Context, Result, bail, ensure};
use bytes::BytesMut;
use gotatun::{
    noise::Tunn,
    packet::{IpNextProtocol, Ipv4, Ipv4Header, Packet, UdpHeader, WgKind, checksum},
};
use std::{net::Ipv4Addr, time::Instant};
use zerocopy::{FromBytes, IntoBytes};

pub const ALICE_TUN: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 1);
pub const BOB_TUN: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
pub const MAGIC: &[u8; 8] = b"BGIOv001";

pub fn inner_packet(sequence: usize, payload_len: usize, port: u16) -> Packet {
    let mut data = BytesMut::zeroed((20 + 8 + payload_len).div_ceil(16) * 16);
    let packet = Ipv4::<[u8]>::mut_from_bytes(&mut data).unwrap();
    packet.header = Ipv4Header::new_for_length(
        BOB_TUN,
        ALICE_TUN,
        IpNextProtocol::Udp,
        (8 + payload_len) as u16,
    );
    packet.header.header_checksum = checksum(&[packet.header.as_bytes()]).into();
    // IPv4 permits a zero UDP checksum; no checksum work is needed during transmission.
    packet.payload[..8]
        .copy_from_slice(UdpHeader::new(port, port, (8 + payload_len) as u16, 0).as_bytes());
    packet.payload[8..16].copy_from_slice(MAGIC);
    packet.payload[16..24].copy_from_slice(&(sequence as u64).to_le_bytes());
    Packet::from_bytes(data)
}

pub fn wire_len(payload_len: usize) -> usize {
    (20 + 8 + payload_len).div_ceil(16) * 16 + 32
}

pub struct Pool {
    pub bytes: Vec<u8>,
    pub stride: usize,
    pub prepare_seconds: f64,
}

/// Application input for upload: payload bytes, rather than outer-sized control datagrams.
pub fn payload_pool(count: usize, payload_len: usize) -> Result<Pool> {
    let size = count
        .checked_mul(payload_len)
        .context("payload buffer overflow")?;
    ensure!(
        payload_len >= 16 && size <= 2 * 1024 * 1024 * 1024,
        "invalid payload buffer"
    );
    let start = Instant::now();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size)?;
    bytes.resize(size, 0);
    for (seq, data) in bytes.chunks_exact_mut(payload_len).enumerate() {
        data[..8].copy_from_slice(MAGIC);
        data[8..16].copy_from_slice(&(seq as u64).to_le_bytes());
    }
    Ok(Pool {
        bytes,
        stride: payload_len,
        prepare_seconds: start.elapsed().as_secs_f64(),
    })
}

pub fn prepare(
    mut tunnel: Option<&mut Tunn>,
    count: usize,
    payload_len: usize,
    port: u16,
) -> Result<Pool> {
    let stride = wire_len(payload_len);
    let size = count
        .checked_mul(stride)
        .context("packet buffer overflow")?;
    ensure!(
        size <= 2 * 1024 * 1024 * 1024,
        "buffer exceeds the experiment's 2 GiB limit"
    );
    let started = Instant::now();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .context("cannot allocate packet buffer")?;
    for sequence in 0..count {
        if let Some(tunnel) = tunnel.as_deref_mut() {
            let packet = inner_packet(sequence, payload_len, port);
            let Some(WgKind::Data(packet)) = tunnel.handle_outgoing_packet(packet, None) else {
                bail!("session cannot encrypt data; refusing an incomplete pool");
            };
            let packet = packet.into_bytes();
            ensure!(packet.len() == stride, "unexpected WireGuard packet size");
            bytes.extend_from_slice(&packet);
        } else {
            let offset = bytes.len();
            bytes.resize(offset + stride, 0);
            bytes[offset..offset + 8].copy_from_slice(MAGIC);
            bytes[offset + 8..offset + 16].copy_from_slice(&(sequence as u64).to_le_bytes());
        }
    }
    Ok(Pool {
        bytes,
        stride,
        prepare_seconds: started.elapsed().as_secs_f64(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gotatun::{
        noise::{TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::{Decoder, Ipv4Decoder},
        x25519::{PublicKey, StaticSecret},
    };
    use std::sync::Arc;

    #[test]
    fn pool_uses_unique_counters_and_preserves_valid_inner_packets() {
        let a = StaticSecret::from([1; 32]);
        let b = StaticSecret::from([2; 32]);
        let ap = PublicKey::from(&a);
        let bp = PublicKey::from(&b);
        let make = |private, public, peer| {
            Tunn::new(
                private,
                peer,
                None,
                None,
                IndexTable::from_os_rng(),
                Arc::new(RateLimiter::new(&public, 100)),
            )
        };
        let mut alice = make(a, ap, bp);
        let mut bob = make(b, bp, ap);
        let init = bob.format_handshake_initiation(false).unwrap();
        let TunnResult::WriteToNetwork(response) =
            alice.handle_incoming_packet(WgKind::HandshakeInit(init))
        else {
            panic!("response");
        };
        let TunnResult::WriteToNetwork(keepalive) = bob.handle_incoming_packet(response) else {
            panic!("confirmation");
        };
        alice.handle_incoming_packet(keepalive);
        let pool = prepare(Some(&mut bob), 3, 1200, 19432).unwrap();
        for (sequence, raw) in pool.bytes.chunks_exact(pool.stride).enumerate() {
            let decode = || Packet::copy_from(raw).try_into_wg().unwrap();
            let TunnResult::WriteToTunnel(plain) = alice.handle_incoming_packet(decode()) else {
                panic!("decryption");
            };
            let ip: Packet<Ipv4> = Ipv4Decoder::CHECK_ALL.decode_owned(plain).unwrap();
            assert_eq!(ip.header.destination(), ALICE_TUN);
            assert_eq!(&ip.payload[8..16], MAGIC);
            assert_eq!(
                u64::from_le_bytes(ip.payload[16..24].try_into().unwrap()),
                sequence as u64
            );
            assert!(
                !matches!(
                    alice.handle_incoming_packet(decode()),
                    TunnResult::WriteToTunnel(_)
                ),
                "replay must remain rejected"
            );
        }
    }
}
