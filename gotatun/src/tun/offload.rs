// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0 was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Linux TUN offloads: [`IFF_VNET_HDR`], TSO segmentation on send and GRO
//! coalescing on receive.
//!
//! With `TUNSETOFFLOAD(TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6)` the kernel
//! reads and writes TCP superpackets through the TUN fd, preceded by a
//! [`virtio_net_hdr`](VirtioNetHdr):
//!
//! - reading yields one superpacket per syscall, which [`split_gso`]
//!   cuts back into MTU-sized segments with fixed up per-segment lengths,
//!   sequence numbers, flags and checksums;
//! - writing accepts coalesced segments (built by [`GroBuffer`]) as one
//!   `writev`, with `VIRTIO_NET_HDR_F_NEEDS_CSUM` asking the kernel to
//!   compute the transport checksum of a superpacket it segments or
//!   delivers locally.
//!
//! This is the TUN-side counterpart of what wireguard-go does in
//! `tun/offload_linux.go`.

use std::io;
use std::os::fd::RawFd;

use nix::ioctl_write_int;
use zerocopy::TryFromBytes;

use crate::packet::{
    Packet, PseudoHeaderV4, PseudoHeaderV6, Tcp, checksum, checksum_ipv4_with_skip,
    checksum_tcp_with_skip,
};

ioctl_write_int!(tusetoffload, b'T', 208);

/// TUN_F_* feature flags we ask the TUN for (checksum offload + TCP
/// segmentation for v4 and v6, with ECN).
use libc::c_ulong;

const TUN_F_CSUM: c_ulong = 0x01;
const TUN_F_TSO4: c_ulong = 0x02;
const TUN_F_TSO6: c_ulong = 0x04;
const TUN_F_TSO_ECN: c_ulong = 0x08;
pub(crate) const TUN_OFFLOAD_FEATURES: c_ulong =
    TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;

/// Size of the `virtio_net_hdr` that precedes every frame.
pub(crate) const VNET_HDR_LEN: usize = 10;

/// VIRTIO_NET_HDR_F_NEEDS_CSUM.
const HDR_F_NEEDS_CSUM: u8 = 1;
/// VIRTIO_NET_HDR_GSO_* (ECN is 0x80 OR'd onto the type by the kernel).
const GSO_NONE: u8 = 0;
const GSO_TCPV4: u8 = 1;
const GSO_TCPV6: u8 = 4;
const GSO_ECN: u8 = 0x80;

/// The `virtio_net_hdr` as it appears on the TUN fd. Integer fields are in
/// the byte order of the running kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    /// Total length of the L3 + L4 header of the segment payload.
    pub hdr_len: u16,
    /// Segment (payload) size the kernel split the packet into / wants.
    pub gso_size: u16,
    /// Offset within the IP packet where checksumming starts.
    pub csum_start: u16,
    /// Offset after `csum_start` where the checksum goes.
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    /// Header for a plain (non-GSO) frame.
    pub(crate) const fn plain() -> Self {
        Self {
            flags: 0,
            gso_type: GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        }
    }

    /// Parse from the first [`VNET_HDR_LEN`] bytes of a read.
    pub(crate) fn parse(buf: &[u8]) -> Option<Self> {
        let b = buf.get(..VNET_HDR_LEN)?;
        Some(Self {
            flags: b[0],
            gso_type: b[1],
            hdr_len: u16::from_le_bytes(b[2..4].try_into().ok()?),
            gso_size: u16::from_le_bytes(b[4..6].try_into().ok()?),
            csum_start: u16::from_le_bytes(b[6..8].try_into().ok()?),
            csum_offset: u16::from_le_bytes(b[8..10].try_into().ok()?),
        })
    }

    /// The header as it must precede a write to the TUN fd.
    pub(crate) fn to_bytes(self) -> [u8; VNET_HDR_LEN] {
        let mut out = [0u8; VNET_HDR_LEN];
        out[0] = self.flags;
        out[1] = self.gso_type;
        out[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        out[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        out[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        out
    }
}

/// Enable TUN offloads on an open TUN fd. An error means this kernel or
/// device does not support them; the caller must stick to
/// [`VirtioNetHdr::plain()`] framing (which an `IFF_VNET_HDR` fd requires
/// regardless).
pub(crate) fn set_offloads(fd: RawFd) -> io::Result<()> {
    // SAFETY: `tusetoffload` issues the TUNSETOFFLOAD ioctl, which takes an
    // `unsigned int` by value. `fd` is an open TUN fd owned by the caller.
    let res = unsafe { tusetoffload(fd, TUN_OFFLOAD_FEATURES) };
    res.map(|_| ()).map_err(io::Error::from)
}

/// Length of the IP header in `buf` (launching point for TCP), if `buf` is
/// an IP packet.
fn ip_header_len(buf: &[u8]) -> Option<usize> {
    match buf.first()? >> 4 {
        4 => Some((buf[0] & 0x0f) as usize * 4),
        6 => Some(40),
        _ => None,
    }
}

/// TCP protocol number (the same in IPv4 and IPv6; this is
/// `IpNextProtocol::Tcp`'s raw value, spelled out because zerocopy's
/// `IntoBytes` is not const).
const TCP_PROTO: u8 = 6;
const _: () = assert!(TCP_PROTO == 6);

/// Split one TCP superpacket (`frame`, the IP packet without the virtio
/// header) into MTU-sized segments, appending them to `out` as [`Packet`]s
/// copied out of `pool`. Returns the number of segments produced.
///
/// Per segment, mirroring what the kernel's software GSO path does:
/// - IPv4: `total_length` is recomputed, `identification` incremented, and the
///   header checksum recomputed. IPv6: `payload_length` recomputed.
/// - TCP: sequence numbers advance by `gso_size`; PSH and FIN are only kept
///   on the final segment; the full checksum is computed from the
///   pseudo-header and this segment alone.
pub(crate) fn split_gso(
    frame: &[u8],
    hdr: &VirtioNetHdr,
    pool: &mut crate::packet::PacketBufPool,
    out: &mut Vec<Packet>,
) -> io::Result<usize> {
    let is_v4 = frame.first().is_some_and(|b| b >> 4 == 4);
    let gso = hdr.gso_type & !GSO_ECN;
    let type_matches = (gso == GSO_TCPV4 && is_v4) || (gso == GSO_TCPV6 && !is_v4);
    if !type_matches {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported gso_type {}", hdr.gso_type),
        ));
    }
    let ip_hdr_len = ip_header_len(frame)
        .filter(|&l| l < frame.len())
        .ok_or_else(|| bad_frame("no IP header"))?;
    let headers_len = hdr.hdr_len as usize;
    if headers_len < ip_hdr_len + 20 || headers_len > frame.len() {
        return Err(bad_frame("hdr_len out of range"));
    }
    let gso_size = hdr.gso_size as usize;
    if gso_size == 0 {
        return Err(bad_frame("zero gso_size"));
    }

    let total = frame.len();
    let n_segments = (total - headers_len).div_ceil(gso_size);
    let mut written = 0usize;
    for seg_index in 0..n_segments {
        let payload_start = headers_len + written;
        let seg_payload = (total - payload_start).min(gso_size);
        let seg_len = headers_len + seg_payload;

        let mut pkt = pool.get();
        let bytes = pkt.buf_mut();
        bytes.clear();
        bytes.resize(seg_len, 0);
        bytes[..headers_len].copy_from_slice(&frame[..headers_len]);
        bytes[headers_len..seg_len]
            .copy_from_slice(&frame[payload_start..payload_start + seg_payload]);

        {
            let seg = &mut bytes[..seg_len];
            if is_v4 {
                seg[2..4].copy_from_slice(&(seg_len as u16).to_be_bytes());
                let id = u16::from_be_bytes(seg[4..6].try_into().unwrap())
                    .wrapping_add(seg_index as u16);
                seg[4..6].copy_from_slice(&id.to_be_bytes());
            } else {
                seg[4..6].copy_from_slice(&((seg_len - 40) as u16).to_be_bytes());
            }

            // The TCP header starts right after the IP header; note that
            // `headers_len` additionally includes the TCP header itself.
            let tcp_off = ip_hdr_len;
            let base_seq =
                u32::from_be_bytes(seg[tcp_off + 4..tcp_off + 8].try_into().unwrap());
            seg[tcp_off + 4..tcp_off + 8]
                .copy_from_slice(&base_seq.wrapping_add(written as u32).to_be_bytes());
            // PSH and FIN belong to the last segment alone.
            if payload_start + seg_payload < total {
                seg[tcp_off + 13] &= !(0x08 | 0x01);
            }

            // Checksums: transported one is computed over the pseudo-header
            // plus this segment, skipping the (stale) checksum word.
            let tcp: &Tcp<[u8]> = Tcp::try_ref_from_bytes(&seg[ip_hdr_len..])
                .map_err(|_| bad_frame("no TCP header"))?;
            let csum = if is_v4 {
                let pseudo = PseudoHeaderV4::from_tcp(
                    u32::from_be_bytes(seg[12..16].try_into().unwrap()).into(),
                    u32::from_be_bytes(seg[16..20].try_into().unwrap()).into(),
                    tcp,
                );
                checksum_tcp_with_skip(pseudo, tcp)
            } else {
                let pseudo = PseudoHeaderV6::from_tcp(
                    u128::from_be_bytes(seg[8..24].try_into().unwrap()).into(),
                    u128::from_be_bytes(seg[24..40].try_into().unwrap()).into(),
                    tcp,
                );
                checksum_tcp_with_skip(pseudo, tcp)
            };
            seg[ip_hdr_len + 16..ip_hdr_len + 18].copy_from_slice(&csum.to_be_bytes());

            if is_v4 {
                // Skips the checksum word: the copied one is stale.
                let hdr_csum = checksum_ipv4_with_skip(&seg[..ip_hdr_len]);
                seg[10..12].copy_from_slice(&hdr_csum.to_be_bytes());
            }
        }

        out.push(pkt);
        written += seg_payload;
    }
    Ok(n_segments)
}

/// Everything needed to decide whether a received TCP segment can join a
/// coalescing group, and to merge it in.
#[derive(Clone, Copy)]
struct SegmentMeta {
    version: u8,
    flow: ([u8; 16], [u8; 16], u16, u16),
    ip_hdr_len: usize,
    tcp_hdr_len: usize,
    seq: u32,
    payload_len: usize,
    flags: u8,
    window: u16,
    ack: u32,
}

impl SegmentMeta {
    /// Parse a complete IP packet. `None` if it is not a TCP packet we can
    /// handle (non-IPv4/6, fragmented IPv4, no TCP header).
    fn parse(pkt: &[u8]) -> Option<Self> {
        let version = pkt.first()? >> 4;
        let (ip_hdr_len, proto) = match version {
            4 => {
                if pkt.len() < 20 {
                    return None;
                }
                let frag = u16::from_be_bytes(pkt[6..8].try_into().ok()?) & 0x3fff;
                if frag != 0 {
                    return None;
                }
                ((pkt[0] & 0x0f) as usize * 4, pkt[9])
            }
            6 => {
                if pkt.len() < 40 {
                    return None;
                }
                (40, pkt[6])
            }
            _ => return None,
        };
        if proto != TCP_PROTO {
            return None;
        }
        let tcp_off = ip_hdr_len;
        if pkt.len() < tcp_off + 20 {
            return None;
        }
        let tcp_hdr_len = ((pkt[tcp_off + 12] >> 4) as usize) * 4;
        if tcp_hdr_len < 20 || pkt.len() < tcp_off + tcp_hdr_len {
            return None;
        }

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        if version == 4 {
            src_ip[..4].copy_from_slice(&pkt[12..16]);
            dst_ip[..4].copy_from_slice(&pkt[16..20]);
        } else {
            src_ip.copy_from_slice(&pkt[8..24]);
            dst_ip.copy_from_slice(&pkt[24..40]);
        }

        Some(Self {
            version,
            flow: (
                src_ip,
                dst_ip,
                u16::from_be_bytes(pkt[tcp_off..tcp_off + 2].try_into().ok()?),
                u16::from_be_bytes(pkt[tcp_off + 2..tcp_off + 4].try_into().ok()?),
            ),
            ip_hdr_len,
            tcp_hdr_len,
            seq: u32::from_be_bytes(pkt[tcp_off + 4..tcp_off + 8].try_into().ok()?),
            payload_len: pkt.len() - tcp_off - tcp_hdr_len,
            flags: pkt[tcp_off + 13],
            window: u16::from_be_bytes(pkt[tcp_off + 14..tcp_off + 16].try_into().ok()?),
            ack: u32::from_be_bytes(pkt[tcp_off + 8..tcp_off + 12].try_into().ok()?),
        })
    }

    /// Pure ACKs/data segments only: SYN, FIN, RST, URG alter semantics the
    /// group logic doesn't model.
    fn eligible(&self) -> bool {
        self.flags & (0x02 | 0x01 | 0x04 | 0x20) == 0
    }
}

/// Coalescing buffer for received TCP segments: consecutive `seq`-contiguous
/// segments of one flow are merged into one superpacket for the TUN.
#[derive(Default)]
pub(crate) struct GroBuffer {
    /// Header (IP+TCP, of the first segment) plus concatenated payloads. A
    /// `Vec` per group: one allocation per ~40 packets written.
    pending: Option<Vec<u8>>,
    meta: Option<SegmentMeta>,
    /// Sequence number the next segment must carry.
    next_seq: u32,
    /// Payload length of the first segment (and all that follow, except the
    /// last, which may be shorter).
    gso_size: usize,
    segments: usize,
    /// A short segment was absorbed: the group is complete and must be
    /// flushed before another can start.
    closed: bool,
}

/// Max payload bytes in one coalesced superpacket. 32k keeps any IPv4
/// `total_length` representable with room to spare.
const MAX_GRO_BYTES: usize = 32 * 1024;
const MAX_GRO_SEGMENTS: usize = 64;
/// The kernel refuses to process (silently drops!) GSO skbs whose segment
/// size is under its `TCP_MIN_GSO_SIZE` (8, on this kernel family: verified
/// empirically that gso_size 1 is accepted by write() but never delivered,
/// while 8 passes). Only payloads at least this large start a group; smaller
/// packets are written as plain frames.
const MIN_GRO_SEGMENT: usize = 8;

impl GroBuffer {
    /// Try to absorb `pkt` into the pending superpacket. Returns `false` when
    /// it doesn't fit; the caller must [`GroBuffer::take`] the pending packet
    /// first, then either retry or write `pkt` on its own.
    pub(crate) fn try_append(&mut self, pkt: &[u8]) -> bool {
        let Some(meta) = SegmentMeta::parse(pkt) else {
            return false;
        };
        if !meta.eligible() || meta.payload_len < MIN_GRO_SEGMENT {
            return false;
        }

        if self.closed {
            // Flush before starting anything new.
            return false;
        }
        if let (Some(pending), Some(cur)) = (&mut self.pending, self.meta) {
            if cur.version == meta.version
                && cur.flow == meta.flow
                && (cur.ip_hdr_len, cur.tcp_hdr_len) == (meta.ip_hdr_len, meta.tcp_hdr_len)
                && meta.seq == self.next_seq
                && meta.ack == cur.ack
                && meta.window == cur.window
                && meta.payload_len <= self.gso_size
                && pending.len() + meta.payload_len <= MAX_GRO_BYTES
                && self.segments < MAX_GRO_SEGMENTS
            {
                let tcp_off = meta.ip_hdr_len;
                // The merged packet keeps the first segment's header, with
                // window and PSH/FIN from the newest segment.
                pending[tcp_off + 14..tcp_off + 16]
                    .copy_from_slice(&pkt[tcp_off + 14..tcp_off + 16]);
                pending[tcp_off + 13] =
                    (pending[tcp_off + 13] & !0x09) | (meta.flags & 0x09);
                pending.extend_from_slice(&pkt[tcp_off + meta.tcp_hdr_len..]);
                self.next_seq = self.next_seq.wrapping_add(meta.payload_len as u32);
                self.segments += 1;
                // A short segment ends the group: the next contiguous
                // segment would have a different gso_size.
                if meta.payload_len != self.gso_size {
                    self.closed = true;
                }
                return true;
            }
            return false;
        }

        // Start a new group.
        self.meta = Some(meta);
        self.pending = Some(pkt.to_vec());
        self.next_seq = meta.seq.wrapping_add(meta.payload_len as u32);
        self.gso_size = meta.payload_len;
        self.segments = 1;
        self.closed = meta.payload_len == 0;
        true
    }

    /// The pending group is complete (a short segment ended it) and should be
    /// written out now.
    pub(crate) fn wants_flush(&self) -> bool {
        self.closed
    }

    /// Take the pending superpacket with the virtio header to write in front
    /// of it, or `None` when nothing is pending.
    pub(crate) fn take(&mut self) -> Option<(VirtioNetHdr, Vec<u8>)> {
        let mut pending = self.pending.take()?;
        let meta = self.meta.take()?;
        self.segments = 0;
        self.closed = false;
        let ip_hdr_len = meta.ip_hdr_len;
        let headers_len = ip_hdr_len + meta.tcp_hdr_len;

        let total_len = pending.len();
        if meta.version == 4 {
            pending[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            // Skip variant: the first segment's checksum is in the header.
            let hdr_csum = checksum_ipv4_with_skip(&pending[..ip_hdr_len]);
            pending[10..12].copy_from_slice(&hdr_csum.to_be_bytes());
        } else {
            pending[4..6].copy_from_slice(&((total_len - 40) as u16).to_be_bytes());
        }

        // The kernel validates (not computes) the transport checksum of
        // TUN-ingress packets on this code path, GSO or not: the merged
        // header's stale checksum word would fail for the superpacket, so
        // compute the full checksum of [pseudo-header + merged TCP part].
        // The NEEDS_CSUM metadata additionally lets the egress sides that do
        // honor it skip recomputation.
        let Ok(tcp) = Tcp::try_ref_from_bytes(&pending[ip_hdr_len..]) else {
            // Should be impossible: every segment was parsed the same way.
            return None;
        };
        let csum = if meta.version == 4 {
            let pseudo = PseudoHeaderV4::from_tcp(
                u32::from_be_bytes(pending[12..16].try_into().unwrap()).into(),
                u32::from_be_bytes(pending[16..20].try_into().unwrap()).into(),
                tcp,
            );
            checksum_tcp_with_skip(pseudo, tcp)
        } else {
            let pseudo = PseudoHeaderV6::from_tcp(
                u128::from_be_bytes(pending[8..24].try_into().unwrap()).into(),
                u128::from_be_bytes(pending[24..40].try_into().unwrap()).into(),
                tcp,
            );
            checksum_tcp_with_skip(pseudo, tcp)
        };
        pending[ip_hdr_len + 16..ip_hdr_len + 18].copy_from_slice(&csum.to_be_bytes());

        let hdr = VirtioNetHdr {
            flags: HDR_F_NEEDS_CSUM,
            gso_type: if meta.version == 4 {
                GSO_TCPV4
            } else {
                GSO_TCPV6
            },
            hdr_len: headers_len as u16,
            gso_size: self.gso_size as u16,
            csum_start: ip_hdr_len as u16,
            csum_offset: 16,
        };
        Some((hdr, pending))
    }
}

fn bad_frame(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// Complete the transport checksum of a frame the kernel handed us with
/// `VIRTIO_NET_HDR_F_NEEDS_CSUM` and `gso_type == NONE`: the checksum word at
/// `csum_start + csum_offset` is missing and must cover the pseudo-header
/// (IP, except plain ICMPv4) plus bytes `csum_start..` with the checksum word
/// zeroed. Without this, every offloaded TCP packet leaves with an invalid
/// checksum and the peer drops it.
pub(crate) fn complete_checksum(frame: &mut [u8], csum_start: usize, csum_offset: usize) -> bool {
    let Some(&version) = frame.first() else {
        return false;
    };
    let src: std::ops::Range<usize> = match version >> 4 {
        4 if frame.len() >= 20 => 12..20,
        6 if frame.len() >= 40 => 8..40,
        _ => return false,
    };
    let proto = if version >> 4 == 4 { frame[9] } else { frame[6] };
    if csum_start >= frame.len() || csum_start + csum_offset + 2 > frame.len() {
        return false;
    }
    let l4_len = frame.len() - csum_start;
    let csum_field = csum_start + csum_offset;
    frame[csum_field..csum_field + 2].copy_from_slice(&[0, 0]);

    let mut pseudo = [0u8; 40];
    let pseudo_len = match version >> 4 {
        4 => {
            pseudo[..8].copy_from_slice(&frame[src]);
            pseudo[9] = proto;
            pseudo[10..12].copy_from_slice(&(l4_len as u16).to_be_bytes());
            12
        }
        _ => {
            pseudo[..32].copy_from_slice(&frame[src]);
            pseudo[32] = proto;
            pseudo[36..38].copy_from_slice(&(l4_len as u16).to_be_bytes());
            38
        }
    };

    // ICMPv4 checksums have no pseudo-header.
    let csum = if version >> 4 == 4 && proto == 1 {
        checksum(&[&frame[csum_start..]])
    } else {
        checksum(&[&pseudo[..pseudo_len], &frame[csum_start..]])
    };
    // In UDP (over IPv4 or IPv6), a computed checksum of zero is transmitted
    // as all-ones.
    let csum = if proto == 17 && csum == 0 { !0 } else { csum };
    frame[csum_field..csum_field + 2].copy_from_slice(&csum.to_be_bytes());
    true
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    /// A NEEDS_CSUM frame must come back with a checksum a receiver accepts:
    /// recompute it and require zero (the "internet checksum" property).
    #[test]
    fn complete_checksum_tcpv4_and_v6() {
        let mut v4 = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        v4.extend_from_slice(&[0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
        assert!(complete_checksum(&mut v4, 20, 16));
        // recompute: pseudo + tcp with checksum word must sum to zero
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&v4[12..16]);
        pseudo[4..8].copy_from_slice(&v4[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&((v4.len() - 20) as u16).to_be_bytes());
        assert_eq!(checksum(&[&pseudo, &v4[20..]]), 0);

        let mut v6 = vec![
            0x60, 0, 0, 0, 0, 20, 6, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ];
        v6.extend_from_slice(&[0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x10, 0xff, 0xff, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
        assert!(complete_checksum(&mut v6, 40, 16));
        let mut pseudo6 = [0u8; 40];
        pseudo6[..16].copy_from_slice(&v6[8..24]);
        pseudo6[16..32].copy_from_slice(&v6[24..40]);
        pseudo6[32] = 6;
        pseudo6[36..38].copy_from_slice(&((v6.len() - 40) as u16).to_be_bytes());
        assert_eq!(checksum(&[&pseudo6[..38], &v6[40..]]), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal IPv4+TCP packet with `payload` and a correct-enough header
    /// for the parsers and splitters here.
    fn tcp_packet(src: [u8; 4], dst: [u8; 4], seq: u32, payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let mut p = vec![0u8; 20 + tcp_len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = TCP_PROTO;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&1000u16.to_be_bytes());
        p[22..24].copy_from_slice(&2000u16.to_be_bytes());
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[28..32].copy_from_slice(&0u32.to_be_bytes());
        p[32] = 5 << 4; // data offset 5
        p[33] = 0x10; // ACK
        p[34..36].copy_from_slice(&0xffffu16.to_be_bytes());
        p[40..40 + payload.len()].copy_from_slice(payload);
        p
    }

    impl VirtioNetHdr {
        /// A TSO-style header for tests.
        fn tcp_like(gso_type: u8) -> Self {
            Self {
                flags: HDR_F_NEEDS_CSUM,
                gso_type,
                hdr_len: 40,
                gso_size: 1460,
                csum_start: 20,
                csum_offset: 16,
            }
        }
    }

    #[test]
    fn virtio_hdr_roundtrip() {
        let hdr = VirtioNetHdr::tcp_like(GSO_TCPV4);
        let bytes = hdr.to_bytes();
        assert_eq!(VirtioNetHdr::parse(&bytes), Some(hdr));
        assert_eq!(VirtioNetHdr::parse(&[0u8; VNET_HDR_LEN]), Some(VirtioNetHdr::plain()));
    }

    #[test]
    fn split_then_gro_roundtrip() {
        // One superpacket: headers + 3.5 segments of 1000 bytes payload.
        let payload: Vec<u8> = (0..3500u32).map(|i| (i % 251) as u8).collect();
        let base = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 42, &payload);
        let hdr = VirtioNetHdr {
            flags: 1,
            gso_type: GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1000,
            csum_start: 20,
            csum_offset: 16,
        };

        let mut pool = crate::packet::PacketBufPool::new(8);
        let mut segments = Vec::new();
        let n = split_gso(&base, &hdr, &mut pool, &mut segments).unwrap();
        assert_eq!(n, 4);
        assert_eq!(segments.len(), 4);
        assert_eq!(segments[0].len(), 40 + 1000);
        assert_eq!(segments.last().unwrap().len(), 40 + 500);

        // GRO the segments back into one superpacket.
        let mut gro = GroBuffer::default();
        for seg in &segments {
            assert!(gro.try_append(seg), "segment must join the group");
        }
        assert!(gro.wants_flush(), "short last segment closes the group");
        let (vhdr, merged) = gro.take().unwrap();
        assert_eq!(vhdr.gso_size, 1000);
        assert_eq!(vhdr.gso_type, GSO_TCPV4);
        assert_eq!(merged.len(), 40 + 3500);
        assert_eq!(merged[24..28], 42u32.to_be_bytes()); // first seq
        assert_eq!(&merged[40..], &payload[..]);

        // Twice-re-split must yield the same bytes.
        let mut pool2 = crate::packet::PacketBufPool::new(8);
        let mut resegs = Vec::new();
        let n2 = split_gso(&merged, &vhdr, &mut pool2, &mut resegs).unwrap();
        assert_eq!(n2, 4);
        for (a, b) in segments.iter().zip(resegs.iter()) {
            assert_eq!(&a[..], &b[..]);
        }
    }

    #[test]
    fn gro_rejects_gaps_and_other_flows() {
        let mut gro = GroBuffer::default();
        assert!(gro.try_append(&tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            100,
            &[0; 100]
        )));
        // Not contiguous.
        assert!(!gro.try_append(&tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            300,
            &[0; 100]
        )));
        // Different flow.
        assert!(!gro.try_append(&tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 3],
            200,
            &[0; 100]
        )));
        // A short segment is absorbed and closes the group.
        assert!(gro.try_append(&tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            200,
            &[0; 50]
        )));
        assert!(gro.wants_flush());
        assert_eq!(gro.segments, 2);
        let (_, merged) = gro.take().unwrap();
        assert_eq!(merged.len(), 40 + 150);
        // After a flush the next segment starts a new group.
        assert!(gro.try_append(&tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            250,
            &[0; 100]
        )));
    }
}
