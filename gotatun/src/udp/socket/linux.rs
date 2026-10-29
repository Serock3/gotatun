// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage};
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::{
    packet::Packet,
    udp::{
        UdpSend,
        socket::{UdpSocket, check_send_max_number_of_packets},
    },
};

/// Max number of packets/messages for sendmmsg/recvmmsg
const MAX_PACKET_COUNT: usize = 100;

/// Max bytes in one UDP GSO (`UDP_SEGMENT`) `sendmsg`. The segmented datagram
/// is a single IP packet, whose total length is limited to 65535 bytes; stay
/// comfortably below. WireGuard bursts are same-sized MTU-bound packets, so
/// this caps a GSO run at roughly 40 packets of tunnel-MTU size.
const MAX_GSO_BYTES: usize = 60_000;

/// Smallest segment size worth GSO'ing. For small segments (e.g. small
/// iperf-style UDP floods), the extra per-segment work the receiving stack
/// does in the sender's softirq outweighs the savings of one skb over many:
/// measured 128-byte UDP throughput dropped ~19% with unbounded GSO, while
/// MTU-sized TCP segments gain 23-28%. So only GSO substantial segments.
const MIN_GSO_SEGMENT_BYTES: usize = 1024;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        self.socket().send_to(&packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        check_send_max_number_of_packets(MAX_PACKET_COUNT, packets)?;

        let socket = self.socket();
        let fd = socket.as_raw_fd();

        let mut start = 0;
        while start < packets.len() {
            let end = start + gso_run_end(&packets[start..]);
            let run = &packets[start..end];

            if run.len() >= 2 && self.gso_supported.load(std::sync::atomic::Ordering::Relaxed) {
                match Self::send_gso_run(socket, fd, run).await {
                    Ok(()) => {
                        start = end;
                        continue;
                    }
                    Err(e) if is_gso_unsupported(&e) => {
                        // Remember this, so we don't retry GSO on every batch.
                        self.gso_supported
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        tracing::warn!("UDP GSO send failed ({e}); falling back to sendmmsg");
                    }
                    Err(e) => return Err(e),
                }
            }

            Self::send_run_sendmmsg(socket, fd, buf, run).await?;
            start = end;
        }
        debug_assert!(start == packets.len(), "all packets should be sent");
        packets.clear();

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        UdpSocket::local_addr(self).map(Some)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(self.socket(), sockopt::Mark, &mark)?;
        Ok(())
    }
}

/// Returns the exclusive end of the first UDP GSO-able run in `packets`: a
/// maximal slice with one destination and one segment size, plus optionally
/// the packet right after it if it is strictly smaller (the kernel allows the
/// last segment of a `UDP_SEGMENT` send to be shorter than `gso_size`).
fn gso_run_end(packets: &[(Packet, SocketAddr)]) -> usize {
    let (first_packet, first_addr) = &packets[0];
    let gso_size = first_packet.len();
    // A segment size that cannot be expressed in UDP_SEGMENT's u16, that alone
    // busts the single-IP-packet budget, or that is too small to be worth
    // segmenting in the kernel, cannot be GSO'd.
    if gso_size < MIN_GSO_SEGMENT_BYTES
        || gso_size as u64 > u16::MAX as u64
        || gso_size > MAX_GSO_BYTES
    {
        return 1;
    }
    let mut total = gso_size;
    let mut end = 1;
    while end < packets.len() {
        let (packet, addr) = &packets[end];
        if *addr != *first_addr
            || packet.len() != gso_size
            || total + gso_size > MAX_GSO_BYTES
        {
            break;
        }
        total += gso_size;
        end += 1;
    }
    // The kernel allows a single trailing segment smaller than `gso_size`.
    if end < packets.len() {
        let (packet, addr) = &packets[end];
        if *addr == *first_addr && packet.len() < gso_size {
            end += 1;
        }
    }
    end
}

/// Errors that mean the platform (or egress route) rejected UDP GSO, so the
/// whole mechanism is unusable rather than this particular send being wrong.
fn is_gso_unsupported(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EIO) | Some(libc::EINVAL))
}

impl super::UdpSocket {
    /// Send `run` (same-size packets to one destination, except possibly a
    /// shorter last one) as a single `sendmsg` with `UDP_SEGMENT`: the kernel
    /// splits the total buffer into `gso_size`-sized datagrams, which is one
    /// skb instead of `run.len()` on the egress path.
    async fn send_gso_run(
        socket: &tokio::net::UdpSocket,
        fd: std::os::fd::RawFd,
        run: &[(Packet, SocketAddr)],
    ) -> io::Result<()> {
        debug_assert!(run.len() >= 2);
        let gso_size = run[0].0.len();
        debug_assert!(gso_size > 0, "empty datagrams cannot be GSO'd");
        let addr = SockaddrStorage::from(run[0].1);

        // The stack array must cover the whole run: `check_send_max_number_of_packets`
        // caps a batch at MAX_PACKET_COUNT packets, so this cannot overflow.
        let mut packets_buf = [IoSlice::new(&[]); MAX_PACKET_COUNT];
        for (slot, (packet, _)) in packets_buf.iter_mut().zip(run.iter()) {
            *slot = IoSlice::new(&packet[..]);
        }
        let pkts = &packets_buf[..run.len()];

        socket
            .async_io(Interest::WRITABLE, || {
                nix::sys::socket::sendmsg::<SockaddrStorage>(
                    fd,
                    pkts,
                    &[nix::sys::socket::ControlMessage::UdpGsoSegments(
                        &(gso_size as u16),
                    )],
                    MsgFlags::MSG_DONTWAIT,
                    Some(&addr),
                )
                .map_err(io::Error::from)
            })
            .await?;
        Ok(())
    }

    /// Send `run` with `sendmmsg`, looping over partial progress. This is the
    /// pre-GSO implementation, now scoped to one run.
    async fn send_run_sendmmsg(
        socket: &tokio::net::UdpSocket,
        fd: std::os::fd::RawFd,
        buf: &mut SendmmsgBuf,
        run: &[(Packet, SocketAddr)],
    ) -> io::Result<()> {
        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        buf.targets.clear();
        for ((packet, target), packets_buf) in run.iter().zip(&mut packets_buf) {
            buf.targets.push(Some(SockaddrStorage::from(*target)));
            *packets_buf = [IoSlice::new(&packet[..])];
        }

        let len = buf.targets.len();
        let pkts = &packets_buf[..len];
        let mut packet_buf_start = 0;
        while packet_buf_start < len {
            let result = socket
                .async_io(Interest::WRITABLE, || {
                    let mut multiheaders =
                        MultiHeaders::preallocate(pkts[packet_buf_start..].len(), None);
                    let multiresult = nix::sys::socket::sendmmsg(
                        fd,
                        &mut multiheaders,
                        &pkts[packet_buf_start..],
                        &buf.targets[packet_buf_start..],
                        [],
                        MsgFlags::MSG_DONTWAIT,
                    )?;
                    let n = multiresult.count();
                    Ok(n)
                })
                .await;
            let n = result?;
            packet_buf_start += n;
        }
        debug_assert!(packet_buf_start == len, "all packets should be sent");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod gro {
    /// Number of segments per message received
    const MAX_SEGMENTS: usize = 64;
    /// Size of a single UDP packet with multiple segments
    // TODO: Fix constant
    const MAX_GRO_SIZE: usize = MAX_SEGMENTS * 4096;

    use super::MAX_PACKET_COUNT;
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::socket::map_src_addr;
    use crate::udp::{UdpRecv, socket::UdpSocket};
    use bytes::BytesMut;
    use nix::cmsg_space;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrStorage};
    use std::hint::cold_path;
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    pub struct RecvManyBuf {
        pub(crate) gro_bufs: Box<[BytesMut; MAX_PACKET_COUNT]>,
    }

    impl Default for RecvManyBuf {
        fn default() -> Self {
            let mut gro_buf = BytesMut::zeroed(MAX_PACKET_COUNT * MAX_GRO_SIZE);
            let gro_bufs = [(); MAX_PACKET_COUNT];
            let gro_bufs = gro_bufs.map(|()| gro_buf.split_to(MAX_GRO_SIZE));
            let gro_bufs = Box::new(gro_bufs);

            Self { gro_bufs }
        }
    }

    impl UdpRecv for UdpSocket {
        type RecvManyBuf = RecvManyBuf;

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.socket().recv_from(&mut buf).await?;
            buf.truncate(n);
            let src = self.map_src(src);
            Ok((buf, src))
        }

        async fn recv_many_from(
            &mut self,
            recv_many_bufs: &mut Self::RecvManyBuf,
            pool: &mut PacketBufPool,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            let socket = self.socket();
            let fd = socket.as_raw_fd();
            let map_ipv4_to_ipv6 = self.map_ipv4_to_ipv6;

            socket
                .async_io(Interest::READABLE, move || {
                    // TODO: the CMSG space cannot be reused, so we must allocate new headers each
                    // time [ControlMessageOwned::UdpGroSegments(i32)] contains
                    // the size of all smaller packets/segments
                    // Use a generic sockaddr storage here because this path serves both the IPv4
                    // and IPv6 UDP sockets. Using `SockaddrIn` corrupts IPv6 source addresses and
                    // can poison the peer runtime endpoint with an unspecified IPv4 address.
                    let headers = &mut MultiHeaders::<SockaddrStorage>::preallocate(
                        MAX_PACKET_COUNT,
                        Some(cmsg_space!(i32)),
                    );

                    let mut io_slices: [[IoSliceMut; 1]; MAX_PACKET_COUNT] =
                        std::array::from_fn(|_| [IoSliceMut::new(&mut [])]);

                    for (i, buf) in recv_many_bufs.gro_bufs.iter_mut().enumerate() {
                        io_slices[i] = [IoSliceMut::new(&mut buf[..])];
                    }

                    let results = nix::sys::socket::recvmmsg(
                        fd,
                        headers,
                        &mut io_slices[..MAX_PACKET_COUNT],
                        MsgFlags::MSG_DONTWAIT,
                        None,
                    )?;

                    for result in results {
                        let Some(iov) = result.iovs().next() else {
                            cold_path();
                            if cfg!(debug_assertions) {
                                tracing::trace!("Received empty datagram from IoSlice");
                            }
                            continue;
                        };

                        let Some(source_addr) = result.address.as_ref().and_then(|addr| {
                            addr.as_sockaddr_in()
                                .map(|&addr| SocketAddr::from(addr))
                                .or_else(|| addr.as_sockaddr_in6().map(|addr| (*addr).into()))
                        }) else {
                            if cfg!(debug_assertions) {
                                tracing::debug!("recvmmsg returned packet without source");
                            }
                            continue;
                        };

                        let source_addr = map_src_addr(map_ipv4_to_ipv6, source_addr);

                        // TODO: is this true? Under what circumstance can the cmsg buffer overflow?
                        let mut cmsgs = result.cmsgs().expect("we have allocated enough memory");

                        let gro_size = cmsgs
                            .find_map(|cmsg| match cmsg {
                                ControlMessageOwned::UdpGroSegments(gro_size) => Some(gro_size),
                                _ => None,
                            })
                            .and_then(|gro_size| usize::try_from(gro_size).ok())
                            .filter(|&gro_size| gro_size > 0);

                        // Generic Receive Offload
                        if let Some(gro_size) = gro_size {
                            // Divide packet into GRO-sized segments and copy them into Packet bufs
                            for gro_segment in iov.chunks(gro_size) {
                                let mut buf = pool.get();
                                // Copy the segment into a packet buffer, growing the buffer if the
                                // segment is larger than the pool's buffer size.
                                // TODO: consider splitting the iov backing buffer into multiple
                                // BytesMut to avoid copying the data here.
                                buf.buf_mut().clear();
                                buf.buf_mut().extend_from_slice(gro_segment);
                                packets.push((buf, source_addr));
                            }
                        } else {
                            // Single packet
                            let size = result.bytes;
                            let mut buf = pool.get();
                            // Copy the datagram into a packet buffer, growing the buffer if the
                            // datagram is larger than the pool's buffer size (reachable via IP
                            // fragment reassembly, up to 64k).
                            buf.buf_mut().clear();
                            buf.buf_mut().extend_from_slice(&iov[..size]);
                            packets.push((buf, source_addr));
                        }
                    }

                    Ok(())
                })
                .await?;

            Ok(())
        }

        fn enable_udp_gro(&self) -> io::Result<()> {
            // TODO: missing constants on Android
            use std::os::fd::AsFd;
            nix::sys::socket::setsockopt(
                &self.as_fd(),
                nix::sys::socket::sockopt::UdpGroSegment,
                &true,
            )?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::UdpSocket;
        use crate::packet::{Packet, PacketBufPool};
        use crate::udp::socket::SockOpt;
        use crate::udp::{UdpRecv, UdpSend};
        use std::net::{Ipv6Addr, SocketAddr};
        use std::time::Duration;

        #[tokio::test]
        async fn recv_many_from_preserves_ipv6_source_addr() {
            let mut receiver =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
            receiver.enable_udp_gro().ok();
            let sender =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();

            let recv_addr = receiver.local_addr().unwrap();
            let sender_addr = sender.local_addr().unwrap();

            let send_pool = PacketBufPool::<4096>::new(1);
            let mut packet = send_pool.get();
            packet.truncate(5);
            packet.copy_from_slice(b"hello");
            sender.send_to(packet, recv_addr).await.unwrap();

            let mut recv_pool = PacketBufPool::<4096>::new(1);
            let mut recv_many_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
            let mut packets = vec![];

            tokio::time::timeout(
                Duration::from_secs(1),
                receiver.recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packets),
            )
            .await
            .unwrap()
            .unwrap();

            assert!(!packets.is_empty(), "expected at least one IPv6 packet");
            assert_eq!(packets[0].1, sender_addr);
        }

        // A datagram larger than the pool buffer must be received in full by growing
        // the target buffer, not dropped or truncated.
        //
        // Note: a single datagram is not GRO-coalesced, so this exercises the non-GRO
        // receive branch. The GRO branch (segments larger than the buffer) is not
        // covered here - UDP GRO does not engage on loopback.
        #[tokio::test]
        async fn recv_many_from_grows_for_oversized_datagram() {
            let mut receiver =
                UdpSocket::bind((Ipv6Addr::LOCALHOST, 0).into(), SockOpt::default()).unwrap();
            receiver.enable_udp_gro().ok();
            let recv_addr = receiver.local_addr().unwrap();

            // 10000 bytes is larger than the 4096-byte pool buffer.
            let payload = vec![0xABu8; 10_000];
            let sender = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
            sender.send_to(&payload, recv_addr).unwrap();

            let mut recv_pool = PacketBufPool::<4096>::new(1);
            let mut recv_many_buf = <UdpSocket as UdpRecv>::RecvManyBuf::default();
            let mut packets: Vec<(Packet, SocketAddr)> = Vec::new();

            // The datagram is already buffered, so a single read returns it.
            tokio::time::timeout(
                Duration::from_secs(1),
                receiver.recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packets),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(packets.len(), 1, "expected exactly one packet");
            let (packet, _) = &packets[0];
            assert_eq!(
                packet.len(),
                payload.len(),
                "oversized datagram must be received in full, not dropped or truncated"
            );
            assert_eq!(
                &packet[..],
                &payload[..],
                "datagram must retain same content"
            );
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::UdpRecv;
    use std::io;
    use std::net::SocketAddr;

    impl UdpRecv for super::UdpSocket {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.socket().recv_from(&mut buf).await?;
            buf.truncate(n);
            let src = self.map_src(src);
            Ok((buf, src))
        }
    }
}

#[cfg(test)]
mod gso_tests {
    use super::*;
    use crate::packet::PacketBufPool;
    use crate::udp::UdpRecv;
    use std::time::Duration;
    use tokio::time::timeout;

    /// send_many_to must deliver, as individual datagrams with intact
    /// payloads and order, a batch of same-size packets to one destination
    /// followed by one shorter packet - exactly the shape a WireGuard burst
    /// has. On platforms with UDP GSO this exercises the UDP_SEGMENT path,
    /// elsewhere the sendmmsg fallback.
    #[tokio::test]
    async fn send_many_to_with_trailing_short_packet() {
        let sender = super::super::UdpSocket::bind(
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            crate::udp::socket::SockOpt::default(),
        )
        .unwrap();
        let mut receiver = super::super::UdpSocket::bind(
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            crate::udp::socket::SockOpt::default(),
        )
        .unwrap();
        let dst = receiver.local_addr().unwrap();

        let mut packets = Vec::new();
        for i in 0..5u8 {
            let mut b = bytes::BytesMut::zeroed(1400);
            b[0] = i;
            packets.push((Packet::from_bytes(b), dst));
        }
        let mut short = bytes::BytesMut::zeroed(100);
        short[0] = 200;
        packets.push((Packet::from_bytes(short), dst));
        for i in 6..8u8 {
            let mut b = bytes::BytesMut::zeroed(1400);
            b[0] = i;
            packets.push((Packet::from_bytes(b), dst));
        }

        let mut buf = Default::default();
        timeout(Duration::from_secs(10), sender.send_many_to(&mut buf, &mut packets))
            .await
            .expect("send completes")
            .unwrap();
        assert!(packets.is_empty(), "send_many_to must consume the batch");

        // 5x1400 + trailing 100 forms one GSO run, then a second run of 2x1400
        // starts after the size break: multiple runs in one call.
        let mut pool = PacketBufPool::new(8);
        for i in 0..8u8 {
            let (packet, src) = timeout(Duration::from_secs(10), receiver.recv_from(&mut pool))
                .await
                .expect("datagram arrives")
                .unwrap();
            assert_eq!(src, sender.local_addr().unwrap());
            let (expected_len, expected_first) = if i == 5 { (100, 200) } else { (1400, i) };
            assert_eq!(packet.len(), expected_len, "datagram {i} must be one segment");
            assert_eq!(packet[0], expected_first, "datagram {i} must keep its payload and order");
        }
    }
}

#[cfg(test)]
mod gso_tests_dualstack {
    use super::*;
    use crate::packet::PacketBufPool;
    use crate::udp::UdpRecv;
    use crate::udp::socket::UdpSocketFactory;
    use crate::udp::{UdpSend, UdpTransportFactory};
    use std::time::Duration;
    use tokio::time::timeout;

    /// Same as gso_tests::send_many_to_with_trailing_short_packet but with the
    /// production socket setup: factory-bound dual-stack (IPv6) socket with
    /// UDP GRO enabled, sending to an IPv4 destination.
    #[tokio::test]
    async fn send_many_to_gso_dual_stack_socket_to_v4() {
        let mut factory = UdpSocketFactory::default();
        let params = crate::udp::UdpTransportFactoryParams {
            addr: None,
            port: 0,
            fwmark: None,
        };
        let (sender, _) = factory.bind(&params).await.unwrap();
        let dst = (std::net::Ipv4Addr::LOCALHOST, 0u16).into();
        let mut receiver = super::super::UdpSocket::bind(dst, crate::udp::socket::SockOpt::default()).unwrap();
        let dst = receiver.local_addr().unwrap();

        let mut packets = Vec::new();
        for i in 0..5u8 {
            let mut b = bytes::BytesMut::zeroed(1400);
            b[0] = i;
            packets.push((Packet::from_bytes(b), dst));
        }

        let mut buf = Default::default();
        timeout(Duration::from_secs(10), sender.send_many_to(&mut buf, &mut packets))
            .await
            .expect("send completes (may fall back to sendmmsg, but must not hang)")
            .unwrap();

        let mut pool = PacketBufPool::new(8);
        for i in 0..5u8 {
            let (packet, _) = timeout(Duration::from_secs(10), receiver.recv_from(&mut pool))
                .await
                .expect("datagram arrives")
                .unwrap();
            assert_eq!(packet.len(), 1400);
            assert_eq!(packet[0], i);
        }
    }
}
