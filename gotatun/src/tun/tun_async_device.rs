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

//! Implementations of [`IpSend`] and [`IpRecv`] for the [`tun`] crate.

use tokio::{sync::watch, time::sleep};
use tun::AbstractDevice;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend, MtuWatcher},
};

use std::{convert::Infallible, io, iter, sync::Arc, time::Duration};

#[cfg(target_os = "linux")]
use crate::tun::offload;

/// Error from [`TunDevice`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to open TUN device
    #[error("Failed to open TUN device: {0}")]
    OpenTun(#[source] tun::Error),

    /// Failed to get TUN device name
    #[error("Failed to get TUN device name: {0}")]
    GetTunName(#[source] tun::Error),

    /// Unsupported TUN feature
    #[error("Unsupported TUN feature: {0}")]
    UnsupportedFeature(String),

    /// Failed to get TUN device MTU
    #[error("Failed to get TUN device MTU: {0}")]
    GetMtu(#[source] tun::Error),
}

/// A kernel virtual network device; a TUN device.
///
/// Implements [`IpSend`] and [`IpRecv`]. On Linux, the TUN is opened with
/// `IFF_VNET_HDR` and TUN offloads enabled (see [`offload`]): reads yield
/// TCP superpackets that are split into MTU-sized segments, and writes
/// coalesce received segments back into superpackets.
#[derive(Clone)]
pub struct TunDevice {
    tun: Arc<tun::AsyncDevice>,
    state: Arc<TunDeviceState>,
    #[cfg(target_os = "linux")]
    vnet: Arc<VnetState>,
}

struct TunDeviceState {
    mtu: MtuWatcher,

    /// Task which monitors TUN device MTU. Aborted when dropped.
    _mtu_monitor: Task,
}

/// Linux-only state for vnet-hdr framing, TSO splitting and GRO coalescing.
/// Guarded by tokio mutexes because the exclusive [`IpRecv`]/[`IpSend`]
/// methods are async.
#[cfg(target_os = "linux")]
struct VnetState {
    /// The TUN fd was opened with `IFF_VNET_HDR`.
    enabled: bool,
    /// `TUNSETOFFLOAD` succeeded, so the kernel produces/consumes
    /// superpackets; without it we still parse/emit plain headers.
    offloads: bool,
    /// Scratch buffer for one TUN read (vnet header + one superpacket).
    read_buf: tokio::sync::Mutex<Vec<u8>>,
    /// Coalescing state for TUN writes.
    gro: tokio::sync::Mutex<offload::GroBuffer>,
    /// Duplicated TUN fd for vectored writes, which the `tun` crate's async
    /// API does not expose. Readiness and buffering are shared with the
    /// original fd. `None` (only when offloads are off entirely) means writes
    /// go through the `tun` crate's single-buffer API.
    write_fd: Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
}

/// Maximum frame we can read from the TUN: virtio header + a 64 kB
/// superpacket.
#[cfg(target_os = "linux")]
const MAX_TUN_READ: usize = offload::VNET_HDR_LEN + 65_535;

/// Byte bound on the TSO superpackets the local TCP stack enqueues for TUN
/// fd reads, applied as the TUN device's `gso_max_size`.
///
/// The device-side queue feeding TUN fd reads is bounded in *packets*
/// (default 500), not bytes, so with TSO every slot can hold a superpacket
/// of up to the GSO limit, 64 KiB: a byte-depth of ~32 MiB. When the single
/// user-space reader task is the tunnel's bottleneck, a fast local sender
/// can leave a standing multi-megabyte queue in front of latency-sensitive
/// packets, adding tens of milliseconds under load (measured: ping p99
/// 6.4 -> 35 ms at 64 KiB packets). Capping superpackets at 8 KiB (~5
/// segments) bounds the queue to ~4 MiB while still reading an order of
/// magnitude fewer, and larger, frames than MTU-sized reads.
///
/// The packet-count bound is deliberately left at the kernel default: the
/// queue is the only burst absorber between the network stack and the
/// single reader task, and shrinking it to bound bytes drops whole bursts
/// of small packets instead (a stop-and-wait UDP transfer collapses when
/// roughly a window of 256 datagrams is dropped per retransmit round).
#[cfg(target_os = "linux")]
const TUN_OFFLOAD_GSO_MAX_SIZE: libc::c_uint = 8 * 1024;

/// Set the interface's GSO superpacket size limit, bounding the byte backlog
/// that can wait for TUN fd reads behind the packet-count-bounded device
/// queue.
///
/// Uses rtnetlink (`RTM_NEWLINK` with `IFLA_GSO_MAX_SIZE`): the equivalent
/// `SIOCSIFTXQLEN`-style ioctls require privileges over the initial user
/// namespace, while netlink accepts `CAP_NET_ADMIN` in the network
/// namespace's own user namespace, which is what an unprivileged-namespace
/// environment has.
#[cfg(target_os = "linux")]
fn set_gso_max_size(name: &str, gso_max_size: libc::c_uint) -> io::Result<()> {
    /// `RTM_NEWLINK`: change one interface's attributes.
    const RTM_NEWLINK: u16 = 16;
    /// `NLM_F_REQUEST | NLM_F_ACK`: a request that must be answered.
    const NLM_F_REQUEST_ACK: u16 = 0x01 | 0x04;
    /// `NLMSG_ERROR`: the reply kind carrying an ack or an error code.
    const NLMSG_ERROR: u16 = 0x02;
    /// `IFLA_GSO_MAX_SIZE`: attribute carrying the max GSO packet size.
    const IFLA_GSO_MAX_SIZE: u16 = 41;

    /// One `rtattr` with a `u32` payload.
    #[repr(C)]
    struct AttrU32 {
        rta_len: libc::c_ushort,
        rta_type: libc::c_ushort,
        payload: libc::c_uint,
    }

    impl AttrU32 {
        const SIZE: libc::c_ushort = 8; // rtattr header + u32 payload
        fn new(rta_type: u16, payload: libc::c_uint) -> Self {
            Self {
                rta_len: Self::SIZE,
                rta_type,
                payload,
            }
        }
    }

    /// `struct ifinfomsg` followed by one `u32` attribute.
    #[repr(C)]
    struct LinkMsg {
        ifi_family: libc::c_uchar,
        _ifi_pad: libc::c_uchar,
        /// 0: `do_setlink` selects the interface by index, not by type.
        ifi_type: libc::c_ushort,
        ifi_index: libc::c_int,
        ifi_flags: libc::c_uint,
        ifi_change: libc::c_uint,
        gso_max_size: AttrU32,
    }

    /// One netlink message: header plus body.
    #[repr(C)]
    struct SetLinkMsg {
        nlh: libc::nlmsghdr,
        body: LinkMsg,
    }

    const _: () = assert!(
        std::mem::size_of::<libc::nlmsghdr>() == 16
            && std::mem::size_of::<LinkMsg>() == 24
            && std::mem::size_of::<SetLinkMsg>() == 40
    );

    let cname = std::ffi::CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name not C-compatible",
        )
    })?;
    // SAFETY: `cname` is a valid NUL-terminated string for the duration of
    // the call, and `if_nametoindex` only reads it.
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name} not found"),
        ));
    }

    let msg = SetLinkMsg {
        nlh: libc::nlmsghdr {
            nlmsg_len: std::mem::size_of::<SetLinkMsg>() as u32,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: NLM_F_REQUEST_ACK,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        body: LinkMsg {
            ifi_family: libc::AF_UNSPEC as libc::c_uchar,
            _ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex as libc::c_int,
            ifi_flags: 0,
            ifi_change: 0,
            gso_max_size: AttrU32::new(IFLA_GSO_MAX_SIZE, gso_max_size),
        },
    };

    // SAFETY: `fd` is either -1 or a freshly created netlink socket that
    // this function closes before returning, and the only message that can
    // arrive on it is the kernel's reply to the one we send. `send` reads
    // only the initialized bytes of `msg`; `recv` writes into `reply`.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut ret = Ok(());
        let sent = libc::send(
            fd,
            &raw const msg as *const libc::c_void,
            std::mem::size_of::<SetLinkMsg>(),
            0,
        );
        let received = if sent < 0 {
            None
        } else {
            let mut reply = [0u8; 4096];
            match libc::recv(fd, reply.as_mut_ptr() as *mut libc::c_void, reply.len(), 0) {
                n if n >= 0 => Some((n as usize, reply)),
                _ => None,
            }
        };
        // Expect exactly one NLMSG_ERROR: error == 0 means "acknowledged".
        match received {
            Some((n, reply))
                if n >= std::mem::size_of::<libc::nlmsghdr>()
                    + std::mem::size_of::<libc::c_int>()
                    && u16::from_ne_bytes([reply[4], reply[5]]) == NLMSG_ERROR =>
            {
                let error = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
                if error != 0 {
                    ret = Err(io::Error::from_raw_os_error(-error));
                }
            }
            _ => {
                ret = Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no netlink ack",
                ))
            }
        }
        libc::close(fd);
        ret
    }
}

/// Build the vnet-hdr state for a freshly-created TUN: probe TUNSETOFFLOAD
/// (which only succeeds on an `IFF_VNET_HDR` fd), and duplicate the fd for
/// vectored writes. Any failure disables offloads but keeps plain framing.
#[cfg(target_os = "linux")]
fn new_vnet_state(tun: &tun::AsyncDevice) -> io::Result<VnetState> {
    use std::os::fd::{AsRawFd, BorrowedFd};

    let fd = tun.as_raw_fd();
    let offloads = offload::set_offloads(fd).is_ok();
    if !offloads {
        tracing::warn!("TUNSETOFFLOAD failed; TUN offloads disabled");
    }
    // SAFETY: the descriptor is owned by `tun` and outlives this borrow.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let owned = nix::unistd::dup(borrowed).map_err(io::Error::from)?;
    let write_fd = tokio::io::unix::AsyncFd::new(owned).map_err(io::Error::other)?;
    Ok(VnetState {
        enabled: true,
        offloads,
        read_buf: tokio::sync::Mutex::new(vec![0; MAX_TUN_READ]),
        gro: tokio::sync::Mutex::new(offload::GroBuffer::default()),
        write_fd: Some(write_fd),
    })
}

#[cfg(target_os = "linux")]
impl VnetState {
    /// State for a TUN we could not prepare vnet framing for at all.
    fn plain() -> Self {
        Self {
            enabled: false,
            offloads: false,
            read_buf: tokio::sync::Mutex::new(Vec::new()),
            gro: tokio::sync::Mutex::new(offload::GroBuffer::default()),
            write_fd: None,
        }
    }
}

impl TunDevice {
    /// Construct from a name.
    ///
    /// # Warning
    ///
    /// If this is used on Windows, you are recommended to enable the `verify_binary_signature`
    /// feature for the `tun` crate. By default, `tun` will load `wintun.dll` using the
    /// [default search order], which includes the `PATH` environment variable.
    ///
    /// [default search order]: <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
    pub fn from_name(name: &str) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        if cfg!(not(target_os = "macos")) || name != "utun" {
            // If the name is 'utun', automatically assign a name
            tun_config.tun_name(name);
        }
        #[cfg(target_os = "macos")]
        tun_config.platform_config(|p| {
            p.enable_routing(false);
        });
        #[cfg(target_os = "linux")]
        tun_config.platform_config(|p| {
            p.vnet_hdr(true);
        });
        // TODO: for wintun, must set path or enable signature check
        let tun = match tun::create_as_async(&tun_config) {
            Ok(tun) => tun,
            #[cfg(target_os = "linux")]
            Err(e) => {
                // An old kernel, or a sandbox that rejects IFF_VNET_HDR: fall
                // back to the plain fd. Offloads are simply off.
                tracing::warn!("Failed to open TUN with IFF_VNET_HDR ({e}); continuing without");
                let mut plain = tun::Configuration::default();
                plain.tun_name(name);
                tun::create_as_async(&plain).map_err(Error::OpenTun)?
            }
            #[cfg(not(target_os = "linux"))]
            Err(e) => return Err(Error::OpenTun(e)),
        };
        let tun = TunDevice::from_tun_device(tun)?;
        Ok(tun)
    }

    /// Construct from a name with an explicit path to `wintun.dll`.
    ///
    /// Use this on Windows when `wintun.dll` is not on `PATH` or in the executable directory.
    #[cfg(windows)]
    pub fn from_name_with_wintun_path(
        name: &str,
        wintun_path: &std::path::Path,
    ) -> Result<Self, Error> {
        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(name);
        tun_config.platform_config(|p| {
            p.wintun_file(wintun_path);
        });
        let tun = tun::create_as_async(&tun_config).map_err(Error::OpenTun)?;
        TunDevice::from_tun_device(tun)
    }

    /// Construct from a [`tun::AsyncDevice`].
    pub fn from_tun_device(tun: tun::AsyncDevice) -> Result<Self, Error> {
        #[cfg(target_os = "linux")]
        if tun.packet_information() {
            return Err(Error::UnsupportedFeature("packet_information".to_string()));
        }

        let mtu = tun.mtu().map_err(Error::GetMtu)?;
        let (tx, rx) = watch::channel(mtu);

        let tun = Arc::new(tun);
        let tun_weak = Arc::downgrade(&tun);

        // Poll for changes to the MTU of the TUN device.
        // TODO: use the OS-specific event-driven patterns that exist instead of polling
        let watch_task = async move || -> Option<Infallible> {
            let mut mtu = mtu;
            loop {
                sleep(Duration::from_secs(3)).await;
                let tun = tun_weak.upgrade()?;
                let new = tun.mtu().ok()?;
                if new != mtu {
                    mtu = new;
                    tx.send(mtu).ok()?;
                }
            }
        };

        let mtu_monitor = Task::spawn("tun_mtu_monitor", async move {
            watch_task().await;
        });

        #[cfg(target_os = "linux")]
        let vnet = {
            let state = new_vnet_state(&tun);
            match state {
                Ok(v) => {
                    if v.offloads {
                        // TSO makes each queued packet a superpacket; bound
                        // its size (see the constant above).
                        match tun.tun_name() {
                            Ok(name) => {
                                if let Err(e) = set_gso_max_size(&name, TUN_OFFLOAD_GSO_MAX_SIZE) {
                                    tracing::warn!(
                                        "failed to bound TUN GSO size ({e}); \
                                         latency under load may suffer"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("failed to get TUN name; not bounding tx queue: {e}")
                            }
                        }
                    }
                    v
                }
                Err(e) => {
                    tracing::warn!("Failed to enable TUN offloads ({e}); TSO/GRO disabled");
                    VnetState::plain()
                }
            }
        };

        let state = Arc::new(TunDeviceState {
            mtu: rx.into(),
            _mtu_monitor: mtu_monitor,
        });

        #[cfg(target_os = "linux")]
        return Ok(Self {
            tun,
            state,
            vnet: Arc::new(vnet),
        });

        #[cfg(not(target_os = "linux"))]
        Ok(Self { tun, state })
    }

    /// Get the name of the TUN device.
    pub fn name(&self) -> Result<String, Error> {
        self.tun.tun_name().map_err(Error::GetTunName)
    }
}

impl IpSend for TunDevice {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.send_batch(Some(packet).into_iter()).await
    }

    async fn send_batch(
        &mut self,
        packets: impl ExactSizeIterator<Item = Packet<Ip>> + Send,
    ) -> io::Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            for packet in packets {
                self.tun.send(&packet.into_bytes()).await?;
            }
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            if !self.vnet.enabled {
                for packet in packets {
                    self.tun.send(&packet.into_bytes()).await?;
                }
                return Ok(());
            }

            let write_fd = self
                .vnet
                .write_fd
                .as_ref()
                .expect("write fd exists whenever vnet framing is enabled");
            let mut gro = self.vnet.gro.lock().await;
            for packet in packets {
                let packet = packet.into_bytes();
                if self.vnet.offloads && gro.try_append(&packet) {
                    if gro.wants_flush() {
                        flush_gro(&mut gro, write_fd).await?;
                    }
                    continue;
                }
                flush_gro(&mut gro, write_fd).await?;
                if self.vnet.offloads && gro.try_append(&packet) {
                    // This packet started a fresh group.
                    continue;
                }
                let hdr = offload::VirtioNetHdr::plain().to_bytes();
                writev_vnet(write_fd, &hdr, &packet).await?;
            }
            flush_gro(&mut gro, write_fd).await?;
            Ok(())
        }
    }
}

/// Write out the pending GRO group, if any.
#[cfg(target_os = "linux")]
async fn flush_gro(
    gro: &mut offload::GroBuffer,
    fd: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
) -> io::Result<()> {
    if let Some((hdr, frame)) = gro.take() {
        writev_vnet(fd, &hdr.to_bytes(), &frame).await?;
    }
    Ok(())
}

/// Write `[header, frame]` to the TUN fd as one vectored write, waiting for
/// writability as needed.
#[cfg(target_os = "linux")]
async fn writev_vnet(
    aio: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    header: &[u8],
    frame: &[u8],
) -> io::Result<()> {
    use nix::sys::uio;

    debug_assert_eq!(header.len(), offload::VNET_HDR_LEN);
    let fd = aio.get_ref();
    let io_slices = [io::IoSlice::new(header), io::IoSlice::new(frame)];
    aio.async_io(tokio::io::Interest::WRITABLE, |_| {
        uio::writev(fd, &io_slices).map_err(io::Error::from)
    })
    .await?;
    Ok(())
}

impl IpRecv for TunDevice {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        #[cfg(not(target_os = "linux"))]
        {
            let mut packet = pool.get();
            let n = self.tun.recv(&mut packet).await?;
            packet.truncate(n);
            match packet.try_into_ip() {
                Ok(packet) => Ok(iter::once(packet)),
                Err(e) => Err(io::Error::other(e.to_string())),
            }
        }
        #[cfg(target_os = "linux")]
        {
            if !self.vnet.enabled {
                let mut packet = pool.get();
                let n = self.tun.recv(&mut packet).await?;
                packet.truncate(n);
                return Ok(PacketIter::Plain(match packet.try_into_ip() {
                    Ok(packet) => iter::once(packet),
                    Err(e) => return Err(io::Error::other(e.to_string())),
                }));
            }

            let mut read_buf = self.vnet.read_buf.lock().await;
            let n = self.tun.recv(&mut read_buf).await?;
            if n < offload::VNET_HDR_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TUN read shorter than a virtio_net_hdr",
                ));
            }
            let hdr = offload::VirtioNetHdr::parse(&read_buf[..n]).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unparsable virtio_net_hdr")
            })?;

            if self.vnet.offloads && hdr.gso_type & !0x80 != 0 {
                let frame = &mut read_buf[offload::VNET_HDR_LEN..n];
                let mut segments = Vec::new();
                match offload::split_gso(frame, &hdr, pool, &mut segments) {
                    Ok(_) => return Ok(PacketIter::Segments(segments, 0)),
                    Err(e) => {
                        tracing::warn!("failed to split TUN superpacket: {e}; dropping it");
                        return Ok(PacketIter::Segments(Vec::new(), 0));
                    }
                }
            }

            // Non-GSO frames may still carry an incomplete transport
            // checksum (NEEDS_CSUM): the kernel left it to us. Complete it in
            // place before the packet is encrypted and sent.
            if hdr.flags & 1 != 0 {
                let (start, off) = (hdr.csum_start as usize, hdr.csum_offset as usize);
                offload::complete_checksum(&mut read_buf[offload::VNET_HDR_LEN..n], start, off);
            }
            let frame = &read_buf[offload::VNET_HDR_LEN..n];
            let mut packet = pool.get();
            let bytes = packet.buf_mut();
            bytes.clear();
            bytes.extend_from_slice(frame);
            Ok(PacketIter::Plain(match packet.try_into_ip() {
                Ok(packet) => iter::once(packet),
                Err(e) => return Err(io::Error::other(e.to_string())),
            }))
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.state.mtu.clone()
    }
}

/// The iterator returned by [`TunDevice`]'s [`IpRecv`] impl: either one plain
/// packet, or the segments of one superpacket (in order).
#[cfg(target_os = "linux")]
enum PacketIter {
    Plain(iter::Once<Packet<Ip>>),
    Segments(Vec<Packet<[u8]>>, usize),
}

#[cfg(target_os = "linux")]
impl Iterator for PacketIter {
    type Item = Packet<Ip>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            PacketIter::Plain(iter) => iter.next(),
            // Advance an index: `Drain`/`IntoIter` would be fine too, but
            // this keeps the vec intact for the caller's lifetime pattern.
            PacketIter::Segments(vec, idx) => {
                if *idx >= vec.len() {
                    return None;
                }
                let packet = std::mem::take(&mut vec[*idx]);
                *idx += 1;
                packet.try_into_ip().map_err(|e| {
                    tracing::trace!("dropping invalid segmented packet: {e}");
                    e
                }).ok()
            }
        }
    }
}
