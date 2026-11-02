// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Linux UDP batching. Buffer/iovec/header allocations stay fixed while the kernel uses them.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::UdpSocket,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

pub fn receive_buffer(socket: &UdpSocket) -> Result<usize> {
    let desired: libc::c_int = 8 * 1024 * 1024;
    let len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: fd is live; both option pointers have the declared initialized sizes.
    unsafe {
        ensure!(
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&desired as *const libc::c_int).cast(),
                len
            ) == 0,
            "SO_RCVBUF: {}",
            io::Error::last_os_error()
        );
    }
    actual_receive_buffer(socket)
}

pub fn actual_receive_buffer(socket: &UdpSocket) -> Result<usize> {
    let mut actual: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the socket is live and the option pointers have the declared sizes.
    unsafe {
        ensure!(
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&mut actual as *mut libc::c_int).cast(),
                &mut len
            ) == 0,
            "getsockopt: {}",
            io::Error::last_os_error()
        );
    }
    Ok(actual as usize)
}

/// The kernel only changes lengths/flags in headers. No pointers escape this owner.
pub struct ReceiveBatch {
    storage: Vec<u8>,
    _iov: Vec<libc::iovec>,
    headers: Vec<libc::mmsghdr>,
    stride: usize,
}

impl ReceiveBatch {
    pub fn new(count: usize, stride: usize) -> Self {
        let mut storage = vec![0; count * stride];
        let mut iov: Vec<_> = storage
            .chunks_exact_mut(stride)
            .map(|chunk| libc::iovec {
                iov_base: chunk.as_mut_ptr().cast(),
                iov_len: chunk.len(),
            })
            .collect();
        let headers = iov
            .iter_mut()
            .map(|iov| {
                // SAFETY: null name/control and zero flags/lengths are valid msghdr defaults.
                let mut header: libc::mmsghdr = unsafe { std::mem::zeroed() };
                header.msg_hdr.msg_iov = iov;
                header.msg_hdr.msg_iovlen = 1;
                header
            })
            .collect();
        Self {
            storage,
            _iov: iov,
            headers,
            stride,
        }
    }

    pub fn receive(&mut self, socket: &UdpSocket, mut packet: impl FnMut(&[u8])) -> Result<()> {
        for header in &mut self.headers {
            header.msg_hdr.msg_flags = 0;
        }
        // SAFETY: all headers, iovecs and uniquely disjoint writable buffers are live and
        // stable for this synchronous call. MSG_WAITFORONE avoids waiting to fill a batch;
        // SO_RCVTIMEO bounds waiting for its first packet (not recvmmsg's buggy timeout).
        let count = unsafe {
            libc::recvmmsg(
                socket.as_raw_fd(),
                self.headers.as_mut_ptr(),
                self.headers.len() as u32,
                libc::MSG_WAITFORONE,
                std::ptr::null_mut(),
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ) {
                return Ok(());
            }
            return Err(error).context("recvmmsg");
        }
        for (i, header) in self.headers[..count as usize].iter().enumerate() {
            ensure!(
                header.msg_hdr.msg_flags & libc::MSG_TRUNC == 0,
                "received a truncated datagram"
            );
            let length = header.msg_len as usize;
            ensure!(length <= self.stride, "invalid received length");
            packet(&self.storage[i * self.stride..i * self.stride + length]);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendReport {
    pub packets: usize,
    pub datagram_bytes: usize,
    pub prepare_seconds: f64,
    pub send_seconds: f64,
    pub offered_payload_gbps: f64,
    pub syscalls: usize,
    pub partial_sends: usize,
}

pub fn send(
    socket: &UdpSocket,
    pool: &crate::packets::Pool,
    payload: usize,
    batch: usize,
    gbps: f64,
) -> Result<SendReport> {
    send_cancellable(socket, pool, payload, batch, gbps, None)
}

pub fn send_cancellable(
    socket: &UdpSocket,
    pool: &crate::packets::Pool,
    payload: usize,
    batch: usize,
    gbps: f64,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> Result<SendReport> {
    let count = pool.bytes.len() / pool.stride;
    let mut iov = vec![
        libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: pool.stride
        };
        batch
    ];
    // SAFETY: zero/null fields are valid defaults. They are populated before use.
    let mut headers = vec![unsafe { std::mem::zeroed::<libc::mmsghdr>() }; batch];
    let mut sent = 0;
    let mut syscalls = 0;
    let mut partial_sends = 0;
    let started = Instant::now();
    while sent < count {
        ensure!(
            !stop.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)),
            "generator cancelled"
        );
        ensure!(
            started.elapsed() < Duration::from_secs(60),
            "packet train exceeded 60 seconds"
        );
        if gbps > 0.0 {
            let deadline = started
                + Duration::from_secs_f64(sent as f64 * payload as f64 * 8.0 / (gbps * 1e9));
            // Only Bob spins; Alice's measured process uses its normal scheduling.
            while Instant::now() < deadline {
                ensure!(
                    !stop.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)),
                    "generator cancelled"
                );
                std::hint::spin_loop();
            }
        }
        let n = batch.min(count - sent);
        for i in 0..n {
            iov[i].iov_base = pool.bytes[(sent + i) * pool.stride..]
                .as_ptr()
                .cast_mut()
                .cast();
            headers[i].msg_hdr.msg_iov = &mut iov[i];
            headers[i].msg_hdr.msg_iovlen = 1;
        }
        // SAFETY: these live, stable headers reference read-only packet slices. sendmmsg
        // does not modify the buffers; the mutable pointer is required by C's iovec ABI.
        let result =
            unsafe { libc::sendmmsg(socket.as_raw_fd(), headers.as_mut_ptr(), n as u32, 0) };
        syscalls += 1;
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("sendmmsg");
        }
        ensure!(result > 0, "sendmmsg made no progress");
        if (result as usize) < n {
            partial_sends += 1;
        }
        for header in &headers[..result as usize] {
            ensure!(header.msg_len as usize == pool.stride, "short UDP send");
        }
        sent += result as usize;
    }
    let send_seconds = started.elapsed().as_secs_f64();
    Ok(SendReport {
        packets: sent,
        datagram_bytes: pool.stride,
        prepare_seconds: pool.prepare_seconds,
        send_seconds,
        offered_payload_gbps: sent as f64 * payload as f64 * 8.0 / send_seconds / 1e9,
        syscalls,
        partial_sends,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batched_datagrams_preserve_boundaries_and_final_short_batch() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        receive_buffer(&rx).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        let pool = crate::packets::prepare(None, 129, 64, 1234).unwrap();
        let report = send(&tx, &pool, 64, 64, 0.0).unwrap();
        assert_eq!(report.packets, 129);
        let mut receiver = ReceiveBatch::new(64, 2048);
        let mut sequences = Vec::new();
        while sequences.len() < 129 {
            receiver
                .receive(&rx, |data| {
                    assert_eq!(data.len(), pool.stride);
                    sequences.push(u64::from_le_bytes(data[8..16].try_into().unwrap()));
                })
                .unwrap();
        }
        assert_eq!(sequences, (0..129).collect::<Vec<_>>());
    }
}
