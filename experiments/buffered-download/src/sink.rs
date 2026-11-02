// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{batch, packets::MAGIC};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    net::{SocketAddrV4, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Default, Serialize)]
pub struct Stats {
    pub unique: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub receive_buffer_bytes: usize,
    pub kernel_socket_drops: u64,
    pub arrival_span_seconds: f64,
}

pub struct Sink {
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<Stats>>>,
}

impl Sink {
    pub fn start(bind: SocketAddrV4, count: usize, expected_len: usize) -> Result<Self> {
        let socket = UdpSocket::bind(bind).context("bind local payload receiver")?;
        let std::net::SocketAddr::V4(bind) = socket.local_addr()? else {
            unreachable!()
        };
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let receive_buffer_bytes = batch::receive_buffer(&socket)?;
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let thread = std::thread::spawn(move || {
            let mut stats = Stats {
                receive_buffer_bytes,
                ..Default::default()
            };
            let mut seen = vec![false; count];
            let mut receiver = batch::ReceiveBatch::new(64, 2048);
            let mut first = None;
            let mut last = Instant::now();
            let mut finish_started = None;
            loop {
                receiver.receive(&socket, |packet| {
                    let now = Instant::now();
                    last = now;
                    first.get_or_insert(now);
                    if packet.len() != expected_len || &packet[..8] != MAGIC {
                        stats.invalid += 1;
                        return;
                    }
                    let seq = u64::from_le_bytes(packet[8..16].try_into().unwrap());
                    let Some(entry) = usize::try_from(seq).ok().and_then(|seq| seen.get_mut(seq))
                    else {
                        stats.invalid += 1;
                        return;
                    };
                    if *entry {
                        stats.duplicates += 1;
                    } else {
                        *entry = true;
                        stats.unique += 1;
                    }
                })?;
                if stop.load(Ordering::Relaxed) {
                    let stop_at = finish_started.get_or_insert_with(Instant::now);
                    if last.elapsed() >= Duration::from_millis(200)
                        || stop_at.elapsed() >= Duration::from_secs(2)
                    {
                        break;
                    }
                }
            }
            stats.arrival_span_seconds = first
                .map(|first| last.duration_since(first).as_secs_f64())
                .unwrap_or_default();
            stats.kernel_socket_drops = socket_drops(bind)?;
            Ok(stats)
        });
        Ok(Self {
            done,
            thread: Some(thread),
        })
    }

    pub fn finish(mut self) -> Result<Stats> {
        self.done.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("receiver thread panicked"))?
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn socket_drops(bind: SocketAddrV4) -> Result<u64> {
    let address = format!(
        "{:08X}:{:04X}",
        u32::from_le_bytes(bind.ip().octets()),
        bind.port()
    );
    // GotaTun normally binds an IPv6 dual-stack socket; the payload sink is IPv4.
    let v6 = format!("00000000000000000000000000000000:{:04X}", bind.port());
    for (path, wanted) in [("/proc/net/udp", address), ("/proc/net/udp6", v6)] {
        if path.ends_with('6') && !bind.ip().is_unspecified() {
            continue;
        }
        let table = std::fs::read_to_string(path)?;
        if let Some(line) = table
            .lines()
            .find(|line| line.split_whitespace().nth(1) == Some(wanted.as_str()))
        {
            return line
                .split_whitespace()
                .last()
                .context("missing UDP drops")?
                .parse()
                .context("invalid UDP drops");
        }
    }
    anyhow::bail!("UDP socket missing from /proc/net/udp{{,6}}: {bind}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receiver_counts_unique_payload_and_detects_duplicates_and_invalid_data() {
        let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(address) = reservation.local_addr().unwrap() else {
            panic!()
        };
        drop(reservation);
        let sink = Sink::start(address, 64, 128).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(address).unwrap();
        let pool = crate::packets::prepare(None, 64, 64, 1234).unwrap();
        crate::batch::send(&tx, &pool, 64, 16, 0.0).unwrap();
        tx.send(&pool.bytes[..128]).unwrap();
        tx.send(&[0u8; 128]).unwrap();
        let stats = sink.finish().unwrap();
        assert_eq!(stats.unique, 64);
        assert_eq!(stats.duplicates, 1);
        assert_eq!(stats.invalid, 1);
        assert_eq!(stats.kernel_socket_drops, 0);
    }
}
