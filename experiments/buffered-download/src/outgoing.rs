// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Count at the production transport boundary, never at the input generator.
use gotatun::{packet::Packet, udp::UdpSend};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    time::Instant,
};

pub struct Counters {
    wire_len: usize,
    epoch: Instant,
    packets: AtomicU64,
    first_ns: AtomicU64,
    last_ns: AtomicU64,
    errors: AtomicBool,
}
#[derive(Serialize, Deserialize)]
pub struct Report {
    pub packets: u64,
    pub datagram_bytes: usize,
    pub send_span_seconds: f64,
    pub transport_error: bool,
}

impl Counters {
    pub fn new(wire_len: usize) -> Self {
        Self {
            wire_len,
            epoch: Instant::now(),
            packets: AtomicU64::new(0),
            first_ns: AtomicU64::new(u64::MAX),
            last_ns: AtomicU64::new(0),
            errors: AtomicBool::new(false),
        }
    }
    fn matches(&self, packet: &Packet) -> bool {
        packet.len() == self.wire_len && packet.first() == Some(&4) && packet.len() > 32
    }
    fn record(&self, count: u64, started: Instant, success: bool) {
        if !success {
            self.errors.store(true, Relaxed);
            return;
        }
        if count == 0 {
            return;
        }
        self.first_ns.fetch_min(
            started.duration_since(self.epoch).as_nanos() as u64,
            Relaxed,
        );
        self.last_ns
            .fetch_max(self.epoch.elapsed().as_nanos() as u64, Relaxed);
        self.packets.fetch_add(count, Relaxed);
    }
    pub fn snapshot(&self) -> Report {
        Report {
            packets: self.packets.load(Relaxed),
            datagram_bytes: self.wire_len,
            send_span_seconds: self
                .last_ns
                .load(Relaxed)
                .saturating_sub(self.first_ns.load(Relaxed)) as f64
                / 1e9,
            transport_error: self.errors.load(Relaxed),
        }
    }
}

#[derive(Clone)]
pub struct CountedSend<S> {
    pub inner: S,
    pub counters: Option<Arc<Counters>>,
}

impl<S: UdpSend> UdpSend for CountedSend<S> {
    type SendManyBuf = S::SendManyBuf;
    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        let count = self
            .counters
            .as_ref()
            .map_or(0, |s| u64::from(s.matches(&packet)));
        let start = Instant::now();
        let result = self.inner.send_to(packet, target).await;
        if let Some(stats) = &self.counters {
            stats.record(count, start, result.is_ok());
        }
        result
    }
    async fn send_many_to(
        &self,
        buf: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let count = self.counters.as_ref().map_or(0, |s| {
            packets.iter().filter(|(p, _)| s.matches(p)).count() as u64
        });
        let start = Instant::now();
        let result = self.inner.send_many_to(buf, packets).await;
        if let Some(stats) = &self.counters {
            stats.record(count, start, result.is_ok());
        }
        result
    }
    fn max_number_of_packets_to_send(&self) -> usize {
        self.inner.max_number_of_packets_to_send()
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        self.inner.set_fwmark(mark)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct Fake {
        fail: bool,
    }
    impl UdpSend for Fake {
        type SendManyBuf = ();
        async fn send_to(&self, _: Packet, _: SocketAddr) -> io::Result<()> {
            if self.fail {
                Err(io::Error::other("partial/failed send"))
            } else {
                Ok(())
            }
        }
    }
    #[tokio::test]
    async fn counts_only_successful_data_and_flags_a_transport_failure() {
        let stats = Arc::new(Counters::new(100));
        let target = "127.0.0.1:1000".parse().unwrap();
        let send = CountedSend {
            inner: Fake { fail: false },
            counters: Some(stats.clone()),
        };
        let mut data = [0; 100];
        data[0] = 4;
        send.send_to(Packet::copy_from(&data[..]), target)
            .await
            .unwrap();
        send.send_to(Packet::copy_from(&[4u8; 32][..]), target)
            .await
            .unwrap();
        send.send_to(Packet::copy_from(&[1u8; 100][..]), target)
            .await
            .unwrap();
        assert_eq!(stats.snapshot().packets, 1);
        let send = CountedSend {
            inner: Fake { fail: true },
            counters: Some(stats.clone()),
        };
        assert!(
            send.send_to(Packet::copy_from(&data[..]), target)
                .await
                .is_err()
        );
        assert_eq!(stats.snapshot().packets, 1);
        assert!(stats.snapshot().transport_error);
    }

    #[derive(Clone)]
    struct BatchFake {
        fail: bool,
        called: Arc<AtomicU64>,
    }
    impl UdpSend for BatchFake {
        type SendManyBuf = ();
        async fn send_to(&self, _: Packet, _: SocketAddr) -> io::Result<()> {
            panic!("must preserve the batched transport method")
        }
        fn max_number_of_packets_to_send(&self) -> usize {
            64
        }
        async fn send_many_to(
            &self,
            _: &mut (),
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            self.called.fetch_add(1, Relaxed);
            if self.fail {
                packets.remove(0);
                Err(io::Error::other("one packet sent before failure"))
            } else {
                packets.clear();
                Ok(())
            }
        }
    }
    #[tokio::test]
    async fn preserves_batching_and_invalidates_partially_failed_batches() {
        let stats = Arc::new(Counters::new(100));
        let calls = Arc::new(AtomicU64::new(0));
        let send = CountedSend {
            inner: BatchFake {
                fail: false,
                called: calls.clone(),
            },
            counters: Some(stats.clone()),
        };
        let target = "127.0.0.1:1000".parse().unwrap();
        let mut data = [0u8; 100];
        data[0] = 4;
        let packets = || {
            vec![
                (Packet::copy_from(&data[..]), target),
                (Packet::copy_from(&[1u8; 148][..]), target),
                (Packet::copy_from(&data[..]), target),
            ]
        };
        assert_eq!(send.max_number_of_packets_to_send(), 64);
        let mut batch = packets();
        send.send_many_to(&mut (), &mut batch).await.unwrap();
        assert!(batch.is_empty());
        assert_eq!(stats.snapshot().packets, 2);
        assert_eq!(calls.load(Relaxed), 1);
        let send = CountedSend {
            inner: BatchFake {
                fail: true,
                called: calls.clone(),
            },
            counters: Some(stats.clone()),
        };
        assert!(send.send_many_to(&mut (), &mut packets()).await.is_err());
        assert_eq!(stats.snapshot().packets, 2);
        assert!(stats.snapshot().transport_error);
    }
}
