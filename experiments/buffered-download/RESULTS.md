# Buffered download: first results

The premise works: Bob can precompute authenticated traffic and drive Alice's
production receive path across the physical NICs, with clear sender headroom.
This prototype is useful diagnostically. Its unpaced throughput is too variable
to replace the current TCP iperf regression benchmarks.

## Method

The four main studies contain 76 complete packet trains: one million fresh packets
per trial, 1200-byte application payload, a ~1.26 GB ciphertext pool, new session
keys per trial, and normal replay protection. Bob's encryption/preparation is
outside the measurement window. Alice runs ordinary GotaTun/AWS-LC 1.16.2 with no
hotpath or Dial9 instrumentation. Only the endpoint's bind-time buffer configuration
changes in the buffer control; the production send/receive socket implementation,
GRO, TUN and kernel/NIC path are preserved. No product source files changed.

Direct controls transmit datagrams with the same outer UDP size, so they test
roughly the same sender packet-rate load. Throughput is application-payload Gb/s,
not Ethernet line rate. Requested 8 Gb/s exceeds this sender's observed capacity:
actual offered rate is recorded separately and was generally about 6.8–7.0 Gb/s.

Delivered throughput divides unique received payload by the larger of sender time
and Alice's first-to-last arrival span. This includes post-send draining rather
than counting queued packets as instantaneous capacity. The initial source version
used sender time alone; the analysis recomputes a consistent definition from its
preserved raw spans. Source revisions are in every study and the CSV.

Both hosts reported a Xeon E3-1240 v6, eight logical CPUs, Linux 6.1.0-47-amd64,
ixgbe, 10 Gb/s full duplex and MTU 1500. Both governors reported `powersave`; no
frequency/governor policy was changed. See [environment.json](results/metadata/environment.json).
Runs were sequential, not randomized; these are exploratory comparisons with only
two or three repetitions per setting, not strong causal/statistical conclusions.

## Selected observations

Mean ± sample standard deviation across complete trains. Requested load is in
application-payload Gb/s; "max" means unpaced. CPU restriction also changes Tokio's
default worker count, so it is a resource sensitivity check, not isolated core scaling.

| Configuration | Requested | Delivered Gb/s | Mean loss | Trains |
| --- | ---: | ---: | ---: | ---: |
| Direct UDP | 6 | 6.000 ± <0.001 | <0.001% | 3 |
| GotaTun, normal buffer limit | 3 | 2.986 ± 0.011 | 0.47% | 3 |
| GotaTun, normal buffer limit | 4 | 3.554 ± 0.373 | 11.14% | 3 |
| GotaTun, normal buffer limit | max | 2.894 ± 0.827 | 58.01% | 3 |
| GotaTun, 8 MiB requested buffer | 3 | 2.987 ± 0.023 | 0.44% | 3 |
| Same buffer, Alice restricted to CPU 0 | 3 | 2.101 ± 0.011 | 29.55% | 2 |

The direct control has substantial headroom over Alice's relatively low-loss
GotaTun rate. Restricting Alice reduces that rate while Bob continues to offer the
same traffic. Together these support the intended isolation from Bob's encryption
path. They do not establish the absolute maximum capacity of Alice's hardware.

Above saturation, delivered throughput is non-monotonic and varies considerably.
Blindly using the highest offered load would be misleading: extra traffic can
reduce delivery rather than reveal a stable plateau. At default buffers, unpaced
throughput's sample SD is about 29% of its mean across three runs.

CPU seconds per delivered Gbit were steadier at fixed moderate load: at requested
3 Gb/s with the 8 MiB buffer, approximately 0.540 ± 0.003 core-seconds/Gbit. This is
a promising diagnostic measure, not yet a calibrated alert. CPU percentage itself
includes the observation window's short idle/drain tail; both scope and duration
are recorded. These estimates use Linux process CPU ticks and have quantization.

## Queue limits and measurement limits

The normal 7 MiB GotaTun receive-buffer request is silently limited by Alice's
`rmem_max=212992`, yielding an actual 425984-byte buffer. The short follow-up
[measurement](results/metadata/normal-buffer-size.json) records that value.
Linux documents this cap and its doubled bookkeeping size under
[SO_RCVBUF](https://man7.org/linux/man-pages/man7/socket.7.html).

The optional `--receive-buffer-mib 8` control uses privileged `SO_RCVBUFFORCE` on the
experiment-owned socket only, yielding 16777216 bytes. Global sysctls are unchanged.
It did not eliminate high-load loss/variance. Reducing Bob's send batch from 64 to
16 also did not produce a consistently stable saturated result. These findings do
not prove buffer size or batching never matter; the full matrix and possible
clock/scheduling effects were not isolated.

All 21 GotaTun trials in the initial/default-buffer sweep reported zero payload-sink
socket drops, while the overloaded GotaTun outer socket reported drops. Some later
controls had small sink drops and are marked in the CSV; do not treat those as a
pure measurement of GotaTun's limit. Outer socket-drop counters, payload losses and
NIC losses are different observations; GRO also complicates comparing their units.
The direct control also occasionally lost a small fraction of packets at its sink.

The [full CSV](results/summary.csv) retains actual offered rates, sink/outer drops,
CPU cost and source revisions. Raw files contain every sample. No experiment
results were published to Bencher and it is not selected by the default workflows.

## Next useful steps

Keep this optional and keep the TCP iperf merge candidate unchanged. The next
capacity experiment should look for a sustained offered rate within an explicit
loss budget, rather than take one unpaced maximum. Longer-train, pacing, CPU/thread
placement and frequency-policy sensitivity need checking before claiming a stable
regression metric. Fixed-load CPU cost could be evaluated separately.

Tests and Clippy pass. Live Ctrl-C and occupied-port checks wrote failed reports,
stopped owned resources, removed the TUN, and preserved the unrelated listener.
No global settings, NIC configuration, upstream repositories or main branches were
changed. Alice's runner service remains active; the legacy job remains stopped.
