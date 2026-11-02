# Buffered real-network download experiment

Optional exploration, separate from the default Benchy suite and upstream review
branches. No product code changes. The existing TCP iperf benches remain the merge
candidate. This experiment measures receive capacity under a different UDP workload;
do not compare its numbers directly with TCP iperf as if they were the same test.

Bob establishes a real WireGuard session with Alice, prepares a bounded pool of
fresh encrypted packets, and waits. Alice starts sampling only after preparation.
Bob then sends the pool once with `sendmmsg`. Alice runs the ordinary embedded
GotaTun device (AWS-LC, normal UDP socket/GRO and TUN), and a batched local UDP sink
counts payload delivered through the kernel. Replay protection and handshakes are
unchanged. The packets cross the physical NICs; routes through localhost are refused.

The direct-UDP control sends datagrams of the same outer UDP size over the same
link, without encryption. This helps establish sender/link/receiver headroom. It
does not prove that the post-TUN sink or every kernel stage has unlimited capacity.

## Run on Alice

Requires a sibling Benchy checkout containing its shared process/CPU helpers,
Linux, Rust 1.95, a C compiler/CMake, passwordless SSH to Bob, and passwordless sudo
for Alice's endpoint. Both hosts need `ip` and `ss`. Bob receives the built binary;
it needs no compiler or TUN device. Neither global sysctls nor NIC settings change.
The controller claims `/tmp/benchy.lock`; keep the legacy job stopped. Avoid builds
or other workloads on either host during measurements.

```bash
cd experiments/buffered-download
cargo build --release --locked
./target/release/gotatun-buffered-download run \
  --rates 1,2,3,4,6,8,0 --repetitions 3 --output results/sweep.json
```

Defaults use Alice `10.0.0.1`, Bob `10.0.0.2`, peer `mole@10.0.0.2`, NIC `eno2`,
interface `bgio0`, outer UDP port 51831, sink port 19432, and one million packets
with 1200-byte application payloads. Each trial gets new keys and a fresh pool.
The ~1.26 GB pool is limited to 2 GiB and freed before the next trial. Control TCP
ports start at 19440 and advance per trial. Endpoint processes have a 120-second
lease; sender preparation/start/transmit waits are bounded.

`--rates` specifies offered **application payload** Gb/s; zero means unpaced. Real
wire rate is higher because of IP/UDP/WireGuard/Ethernet overhead. `--batch` selects
1–256 datagrams per send call. `--modes direct` or `--modes gotatun` selects one mode.
`--endpoint-cpus 0` restricts only Alice's GotaTun process for a sensitivity check.

## Interpret results

The JSON is updated after each completed trial, including on failures. Results are
not automatically published to Bencher. Each trial records:

- Actual offered rate and sending duration, excluding all encryption/preparation.
- Unique delivered payload / sender duration, loss, duplicates and invalid packets.
- Payload sink kernel socket drops, its actual receive buffer, and arrival span.
- GotaTun's outer socket drops, including its normal IPv6 dual-stack socket.
- GotaTun process CPU over START through the receiver drain (including a short idle
  tail), its sampling window, and CPU seconds per delivered Gbit. The latter avoids
  the idle tail diluting the reported CPU cost; process CPU accounting has tick
  quantization and these are diagnostic estimates for finite packet trains.

Look for delivered throughput plateauing while actual offered load continues to
increase, with the direct control demonstrably faster. Loss at saturation is an
expected observation, not silently counted as delivered traffic. Socket drops at
the payload sink indicate a measurement bottleneck and invalidate a simple claim
that the plateau is solely GotaTun's processing limit. A large difference between
arrival span and sending duration also needs investigation.

Pacing operates per batch: it produces small bursts, not perfectly evenly spaced
packets. Test batch-size and packet-count sensitivity before treating the result
as a stable capacity benchmark. Very short trains exaggerate startup/drain effects.

Unit/integration tests cover authenticated packet generation, unique counters and
replay rejection, batched datagram boundaries, and receiver duplicate/invalid-data
accounting. Socket tests require a normal Linux environment (no root required).
