# Buffered real-network download experiment

Optional exploration, separate from the default Benchy suite and upstream review
branches. No product code changes. The existing TCP iperf benches remain the merge
candidate. This experiment measures receive capacity under a different UDP workload;
do not compare its numbers directly with TCP iperf as if they were the same test.

Bob establishes a real WireGuard session with Alice, prepares a bounded pool of
fresh encrypted packets, and waits. Alice starts sampling only after preparation.
Bob then sends the pool once with `sendmmsg`. Alice runs the ordinary embedded
GotaTun device (AWS-LC, normal UDP socket/GRO and TUN), and a batched local UDP sink
counts payload delivered through the kernel. Inner IPv4 UDP uses a zero UDP
checksum (permitted for IPv4); IP headers have valid checksums. This is a custom
UDP workload, not a reproduction of TCP checksum/ACK processing. Replay protection and handshakes are
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
The default ~1.26 GB pool is freed before the next trial. Download pools may use up
to 8 GiB, but preparation refuses to consume more than half of Bob's currently
available RAM. Upload plaintext pools retain their 2 GiB limit. Control TCP
ports start at 19440 and advance per trial. Endpoint processes have a 120-second
lease; sender preparation/start/transmit waits are bounded.

`--rates` specifies offered **application payload** Gb/s; zero means unpaced. Real
wire rate is higher because of IP/UDP/WireGuard/Ethernet overhead. `--batch` selects
1–256 datagrams per send call. `--modes direct` or `--modes gotatun` selects one mode.
`--endpoint-cpus 0` restricts only Alice's GotaTun process for a sensitivity check
(and affects the runtime's default worker count). `--receive-buffer-mib 8` uses
`SO_RCVBUFFORCE` on that process's owned socket to bypass a low `rmem_max`, without
changing the global setting. Zero, the default, retains normal buffer-limit
behavior. Both the requested and actual kernel buffer sizes are recorded.

## Interpret results

The JSON is updated after each completed trial, including on failures. Results are
not automatically published to Bencher. Each trial records:

- Actual offered rate and sending duration, excluding all encryption/preparation.
- Unique delivered payload divided by the greater of sender duration and local
  first-to-last delivery span, plus loss, duplicates and invalid packets. The
  sender-window-only rate is retained separately. This prevents post-send queue
  draining from masquerading as higher sustained processing capacity.
- Payload sink kernel socket drops, its actual receive buffer, and arrival span.
- GotaTun's outer socket drops and actual receive-buffer size, including its
  normal IPv6 dual-stack socket. Drop counters at different stack layers need not
  count the same units, especially with GRO; do not subtract them to assign loss.
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

## Paced download capacity search

See [CAPACITY-RESULTS.md](CAPACITY-RESULTS.md) for the measured searches, including
failed confirmations and the longer-trial pacing comparison.

Search for the highest offered rate within an explicit packet-loss budget. Select
one mode and at least three repetitions. The example prepares four million fresh
packets (~5.06 GB) **before each trial**, giving about 13 seconds of data at 3 Gb/s:

```bash
./target/release/gotatun-buffered-download capacity \
  --modes gotatun --packets 4000000 --repetitions 3 --batch 64 \
  --payload-receive-buffer-mib 8 \
  --min-gbps 2 --max-gbps 4 --resolution-gbps 0.125 \
  --loss-budget-percent 0.1 --output results/capacity/batch-64.json
```

The search tests both bounds, bisects the passing/failing bracket, then repeats
the best passing rate for confirmation. Every repetition must meet the budget;
losses are never averaged into a pass. It rests two seconds between trials. A
generator rate more than 1% from the request, payload-sink socket drops, or
duplicate payload invalidates the search and leaves a failed report with raw
samples. Loss in GotaTun's outer receive socket remains part of the tested path.

The report records every trial and decision, passing/failing bounds, and whether
confirmation succeeded. A failed confirmation is explicitly unstable; a passing
upper bound means only "at least the search maximum." The bracket assumes a
roughly monotonic loss boundary and is an experimental estimate, not a confidence
interval. `--rates` is replaced by the search bounds in this command. Paced trials
longer than 55 seconds are refused to stay within the sender/session leases.

Repeat with `--batch 256` to test larger send batches. The packet pool controls
trial length; the send batch controls syscall amortization and burst size. Larger
batches may increase burst loss, so they are a separate experimental condition.
Keep the direct control demonstrably faster and check longer trains before using
the result for regression alerts. No encrypted pool is ever reused or replayed.

`--payload-receive-buffer-mib 8` raises only the local payload sink's socket
buffer, using a short-lived `sudo -n` helper that inherits that owned socket on
stdin. No global limit or GotaTun buffer setting changes, and the socket is closed
at trial end. Its actual buffer size is recorded. This avoids making a small sink
queue an accidental limiter when GotaTun delivers bursts. The receiver also
records missing packets in sequence blocks of 100,000, computed after the trial
from its existing bitmap without adding work to the receive loop.

`--no-catch-up` spaces batches from each actual batch start, rather than catching
up to the original schedule after a sender stall. This can reduce unintended
bursts, at the cost of a slightly lower actual offered rate. The capacity search
still requires that rate to be within 1% of the request. Both pacing policies
retain the same syscall/buffer path and cross the physical NICs.

## Results and analysis

See [RESULTS.md](RESULTS.md) for the first Alice/Bob studies and limitations. Raw
studies and environment/validation metadata are retained under `results/`. Rebuild
the table and CSV with Python's standard library:

```bash
python3 analyze.py results/*.json --csv results/summary.csv
```

The displayed spread is sample standard deviation across complete packet trains,
not across one-second intervals. The script recomputes the same delivery-window
definition for the initial and refined experimental report versions.

## Upload counterpart

The `upload` command measures Alice's local encrypted output while Bob discards
data. It is a separate experiment on `experiment/raw-upload`; see
[UPLOAD-RESULTS.md](UPLOAD-RESULTS.md) for the method, observations and limitations.
It leaves the normal iperf benchmarks unchanged.

```bash
./target/release/gotatun-buffered-download upload \
  --modes gotatun --rates 0 --input-loops 10 --repetitions 3 \
  --peer-kernel-drop --output results/upload/kernel-drop.json
```

Bob validates an authenticated, checksum-checked probe before measurement, then
never decrypts data. Normally he drains raw UDP; `--peer-kernel-drop` instead keeps
the port open but stops reading, so his kernel drops traffic once the socket queue
fills. Alice's primary metric uses her local transport counter, cross-checked with
her NIC, and never uses Bob's received-packet count.

`--input-loops` repeats plaintext, with fresh encryption/nonces for every outgoing
WireGuard packet. It is refused for encrypted download pools. The generator has a
60-second deadline and a cooperative stop flag so it stops before TUN cleanup on
cancellation. Paced trains whose expected duration exceeds 55 seconds are refused.
The default output filename is now `buffered-io.json`; use explicit output paths
when comparing conditions.

Summarize saved upload studies separately from download studies:

```bash
python3 analyze-upload.py results/upload/upload-*.json --csv results/upload/summary.csv
```
