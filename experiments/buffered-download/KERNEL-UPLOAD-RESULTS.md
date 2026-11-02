# Kernel-peer TCP upload and first-slice integration

**The kernel peer exposes Alice's upload capacity that was hidden by Bob's
GotaTun receiver.** Five complete upload trials per configuration gave:

| Alice sender | Bob receiver | Alice Gb/s mean ± sample SD | CV | Range Gb/s |
| --- | --- | ---: | ---: | ---: |
| Kernel WG | Kernel WG | 7.148 ± 0.690 | 9.65% | 6.607–8.229 |
| GotaTun | Kernel WG | **4.537 ± 0.053** | **1.16%** | 4.462–4.579 |
| GotaTun | GotaTun | 2.655 ± 0.050 | 1.90% | 2.598–2.727 |

Every trial uses 30 measured seconds after three seconds of omitted warmup, one
TCP stream, 1440-byte tunnel MTU, and the same real 10 Gb/s link. Case order
rotates between repetitions. Alice's local sender summary and CPU are primary;
Bob has no GotaTun CPU instrumentation. TCP MSS was 1388 in every configuration.
The raw protocol and validation are implemented in the same isolated experiment
as [the download comparison](KERNEL-TCP-RESULTS.md), using `--direction upload`.

The kernel-peer upload is about 71% higher than the userspace-peer control.
Alice's GotaTun CPU also rises from about 288% to 377% (100% is one logical CPU),
consistent with exercising her sender more fully. The kernel control is variable,
but even its lowest value is about 44% above the fastest mixed upload trial.
Peer capacity should be rechecked as GotaTun improves.

The previous raw UDP upload of roughly 3.4 Gb/s used different packetization and
kernel/offload work; it was not a universal transmit ceiling. The present peer
comparison holds the TCP workload constant. Alice's sender and Bob's receiver
summaries differ by less than 0.007% in every trial, so queued-but-undelivered
data does not explain the higher rate. Bob's summary is diagnostic, not the
primary measurement.

## Selected production approach

Use TCP iperf with GotaTun embedded on Alice and Linux kernel WireGuard on Bob
for **both upload and download**. The earlier download comparison measured
2.647 ± 0.010 Gb/s with that topology (0.37% relative SD). These small samples
support the simpler setup; they do not establish long-term repeatability.

This has been integrated into the first proposed upstream slice on the test
fork's `review/gotatun-benchmarks` branch, in commit
`1c1e3138dd8dbc2e19af3b2348e2e0149cab8d45`. The slice includes:

- Existing separate upload/download packages and shared measure IDs, with only
  Alice sampled for GotaTun/iperf CPU and throughput.
- A small leased kernel-peer helper on Bob. Fresh keys/PSK are passed to `wg`
  through stdin; no key/config file is written.
- Existing-interface guards on both endpoints, private random deployment
  directories, and a unique ownership label for cleanup after interrupted startup
  or forced helper shutdown. Unowned interfaces are preserved and failures surface.
- A default three-second omitted throughput warmup (`BENCHY_WARMUP`, 0–30 seconds).
  GotaTun CPU covers the full invocation including warmup; CPU has no uncertainty
  bounds. Throughput interval uncertainty excludes the warmup.
- Peer/warmup/CPU-scope parameters and a fresh prepared Bencher testbed,
  `alice-bob-kernel-peer-v1`, to avoid mixing baselines across workload changes.

The first slice is approximately **930 review lines**, excluding generated
lockfiles, including roughly 710 Rust lines. The kernel-peer/lifecycle module is
195 lines. Raw-packet generation and rate-search experiments are excluded.

The hotpath and Dial9 review layers have been rebased above it. Their profiling
controllers are unchanged. Original tips are backed up under
`archive/pre-kernel-peer-*-20261103` in the test fork. No fork main or upstream
branch, PR or default workflow was changed.

## Integrated validation

The actual first-slice binaries passed a 30-second live run in each direction:
**4.624 Gb/s upload** and **2.658 Gb/s download**. These are individual validation
runs, separate from the five-trial experiment above. Their existing schema-v1
artifacts, under `results/kernel-upload/core/`, identify `linux-wireguard`,
record three seconds of warmup, and retain all three shared measures. Throughput
uncertainty uses 30 local one-second intervals, and CPU has no bounds.

Live failure tests additionally verified that an invalid warmup fails before
setup, a pre-existing interface on Bob is preserved, and interruption records
failure and removes both owned interfaces. Core tests/Clippy pass; the rebased
hotpath workspace passes tests/Clippy and the Dial9 workspace builds. Experimental
packet-workload tests also pass. Host cleanup metadata is retained with the data.

The first-slice changes are review candidates, not a rollout. Hosted publishing
was not invoked for these direct SSH validations. Fresh default-branch baselines
and threshold calibration remain rollout tasks after human review.

## Reproduce the experiment

```bash
cargo build --release --locked
./target/release/gotatun-buffered-download kernel-tcp \
  --direction upload --duration 30 --warmup 3 --repetitions 5 \
  --output results/kernel-upload/comparison.json
python3 analyze-kernel-tcp.py results/kernel-upload/comparison.json \
  --csv results/kernel-upload/summary.csv
```

The analyzer validates Alice's sender role, one-stream settings, omitted warmup,
duration, byte/rate consistency, local interval direction, and complete case/run
coverage. Raw JSON includes every interval and both end summaries. Measurements
used source `f55b3d8` on `experiment/kernel-upload`; the production integration is
kept separately on the review branch.
