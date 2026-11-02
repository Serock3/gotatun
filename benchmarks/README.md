# GotaTun system benchmarks

This separate Cargo workspace embeds GotaTun from this checkout. Benchy supplies the
runner, result schema and GitHub/Bencher integration from a sibling `benchy` checkout.

## Workload and measurements

`gotatun-upload` sends TCP traffic from Alice to Bob; `gotatun-download` sends from
Bob to Alice. Both measure Alice only. Alice embeds GotaTun; Bob runs Linux kernel
WireGuard and the iperf server, without CPU sampling or profiling. Kernel/kernel
controls on the benchmark machines establish peer headroom in each direction.

Both benchmarks report shared measures:

- `throughput.network`: Alice's sender or receiver throughput, stored in bits/s and
  published as Gb/s.
- `cpu.gotatun`: Alice's GotaTun process CPU, from the change in `/proc/PID/stat`
  user/system time over the full iperf invocation, including setup and omitted
  warmup, across all its threads.
- `cpu.iperf`: Alice's iperf process CPU, from its local JSON report.

CPU is expressed as a percentage of one logical CPU (200% means two CPUs), without
uncertainty bounds. Throughput uses the local one-second intervals to estimate the
standard error of the mean. This assumes between-run variance is negligible; it is
not an estimate of between-run variance. Raw reports retain the estimate's method.

The embedded endpoint selects AWS-LC, matching GotaTun's default crypto backend.
Its independently resolved lockfile pins the same AWS-LC version as the root
lockfile. Changing the peer and warmup requires fresh baselines; the prepared
publisher uses `alice-bob-kernel-peer-v1`, separate from the old runs.

Each test has a three-second pre-test excluded from iperf's throughput summary and
interval uncertainty. CPU covers both warmup and measured traffic. The default
measured phase remains 30 seconds. The kernel peer still has finite capacity;
repeat the headroom control as GotaTun throughput approaches its measured limit.

## Running

```console
cargo build --release --locked --manifest-path benchmarks/Cargo.toml -p gotatun-upload-benchmark
./benchmarks/target/release/gotatun-upload-benchmark
```

Run the controller directly as the SSH user; the repository's Cargo runner uses
sudo for the product CLI. The benchmark itself elevates only endpoint setup.

The controller needs Rust, a C compiler/CMake for AWS-LC, `ip`, `ping`, `iperf3`,
`ssh`, `scp`, `ss`, and passwordless sudo to create a TUN endpoint. Bob needs the
runtime tools, `wg` (wireguard-tools), kernel WireGuard support and sudo; it receives
the benchmark executable over SSH. Processes are stopped by their recorded PID.
Endpoints have a bounded lease as a fallback if the controller loses its SSH
connection. Both benchmarks acquire
`/tmp/benchy.lock` to exclude local/manual runs as well as Actions jobs.

Both endpoints refuse existing interfaces. Bob's helper accepts generated keys
through its arguments and passes them to `wg setconf` via stdin, without writing
key/config files. It removes its temporary interface on SIGINT, SIGTERM or lease
expiry. After shutdown the controller also checks for a leftover peer interface
with its unique ownership label; an interface with a different label is preserved
and the cleanup failure is reported. Deployments use private random temporary
directories. No global buffer limits, NIC settings or persistent WG config change.

Configuration is read at runtime:

| Variable | Default |
| --- | --- |
| `BENCHY_PEER` | `mole@10.0.0.2` |
| `BENCHY_ALICE_ADDRESS` | `10.0.0.1` |
| `BENCHY_BOB_ADDRESS` | `10.0.0.2` |
| `BENCHY_INTERFACE` | `bench0` |
| `BENCHY_WIREGUARD_PORT` | `51821` |
| `BENCHY_IPERF_PORT` | `5201` |
| `BENCHY_DURATION` | `30` seconds (1–120) |
| `BENCHY_WARMUP` | `3` seconds (0–30), excluded from throughput |
| `BENCHY_MTU` | `1440` |

Keys are generated per run. SSH identity/host keys are provisioned on the controller.

## Actions

`Benchmarks` runs on pushes to main, nightly, on internal PRs, and manually with a
benchmark selection and iteration count. External PR jobs require maintainer
approval before running contributor code on the dedicated machines.

A separate GitHub-hosted `Publish benchmarks` workflow receives the project's
`BENCHER_API_KEY` Actions secret and `BENCHER_PROJECT` repository variable. The
self-hosted benchmark job receives no publishing secret. Raw JSON remains in the
benchmark run's summary/artifact; publishing verifies the run and artifact identity.
Profiler experiments are separate review layers, not part of these endpoints.
