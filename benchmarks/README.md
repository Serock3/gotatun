# GotaTun system benchmarks

This separate Cargo workspace embeds GotaTun from this checkout. Benchy supplies the
runner, result schema and GitHub/Bencher integration from a sibling `benchy` checkout.

## Workload and measurements

`gotatun-upload` sends TCP traffic from Alice to Bob; `gotatun-download` sends from
Bob to Alice. Both measure Alice only. Bob runs the peer endpoint and iperf server,
without CPU sampling or profiling.

Both benchmarks report shared measures:

- `throughput.network`: Alice's sender or receiver throughput, stored in bits/s and
  published as Gb/s.
- `cpu.gotatun`: Alice's GotaTun process CPU, from the change in `/proc/PID/stat`
  user/system time over the transfer's wall time, across all its threads.
- `cpu.iperf`: Alice's iperf process CPU, from its local JSON report.

CPU is expressed as a percentage of one logical CPU (200% means two CPUs), without
uncertainty bounds. Throughput uses the local one-second intervals to estimate the
standard error of the mean. This assumes between-run variance is negligible; it is
not an estimate of between-run variance. Raw reports retain the estimate's method.

The embedded endpoints select AWS-LC, matching GotaTun's default crypto backend.
Their independently resolved lockfile pins the same AWS-LC version as the root
lockfile. Changing backend requires a new baseline; the pilot uses the
`alice-bob-aws-lc-v1` Bencher testbed rather than comparing with the old Ring runs.

## Running

```console
cargo run --release --locked --manifest-path benchmarks/Cargo.toml -p gotatun-upload-benchmark
```

The controller needs Rust, a C compiler/CMake for AWS-LC, `ip`, `ping`, `iperf3`,
`ssh`, `scp`, `ss`, and passwordless sudo to create a TUN endpoint. Bob needs the
runtime tools and sudo; it receives the same benchmark executable over SSH.
Processes are stopped by their recorded PID. Endpoints have a five-minute lease
as a fallback if the controller loses its SSH connection. Both benchmarks acquire
`/tmp/benchy.lock` to exclude local/manual runs as well as Actions jobs.

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
