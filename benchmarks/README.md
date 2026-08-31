# GotaTun system benchmarks

This is a separate Cargo workspace containing the benchmark definitions for this repository. The
shared runner and result format live in the sibling `app-bench` repository.

Run the default benchmark set through `benchy-cli` from `app-bench`, or run the first scenario
directly:

```console
cargo run --release --locked \
  --config 'target."cfg(unix)".runner="/usr/bin/env"' \
  --manifest-path benchmarks/Cargo.toml \
  --package gotatun-throughput-benchmark
```

The throughput scenario runs on the controller host and deploys its current executable to the peer.
It embeds the GotaTun library, but invokes the host's `ip`, `ssh`, `scp`, `ping`, and `iperf3` tools.
Both hosts need passwordless access to the narrow privileged operations used by the benchmark.

Configuration is read at runtime:

- `APP_BENCH_PEER` (default `mole@10.0.0.2`)
- `APP_BENCH_ALICE_ADDRESS` (default `10.0.0.1`)
- `APP_BENCH_BOB_ADDRESS` (default `10.0.0.2`)
- `APP_BENCH_INTERFACE` (default `bench0`)
- `APP_BENCH_WIREGUARD_PORT` (default `51821`)
- `APP_BENCH_IPERF_PORT` (default `5201`)
- `APP_BENCH_DURATION` (default `30` seconds)
- `APP_BENCH_MTU` (default `1440`)

WireGuard key material is generated for each run and is not stored in GitHub. The SSH host identity
is provisioned on the benchmark controller rather than injected into branch-controlled code.
