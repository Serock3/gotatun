# GotaTun system benchmarks

This is a separate Cargo workspace containing the benchmark definitions for this repository. The
shared runner and temporary result artifacts live in the sibling `benchy` repository.

Run the default benchmark set through `benchy-cli` from `benchy`, or run the first scenario
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
The result records sender- and receiver-reported throughput plus the Alice and Bob process CPU usage
for both iperf3 and GotaTun. CPU percentages are normalized to one logical core and may exceed 100%
when a process uses multiple cores.

Configuration is read at runtime:

- `BENCHY_PEER` (default `mole@10.0.0.2`)
- `BENCHY_ALICE_ADDRESS` (default `10.0.0.1`)
- `BENCHY_BOB_ADDRESS` (default `10.0.0.2`)
- `BENCHY_INTERFACE` (default `bench0`)
- `BENCHY_WIREGUARD_PORT` (default `51821`)
- `BENCHY_IPERF_PORT` (default `5201`)
- `BENCHY_DURATION` (default `30` seconds)
- `BENCHY_MTU` (default `1440`)

WireGuard key material is generated for each run and is not stored in GitHub. The SSH host identity
is provisioned on the benchmark controller rather than injected into branch-controlled code.
