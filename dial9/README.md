# Dial9 profiling harness

`gotatun-dial9` profiles Alice's full GotaTun device under TCP iperf: 5 seconds sending to Bob,
then 5 seconds receiving. This combines both directions in one diagnostic trace, while
numeric benchmarks record them separately. A short ping readiness probe precedes the workload.
The embedded device uses AWS-LC, matching the numeric benchmarks and the product default.

The manual **Dial9 profile** workflow runs on the shared benchmark runner and acquires the same
machine lock as Benchy. It uploads `dial9-traces-<run id>-<attempt>` for 7 days and removes that
attempt's local traces after upload. It does not publish numbers to Bencher. `run.json` records
the source commit, workflow run, parameters and success/failure status alongside the trace.

Inputs are `iperf-seconds` (1–60 per direction, default 5) and `cpu-sample-hz` (1–4000, default
999). More samples and longer runs cost more disk space and profiler overhead. The harness
caps the rolling buffer at 512 MiB and rejects runs whose early segments were discarded.

## Scope and interpretation

Alice is profiled; Bob runs an unprofiled endpoint. Traces contain CPU stacks, scheduler events,
sampled allocations and live allocation tracking, process resources, Tokio tasks and tracing
spans. Explicit `WorkloadEvent` markers bracket each transfer. The custom tracing bridge records ordinary events (level, target, fields, span scope and source
location) alongside the spans; logs also go to stderr. The shared default `info` filter keeps
packet-level trace logs out of both destinations to avoid flooding the trace.

CPU profiling runs through sudo. Check `cpu.profile.backend` in the trace for the actual backend
rather than inferring success from sysctl values. Kernel symbolization may require
`kernel.kptr_restrict=0`; no host settings are modified automatically. Instrumentation affects
performance, so use these traces to explain the separate uninstrumented numeric results.

The telemetry and trace-format crates are pinned to 0.5.0-rc0. The installed Dial9 CLI 0.5.6
can decode this format; recheck compatibility whenever either version changes.

## Download and inspect

```bash
gh run download <run id> --repo serock3-bench/gotatun \
  -n dial9-traces-<run id>-<attempt> -D ./dial9-traces
dial9 serve --local-dir ./dial9-traces
```

For a quick integrity and workload check with the CLI's bundled parser:

```bash
dial9 agents toolkit /tmp/dial9-toolkit
node dial9/verify-trace.cjs /tmp/dial9-toolkit ./dial9-traces
```

This first runs the toolkit's aggregate analysis, then checks for complete send/receive markers
and on-CPU samples in both phases. It is a smoke check, not a performance diagnosis. The bundled
`dial9 agents` skills describe deeper analysis.

## Build and run by hand

Keep a sibling `benchy` checkout, as for the numeric benchmarks. Build from this directory so `.cargo/config.toml` enables `tokio_unstable` and frame pointers:

```bash
cd dial9
cargo build --locked --profile profiling
./target/profiling/gotatun-dial9 run --trace-dir ./traces --iperf-seconds 5
```

`run` is the unprivileged controller and invokes `tunnel` through passwordless sudo locally.
It deploys the same binary to Bob over passwordless SSH, starts an unprofiled `endpoint` and an
iperf server on port 5209, verifies that the listener belongs to this run, and stops the owned
processes on success or failure. The peer endpoint also has a bounded lease. Abandoned local
processes after a hard kill may still require inspection before another run.

The usual `BENCHY_PEER`, `BENCHY_ALICE_ADDRESS`, `BENCHY_BOB_ADDRESS` and
`BENCHY_WIREGUARD_PORT` variables override controller defaults. Both machines need `ip`, `ping`,
`iperf3`, `ss`, SSH and passwordless sudo. WireGuard keys are ephemeral. Use separate machines:
putting both tunnel addresses on one kernel can route locally and bypass GotaTun.
