# TCP downloads with a kernel WireGuard peer

This experiment checks whether Linux WireGuard on Bob can feed Alice sufficiently
fast for a simple TCP download benchmark. It remains on `experiment/kernel-peer`,
separate from main, the upstream review branches, Actions and Bencher publishing.

## Result

**Kernel WireGuard on Bob has ample headroom at the current GotaTun download
rates.** TCP throughput was essentially unchanged by the peer swap in these
samples, and the mixed setup had less variation across complete runs.

Five 30-second measured trials per case, each after three seconds of omitted
warmup. Rates are Alice's received application-payload Gb/s; SD is sample standard
deviation across complete trials.

| Alice receiver | Bob sender | Mean ± SD Gb/s | CV | Range Gb/s |
| --- | --- | ---: | ---: | ---: |
| Kernel WG | Kernel WG | 8.357 ± 0.248 | 2.96% | 8.112–8.746 |
| GotaTun | Kernel WG | **2.647 ± 0.010** | **0.37%** | 2.632–2.655 |
| GotaTun | GotaTun | 2.658 ± 0.052 | 1.95% | 2.588–2.728 |

Even the slowest kernel/kernel trial exceeds three times the observed mixed
throughput. The two GotaTun receiver configurations differ by about 0.4% in mean
throughput. With five samples, the reduced variation is encouraging evidence for
this setup; it does not establish long-term stability or a causal explanation
for every source of variance.

The mixed configuration reported 77 TCP sender retransmissions across five
trials, compared with 9,555 for GotaTun/GotaTun and zero for kernel/kernel. These
counts describe TCP retransmissions, not a directly measured WireGuard packet
loss percentage. Alice's GotaTun process averaged 385.4% CPU with the kernel peer
and 381.1% with the userspace peer; CPU scope is described below.

The physical link is **10 Gb/s**. The earlier 6 Gb/s UDP control was a chosen
offered rate, and the custom unpaced UDP generator topped out around 6.8–7 Gb/s.
Those measurements did not establish a 6 Gb/s link ceiling. TCP through the
kernel has a different I/O/offload path; the measured 8.1–8.7 Gb/s remains below
the physical link rate. Offload/scheduling causes were not separately profiled.

This supports using **ordinary TCP iperf with kernel WireGuard on Bob** for the
automated download benchmark, retaining the embedded GotaTun on Alice and all
primary measurements on Alice. No custom sender, encrypted packet pool or loss
budget search is needed for that test. The UDP experiments remain available for
diagnosis. Default workflows/benchmark definitions have not been changed.

## Method

Three endpoint combinations are tested with fresh keys and interfaces each time:

- **Kernel/kernel:** Alice and Bob both use Linux WireGuard, checking sender and
  link headroom.
- **GotaTun/kernel:** Alice runs the ordinary embedded GotaTun/AWS-LC endpoint;
  Bob uses Linux WireGuard.
- **GotaTun/GotaTun:** the corresponding userspace peer control.

All data flows **Bob to Alice** over their physical `eno2` link, negotiated at
10 Gb/s. The controller verifies physical underlay routes and tunnel routes.
MTU is 1440 on every tunnel; iperf reports the same TCP MSS in every case. Alice
initiates one TCP stream with `--reverse`, `--time 30`, `--omit 3`, `--interval 1`,
and JSON output. There are five complete trials per case. The case order rotates
each repetition and there is a two-second rest between trials. No CPU pinning,
buffer-limit changes, congestion-control tuning, or NIC changes are made.

The primary value is Alice's `end.sum_received.bits_per_second`, excluding the
three-second omitted warmup. TCP sender retransmission counts are retained as
diagnostics. Full iperf client JSON, including receiver intervals, is saved for
every trial. Throughput spread is sample SD across complete trials.

CPU is collected only for Alice's GotaTun process, in units where 100% is one
logical CPU. Its window covers the entire iperf invocation, including connection
setup and omitted warmup. Alice's iperf CPU comes from iperf's own summary. An idle
kernel-endpoint helper's process CPU does not measure the kernel datapath, so the
kernel/kernel case intentionally has no GotaTun CPU value. These measurements do
not establish comparative total-system CPU efficiency of kernel vs userspace WG.

Both hosts use Linux 6.1.0-47-amd64, iperf3 3.12, wireguard-tools v1.0.20210914,
`cubic` TCP congestion control and their existing `powersave` governors. GotaTun
is built in release mode with AWS-LC; the product library source is unchanged.

## Resource ownership

The controller holds the shared Benchy machine lock. Kernel helpers refuse an
existing interface, configure ephemeral keys through stdin (no key/config files),
and remove their owned interface on SIGINT, SIGTERM or 120-second lease expiry.
After stopping processes, the controller also checks for a leftover interface
whose ownership alias matches that helper's PID. An interface with another alias
is preserved. Existing services, interfaces, global sysctls and NIC settings are
left intact.

Each trial uses only `bgio0`, UDP port 51831 and TCP port 19432. Peer deployment
uses a private random temporary directory, removed on completion. The ordinary
iperf server is stopped by its owned PID after each successful trial; its
"interrupt - the server has terminated" message is expected cleanup output.

## Reproduce and inspect

```bash
cargo build --release --locked
./target/release/gotatun-buffered-download kernel-tcp \
  --duration 30 --warmup 3 --repetitions 5 \
  --output results/kernel-tcp/comparison.json
python3 analyze-kernel-tcp.py results/kernel-tcp/comparison.json \
  --csv results/kernel-tcp/summary.csv
```

The analyzer validates direction, single-stream TCP settings, omitted warmup,
receiver duration, byte/rate consistency, case/repetition coverage and CPU scope
before computing summaries. Raw data, host metadata and failure-path validation
are retained alongside the report.

## Validation and final state

Eight Rust tests and Clippy with warnings denied pass. The analyzer validated all
15 main trials and three smoke trials. A live SIGINT test interrupted an active
kernel/kernel download and cleaned up both interfaces and all owned processes.
A separate test pre-created an interface: startup was rejected, the interface
and ownership alias were preserved, and only the validation fixture was removed
afterward. Both failed runs were retained as diagnostic reports.

Final checks show no `bgio0` interface, experiment endpoint, or experiment port
listener on either host. The machine lock is released, Alice's runner remains
active, both links report 10,000 Mb/s, and global receive-buffer limits and TCP
congestion control remain unchanged. No persistent WireGuard configuration or
key file was created. All experiment changes are on the test fork's
`experiment/kernel-peer` branch; main, review branches and upstream are untouched.

These are small exploratory samples on this testbed. Kernel control headroom
applies to the observed GotaTun rates. TCP's ACK, flow-control, congestion-control
and retransmission behavior are part of the workload. Packet sizes and kernel
work differ from the precomputed IPv4 UDP experiment, so the two are useful
cross-checks rather than identical measurements of one fixed ceiling.
