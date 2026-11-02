# Upload to a peer that discards data

This counterpart measures Alice's real upload pipeline while removing Bob's
WireGuard receive/decryption work. It works even when Bob never reads the UDP
socket during measurement and his kernel drops virtually all the traffic.
It remains optional and separate from the TCP iperf merge candidates.

## Path and primary metric

Application UDP on Alice → kernel/TUN → normal GotaTun encryption and transport →
physical eno2 NIC → Bob. Neither the real transport nor the NIC is replaced with
an in-memory/localhost substitute. The underlay routes are checked on both hosts.

The local application input rate alone can be misleading because packets can be
dropped before GotaTun outputs them. Instead, an experimental transport wrapper
counts successful sends of the expected-sized WireGuard data packets, excluding
handshake, keepalive and probe packets. It delegates the ordinary transport's
single/batched methods, batch limit, buffer type, local address and fwmark handling.
Any transport error invalidates the trial, including errors after partial sends.
The wrapper adds timing/counter overhead which has not been independently calibrated.
No product source code is modified.

The primary rate is local output packets × application payload bits, divided by
the larger of the application send duration and the local output span. Bob's receive
rate/count is **not** part of this calculation. Alice's NIC TX packet count, bytes,
drops and errors are recorded independently as a cross-check. NIC counters are
interface-wide and can include unrelated traffic; on this dedicated link they
matched the local data count exactly in every saved upload trial, with no TX
errors/drops.

Bob uses the Noise code only for startup handshake and one authenticated probe.
The probe's IPv4 and UDP checksums and payload are validated, then the tunnel
object is dropped. During measurement he either reads/drops raw UDP datagrams
(no data decryption), or, with `--peer-kernel-drop`, simply holds the socket open.
Keeping it open avoids port-unreachable ICMP errors. His counters are diagnostics.

## Trials

All trials use 1200-byte application payloads. Direct controls use the same outer
UDP datagram size as the encrypted workload. Three repetitions per normal setting,
two for the long CPU restriction control. This is exploratory data, not a precise
claim about hardware maximums. Runs were sequential, not randomized, and the hosts'
existing powersave governors remained unchanged.

The initial short studies use one million input packets per trial. Longer trials
reuse that plaintext pool ten times (ten million input packets), producing fresh
WireGuard counters/ciphertext each time. This gives roughly 10–12 seconds of input
without allocating ten times the memory. Only plaintext is repeated; encrypted
packet replay protection is unchanged. Bob's header tracking saw no duplicate
WireGuard data counters in the draining studies. A repeating direct control can
reuse application sequence IDs; `received_datagrams` counts all receives, whereas
`packets`/`duplicates` describe its IDs.

### Maximum-load results

Mean ± sample standard deviation across complete trials. Rates are application
payload equivalents; the encrypted/ethernet wire rate includes additional overhead.

| Condition | Alice output Gb/s | Trials |
| --- | ---: | ---: |
| Direct UDP reference, short trials | 6.864 ± 0.031 | 3 |
| GotaTun, Bob drains without decrypting, long trials | 3.407 ± 0.107 | 3 |
| GotaTun, Bob never reads (kernel drops), long trials | 3.349 ± 0.031 | 3 |
| Same kernel-drop condition, Alice restricted to CPU 0 | 2.261 ± 0.009 | 2 |

Bob's kernel dropped about 12 million packets across the three long no-read trials.
His userspace received zero during those phases. Alice's NIC count still matched
her local output count exactly. Output remained close to the draining condition,
which supports the intended independence from Bob's userspace receive/decryption
capacity. Physical link/NIC capacity remains a shared ceiling.

Alice's attempted input in the long no-read trials averaged about 8.38 Gb/s, above
her approximately 3.35 Gb/s encrypted output. With Alice restricted to CPU 0, input
averaged about 10.12 Gb/s while encrypted output fell to 2.26 Gb/s. Attempted TUN
input can exceed link speed because much of it never reaches the encrypted
transport. It must not be reported as tunnel throughput.

Restricting Alice also changes Tokio's default worker count, so this is a resource
sensitivity check rather than isolated core scaling. The generator shares Alice's
CPU/kernel resources with GotaTun; this measures that complete local pipeline,
not pure encryption capacity. The direct reference and actual offered rate help
check generator headroom but do not eliminate contention from the generator.

## Interpretation

This is a promising upload workload: the long kernel-drop trials had about 0.9%
sample SD relative to their mean, while demonstrating that Bob's userspace can do
no receiving at all. More repetitions and checks across revisions/settings are
needed before treating it as a stable regression benchmark.

It is a UDP experiment, not an apples-to-apples speedup over TCP iperf or the
synthetic download workload. Checksums, traffic production, pacing and kernel work
differ. Longer input, rather than simply using a more aggressive offered rate, is
useful: short maximum-load results varied considerably more, especially in the
one-CPU control.

Raw studies and a [CSV summary](results/upload/summary.csv) are under
`results/upload/`. Every study records its source SHA, settings, all samples and
CPU observation windows. CPU counts only Alice's GotaTun process, across threads,
including the short drain tail; it excludes the generator and unrelated kernel work.
No experiment results are automatically published to Bencher.

Five local tests and Clippy pass. Live upload cancellation stopped the generator,
endpoint, TUN and peer in under a second; an occupied UDP port failed cleanly,
preserved the unrelated listener, and left no TUN. No global sysctls/NIC settings
or main/review/upstream branches were changed.
