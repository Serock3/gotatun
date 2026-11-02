# Paced download capacity experiment

This extends the precomputed-download experiment with longer fresh packet pools
and a repeated-trial search under an explicit loss budget. It remains separate
from the default TCP iperf benchmarks, Bencher publishing, and upstream review
branches. No product source code changes.

The final search **confirmed a 2.75 Gb/s offered-rate target** within the 0.1%
loss budget. The next tested rate, 2.875 Gb/s, failed. This is one confirmed
experimental bracket, not yet evidence of repeatability across independent
searches or days.

## Findings

| Pool / send batch / pacing | Search result | Confirmation or rejection |
| --- | --- | --- |
| 4 million packets / 64 / catch-up | Candidate 3.000 Gb/s; unstable | Confirmation worst loss 0.2067% |
| 4 million / 256 / catch-up | No passing lower bound | 2 Gb/s worst loss 0.1883% |
| 6 million / 64 / catch-up | Candidate 2.875 Gb/s; unstable | Confirmation worst loss 0.2198% |
| 6 million / 64 / no catch-up | **Confirmed 2.750 Gb/s**; 2.875 fails | All six accepted-rate trials lost 0.0087–0.0229% |

At the final accepted target, actual offered load was 2.747–2.749 Gb/s and
delivered payload was **2.748 ± 0.001 Gb/s** (mean ± sample SD across six complete
trials). Each train lasted about 21 seconds. All corrected encrypted trials had
zero payload-sink socket drops; GotaTun retained its normal receive-buffer cap.

The larger pool fits in Bob's RAM: four million packets occupy 5.056 GB and six
million occupy 7.584 GB. Larger send batches did not give a dependable low-loss
result in this small comparison; extending a pool and enlarging a burst are
different changes.

The default pacer can compensate for a scheduling delay with a catch-up burst.
The optional `--no-catch-up` policy instead resumes spacing batches from actual
batch starts. This removes accumulated catch-up debt, but does **not** guarantee
uniform packet spacing within a batch or prevent receiver scheduling stalls.
It also slightly reduces actual offered load, which is recorded and checked.

The pacing change did not eliminate loss spikes: a no-catch-up trial at 3 Gb/s
lost 0.4452%, and one at 2.875 Gb/s lost 0.1670%. A separate three-trial fixed-rate
no-catch-up study at 2.875 Gb/s passed, illustrating why separate confirmation is
valuable. We have not instrumented scheduler delays or causally established
which queues explain the spikes. Do not attribute every loss to Bob's pacing.

Both startup loss and later loss occurred. Averaging losses would hide important
failures: the final 2.875 Gb/s search point averaged 0.0725% loss, below the budget,
but one repetition exceeded it. Acceptance therefore uses the **worst complete
trial**, rather than the average. Larger pools alone did not make the near-limit
result stable.

## Method

Bob precomputes an entire pool of fresh authenticated WireGuard packets for each
new session, before measurement starts. He paces transmission over the real
10 Gb/s link. Alice uses normal GotaTun/AWS-LC, UDP/GRO, TUN, and kernel delivery
to a local UDP sink. Each packet contains 1200 bytes of application payload.

The search requires **every one of three complete trials** at a rate to stay at
or below **0.1% payload loss**, bisects the passing/failing rate bracket to at
most 0.125 Gb/s, and runs three additional trials at the best passing rate. A
failed confirmation is explicitly reported as unstable. Bounds assume an
approximately monotonic loss boundary; they are not confidence intervals.

The generator must maintain the requested rate within 1%. Any payload-sink
socket drops or duplicate/invalid payload invalidate the measurement. Normal
GotaTun outer-socket drops count against its receive-path result. Throughput uses
unique delivered payload divided by the greater of sender duration and local
arrival span, including any post-send draining.

The approach is inspired by [RFC 2544's throughput
search](https://www.rfc-editor.org/rfc/rfc2544.html#section-26.1), but this is **not
an RFC 2544 compliance test**: we permit a specified nonzero loss budget, use
shorter trials, and test a software VPN path with this particular packet size.

## Measurement correction

Initial trials with the ordinary payload-sink buffer occasionally dropped packets
at that final sink. Those searches were rejected and retained as
`batch-64-wide-invalid.json` and `batch-64-narrow-invalid.json`, not counted as
valid capacity searches.

The corrected condition raises **only the owned payload-sink socket** to an
8 MiB requested buffer (16 MiB actual Linux accounting), via a short-lived sudo
helper before measurement. The descriptor is safely inherited from the
controller; the helper exits immediately. The buffer disappears when the socket
closes. GotaTun retains its normal 7 MiB request, capped to **425,984 bytes actual**
by the existing host limit. Neither global sysctls nor NIC settings change.

The direct-UDP controls maintained approximately 6 Gb/s with zero payload loss
in all nine trials, including the larger pool/no-catch-up policy and the larger
send batch. This establishes useful sender/link headroom for the tested rates;
it does not prove that every post-TUN receive stage has unlimited capacity.

The sink also computes missing-packet counts in sequence blocks of 100,000 after
receiving, using its existing received-packet bitmap. This adds no per-packet work
to the receive loop and lets us distinguish early loss from loss across a train.

## Interpretation and limits

Pool size and send batch size are separate: a larger pool extends the trial;
a larger `sendmmsg` batch reduces syscall frequency but makes larger bursts.
Encrypted pools are never replayed. The memory guard limits pools to 8 GiB and
half of Bob's currently available RAM, whichever is smaller. Pools are freed
between trials.

All trials include startup; there is no excluded traffic warmup. Loss near the
budget may therefore reflect startup and occasional scheduling stalls, as well
as sustained receive capacity. The sequence-block breakdown is diagnostic, not
used to discard unfavorable samples. Offered traffic is paced per batch, and
the default pacing can catch up after a scheduling delay; the alternate policy
does not accumulate that debt.

These are small, sequential exploratory studies, not randomized comparisons.
Both hosts keep their existing `powersave` governors. The payload sink shares
Alice's CPU/kernel resources with GotaTun, and zero sink drops alone does not
prove it has no performance cost. CPU figures cover only Alice's GotaTun process,
including the short observation/drain tail. The workload uses IPv4 UDP with a
zero inner UDP checksum; it is not an apples-to-apples comparison with TCP iperf.

## Reproduce

Build the isolated workspace, then run the example in the README. Study commands
take the shared Benchy machine lock. A result file is updated after every trial,
including completed samples from failed searches. Source SHAs are in each file.
No results from this experiment are automatically uploaded to Bencher.

Summarize completed studies with Python's standard library:

```bash
python3 analyze.py results/capacity/direct-64.json \
  results/capacity/direct-256.json results/capacity/direct-6m-no-catch-up.json \
  results/capacity/batch-64.json results/capacity/batch-256.json \
  results/capacity/pool-6m-batch-64.json \
  results/capacity/no-catch-up-2.875.json \
  results/capacity/no-catch-up-search.json --csv results/capacity/summary.csv
python3 verify-capacity.py
```

The CSV includes worst loss (the acceptance criterion), throughput sample SD,
trial durations, and early/later missing-packet counts. Raw rejected diagnostic
studies are retained separately and intentionally refused by the summary script.
The verifier checks raw counts, rate/window calculations, missing-block sums,
recorded socket sizes, and every search decision, and writes validation metadata.
Execution status `success` means the study completed: inspect `confirmed` and
`outcome` to distinguish a confirmed bracket from an unstable or out-of-range
result.

The practical next step before adoption is to repeat complete searches and check
whether the accepted bracket moves. Receiver startup, per-batch burstiness and
queue/scheduler behavior remain possible contributors. The ordinary TCP iperf
benchmarks remain the merge candidates; this exploration does not block them.

## Validation and final state

Eight Rust tests and Clippy with `-D warnings` pass. The data verifier checked all
80 completed trials, including the retained rejected studies. Live interruption
during a large-pool trial wrote a failed result and released the owned endpoint,
sender, payload socket, TUN interface, and machine lock. The final metadata records
no remaining experimental listeners/processes on either host, unchanged global
receive-buffer limits, and an active Alice runner service. Bob's RAM was released
and swap use remained zero. Main/review branches and upstream repositories were
untouched; all experiment changes are on `experiment/download-capacity` in the
test fork.
