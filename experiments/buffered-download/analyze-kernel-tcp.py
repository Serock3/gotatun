#!/usr/bin/env python3
"""Validate and summarize complete kernel-peer TCP studies (standard library only)."""
import argparse
import collections
import csv
import json
import math
import statistics
from pathlib import Path


def rows(files):
    for file in files:
        study = json.loads(file.read_text())
        if study["status"] != "success":
            raise ValueError(f"{file}: study did not complete successfully")
        assert study["direction"] in ("upload", "download") and study["measured_host"] == "alice"
        sender = study["direction"] == "upload"
        groups = collections.defaultdict(list)
        for trial in study["trials"]:
            raw = trial["iperf"]
            start = raw["start"]["test_start"]
            local = raw["end"]["sum_sent" if sender else "sum_received"]
            field = "alice_payload_gbps" if "alice_payload_gbps" in trial else "receiver_payload_gbps"
            assert start["protocol"] == "TCP" and start["reverse"] == int(not sender)
            assert start["num_streams"] == 1
            assert start["duration"] == study["settings"]["duration"]
            assert start["omit"] == study["settings"]["warmup"]
            assert local["sender"] is sender and local["bytes"] > 0
            assert abs(local["seconds"] - study["settings"]["duration"]) < 0.2
            assert math.isclose(trial[field], local["bits_per_second"] / 1e9)
            assert math.isclose(local["bits_per_second"], local["bytes"] * 8 / local["seconds"], rel_tol=1e-5)
            assert trial["cpu_window_seconds"] >= study["settings"]["duration"] + study["settings"]["warmup"] - 0.2
            assert (trial["alice_gotatun_cpu_percent"] is None) == (trial["case"] == "kernel_kernel")
            assert all(interval["sum"].get("sender", False) is sender for interval in raw["intervals"])
            groups[trial["case"]].append(trial)
        assert set(groups) == set(study["settings"]["cases"])
        for case, trials in groups.items():
            assert sorted(t["repetition"] for t in trials) == list(range(1, study["settings"]["repetitions"] + 1))
            rates = [t["alice_payload_gbps"] if "alice_payload_gbps" in t else t["receiver_payload_gbps"] for t in trials]
            mean = statistics.mean(rates)
            sd = statistics.stdev(rates) if len(rates) > 1 else None
            cpu = [t["alice_gotatun_cpu_percent"] for t in trials if t["alice_gotatun_cpu_percent"] is not None]
            retransmits = [t["sender_retransmits"] for t in trials if t["sender_retransmits"] is not None]
            yield {
                "study": file.stem,
                "case": case,
                "direction": study["direction"],
                "samples": len(trials),
                "duration_seconds": study["settings"]["duration"],
                "omitted_warmup_seconds": study["settings"]["warmup"],
                "mtu": study["mtu"],
                "mss_values": ",".join(str(v) for v in sorted({t["iperf"]["start"]["tcp_mss_default"] for t in trials})),
                "throughput_mean_gbps": mean,
                "throughput_sample_sd_gbps": sd if sd is not None else "",
                "throughput_cv_percent": sd / mean * 100 if sd is not None else "",
                "throughput_median_gbps": statistics.median(rates),
                "throughput_min_gbps": min(rates),
                "throughput_max_gbps": max(rates),
                "alice_gotatun_cpu_mean_percent": statistics.mean(cpu) if cpu else "",
                "alice_iperf_cpu_mean_percent": statistics.mean(t["alice_iperf_cpu_percent"] for t in trials),
                "sender_retransmits_total": sum(retransmits) if retransmits else "",
                "source_sha": study["source_sha"],
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("studies", type=Path, nargs="+")
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    results = list(rows(args.studies))
    print("study | direction | Alice/Bob case | samples | Alice Gb/s mean ± sample SD | CV % | Alice GotaTun CPU % | sender retransmits")
    for row in results:
        sd = row["throughput_sample_sd_gbps"]
        spread = f" ± {sd:.3f}" if sd != "" else ""
        cv = row["throughput_cv_percent"]
        cv_text = f"{cv:.2f}" if cv != "" else ""
        cpu = row["alice_gotatun_cpu_mean_percent"]
        cpu_text = f"{cpu:.1f}" if cpu != "" else ""
        print(f'{row["study"]} | {row["direction"]} | {row["case"]} | {row["samples"]} | '
              f'{row["throughput_mean_gbps"]:.3f}{spread} | {cv_text} | '
              f'{cpu_text} | {row["sender_retransmits_total"]}')
    if args.csv:
        with args.csv.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=results[0])
            writer.writeheader()
            writer.writerows(results)


if __name__ == "__main__":
    main()
