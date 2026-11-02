#!/usr/bin/env python3
"""Summarize complete experimental studies; requires only Python's standard library."""
import argparse
import collections
import csv
import json
import math
import statistics
from pathlib import Path


def summarize(files):
    for file in files:
        study = json.loads(file.read_text())
        if study["status"] != "success":
            raise ValueError(f"{file}: incomplete or failed study")
        groups = collections.defaultdict(list)
        payload = study["settings"]["payload"]
        for trial in study["trials"]:
            groups[trial["mode"], trial["requested_payload_gbps"]].append(trial)
        for (mode, rate), trials in groups.items():
            # Older experimental reports used only the sender window. Recompute
            # from the preserved raw spans so all studies use the same definition.
            delivered = [
                t["receiver"]["unique"] * payload * 8 / 1e9
                / max(t["sender"]["send_seconds"], t["receiver"]["arrival_span_seconds"])
                for t in trials
            ]
            assert all(math.isfinite(value) for value in delivered)
            assert all(t["receiver"]["invalid"] == 0 for t in trials)
            cpu_cost = [t["gotatun_cpu_seconds_per_payload_gigabit"] for t in trials
                        if t.get("gotatun_cpu_seconds_per_payload_gigabit") is not None]
            missing = [t["receiver"].get("missing_per_100k_packets") for t in trials]
            has_breakdown = all(blocks is not None for blocks in missing)
            yield {
                "study": file.stem,
                "mode": mode,
                "packets_per_trial": study["settings"]["packets"],
                "send_batch": study["settings"]["batch"],
                "requested_payload_gbps": rate,
                "samples": len(trials),
                "offered_mean_gbps": statistics.mean(t["sender"]["offered_payload_gbps"] for t in trials),
                "delivered_mean_gbps": statistics.mean(delivered),
                "delivered_sample_sd_gbps": statistics.stdev(delivered) if len(delivered) > 1 else "",
                "loss_mean_percent": statistics.mean(t["loss_percent"] for t in trials),
                "loss_max_percent": max(t["loss_percent"] for t in trials),
                "first_100k_missing_total": sum(blocks[0] for blocks in missing) if has_breakdown else "",
                "later_missing_total": sum(sum(blocks[1:]) for blocks in missing) if has_breakdown else "",
                "sender_seconds_mean": statistics.mean(t["sender"]["send_seconds"] for t in trials),
                "preparation_seconds_mean": statistics.mean(t["sender"]["prepare_seconds"] for t in trials),
                "sink_drop_total": sum(t["receiver"]["kernel_socket_drops"] for t in trials),
                "outer_drop_total": sum(t.get("gotatun_outer_socket_drops") or 0 for t in trials),
                "receive_buffer_bytes": trials[0].get("gotatun_receive_buffer_bytes") or "",
                "cpu_seconds_per_payload_gigabit_mean": statistics.mean(cpu_cost) if cpu_cost else "",
                "cpu_seconds_per_payload_gigabit_sample_sd": statistics.stdev(cpu_cost) if len(cpu_cost) > 1 else "",
                "source_sha": study["source_sha"],
                "capacity_outcome": (study.get("capacity_search") or {}).get("outcome", ""),
                "capacity_confirmed": (study.get("capacity_search") or {}).get("confirmed", ""),
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("studies", type=Path, nargs="+")
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    rows = list(summarize(args.studies))
    print("study | mode | requested | actual offered | delivered mean ± sample SD | loss % | sink drops")
    for row in rows:
        sd = row["delivered_sample_sd_gbps"]
        spread = f" ± {sd:.3f}" if sd != "" else ""
        print(f'{row["study"]} | {row["mode"]} | {row["requested_payload_gbps"]:g} | '
              f'{row["offered_mean_gbps"]:.3f} | {row["delivered_mean_gbps"]:.3f}{spread} | '
              f'{row["loss_mean_percent"]:.4f} | {row["sink_drop_total"]}')
    for file in args.studies:
        search = json.loads(file.read_text()).get("capacity_search")
        if search:
            print(f'{file.stem}: {search["outcome"]}; confirmed={search["confirmed"]}; '
                  f'passing={search["passing_lower_gbps"]}, failing={search["failing_upper_gbps"]} Gb/s')
    if args.csv:
        with args.csv.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=rows[0])
            writer.writeheader()
            writer.writerows(rows)


if __name__ == "__main__":
    main()
