#!/usr/bin/env python3
"""Summarize upload studies using Alice's local transport output as the primary metric."""
import argparse
import collections
import csv
import json
import statistics
from pathlib import Path


def rows(files):
    for file in files:
        study = json.loads(file.read_text())
        if study["status"] != "success" or study["direction"] != "upload":
            raise ValueError(f"{file}: expected a completed upload study")
        groups = collections.defaultdict(list)
        for trial in study["trials"]:
            groups[trial["mode"], trial["requested_payload_gbps"]].append(trial)
        for (mode, rate), trials in groups.items():
            values = [t["local_output_payload_gbps"] for t in trials]
            output_packets = [t["local_output"]["packets"] if t["local_output"]
                              else t["offered"]["packets"] for t in trials]
            peer_received = [t["peer_drain"].get("received_datagrams",
                             t["peer_drain"]["packets"] + t["peer_drain"]["duplicates"])
                             for t in trials]
            yield {
                "study": file.stem,
                "mode": mode,
                "requested_payload_gbps": rate,
                "samples": len(trials),
                "input_loops": study["settings"].get("input_loops", 1),
                "peer_kernel_drop": study["settings"].get("peer_kernel_drop", False),
                "offered_mean_gbps": statistics.mean(t["offered"]["offered_payload_gbps"] for t in trials),
                "output_mean_gbps": statistics.mean(values),
                "output_sample_sd_gbps": statistics.stdev(values) if len(values) > 1 else "",
                "local_output_packets_total": sum(output_packets),
                "nic_packets_total": sum(t["nic_delta"]["tx_packets"] for t in trials),
                "nic_tx_dropped_total": sum(t["nic_delta"]["tx_dropped"] for t in trials),
                "nic_tx_errors_total": sum(t["nic_delta"]["tx_errors"] for t in trials),
                "peer_received_total": sum(peer_received),
                "peer_socket_drops_total": sum(t["peer_drain"]["socket_drops"] for t in trials),
                "source_sha": study["source_sha"],
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("studies", type=Path, nargs="+")
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    results = list(rows(args.studies))
    print("study | mode | requested | offered | Alice output mean ± sample SD (Gb/s) | NIC minus local count | peer drops")
    for r in results:
        sd = r["output_sample_sd_gbps"]
        spread = f" ± {sd:.3f}" if sd != "" else ""
        print(f'{r["study"]} | {r["mode"]} | {r["requested_payload_gbps"]:g} | '
              f'{r["offered_mean_gbps"]:.3f} | {r["output_mean_gbps"]:.3f}{spread} | '
              f'{r["nic_packets_total"] - r["local_output_packets_total"]} | '
              f'{r["peer_socket_drops_total"]}')
    if args.csv:
        with args.csv.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=results[0])
            writer.writeheader()
            writer.writerows(results)


if __name__ == "__main__":
    main()
