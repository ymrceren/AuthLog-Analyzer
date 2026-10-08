import argparse
import json
import re
from collections import Counter
from pathlib import Path

FAILURE_MARKERS = [
    "failed password",
    "failed publickey",
    "authentication failure"
]

IP_PATTERN = re.compile(
    r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b"
)


def analyze_log(file_path, threshold):
    counts = Counter()
    total_failures = 0

    with open(file_path, "r", encoding="utf-8",
              errors="replace") as file:
        for line in file:
            line_lower = line.lower()

            if not any(marker in line_lower
                       for marker in FAILURE_MARKERS):
                continue

            total_failures += 1
            match = IP_PATTERN.search(line)

            if match:
                counts[match.group(1)] += 1

    suspicious = {
        ip: count
        for ip, count in counts.items()
        if count >= threshold
    }

    return {
        "total_failed_events": total_failures,
        "unique_source_ips": len(counts),
        "failures_by_ip": dict(counts.most_common()),
        "potentially_suspicious_ips": suspicious
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Linux authentication logs."
    )
    parser.add_argument(
        "--file", required=True,
        help="Path to the log file"
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Failure count threshold"
    )
    parser.add_argument(
        "--json", help="Optional JSON report path"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    try:
        report = analyze_log(args.file, args.threshold)
    except OSError as error:
        parser.error(str(error))

    print("\n=== AuthLog Analyzer ===")
    print("Failed events:", report["total_failed_events"])
    print("Unique source IPs:", report["unique_source_ips"])

    print("\nPotentially suspicious sources:")
    if report["potentially_suspicious_ips"]:
        for ip, count in report[
            "potentially_suspicious_ips"
        ].items():
            print(f"{ip}: {count} failed attempts")
    else:
        print("No IP reached the configured threshold.")

    if args.json:
        Path(args.json).write_text(
            json.dumps(report, indent=2),
            encoding="utf-8"
        )
        print("\nJSON report saved:", args.json)


if __name__ == "__main__":
    main()