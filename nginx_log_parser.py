import argparse
import contextlib
import json
import logging
import re
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

IP_PATTERN = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
TIMESTAMP_PATTERN = r"\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]"
DEFAULT_PUBLIC_THRESHOLD = 10
DEFAULT_PRIVATE_THRESHOLD = None


@dataclass
class LogRecord:
    ip: str
    count: int
    ip_type: str  # "public" / "private"
    suspicious: bool
    geo: dict = field(default_factory=dict)
    timestamps: list[datetime] = field(default_factory=list)


def extract_valid_ips(line: str) -> list[str]:
    candidates = re.findall(IP_PATTERN, line)
    valid = []
    for ip_str in candidates:
        octets = ip_str.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            valid.append(ip_str)
    return valid


def is_private(ip: str) -> bool:
    try:
        parts = ip.split(".")
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        return a == 192 and b == 168
    except ValueError:
        return False


def is_suspicious(
    ip: str,
    count: int,
    threshold_public: int,
    threshold_private: int | None,
) -> bool:
    if is_private(ip):
        return threshold_private is not None and count >= threshold_private
    return count >= threshold_public


def get_geo(ip: str) -> dict | None:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,city,org,status"
        with urllib.request.urlopen(url, timeout=3) as response:  # nosec B310
            data = json.loads(response.read())
            if data["status"] == "success":
                return {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "org": data.get("org"),
                }
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError):
        return None
    return None


def extract_timestamp(line: str) -> datetime | None:
    match = re.search(TIMESTAMP_PATTERN, line)
    if match is None:
        return None
    raw = match.group(1)
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")


def parse_log_file(
    path: str,
    threshold_public: int = DEFAULT_PUBLIC_THRESHOLD,
    threshold_private: int | None = DEFAULT_PRIVATE_THRESHOLD,
) -> list[LogRecord]:
    """
    Reads the nginx log and returns the LogRecord list.
    Lines without a valid timestamp are skipped — they cannot
    participate in the rate-based analysis. This is a deliberate limitation,
    not a bug.
    """

    ip_data: dict[str, list[datetime]] = {}

    with open(path, encoding="utf-8") as f:
        for line in f:
            ts = extract_timestamp(line)
            for ip in extract_valid_ips(line):
                if ip not in ip_data:
                    ip_data[ip] = []
                if ts is not None:
                    ip_data[ip].append(ts)

    records = []
    for ip, timestamps in sorted(
        ip_data.items(), key=lambda x: len(x[1]), reverse=True
    ):
        if not timestamps:
            continue
        count = len(timestamps)
        records.append(
            LogRecord(
                ip=ip,
                count=count,
                ip_type="private" if is_private(ip) else "public",
                suspicious=is_suspicious(
                    ip, count, threshold_public, threshold_private
                ),
                timestamps=timestamps,
            )
        )
    return records


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="IP address analyzer for nginx logs")
    p.add_argument("--file", required=True, help="Path to nginx log file")
    p.add_argument("--output", help="Save report to file. Recommended: .ndjson.")
    p.add_argument(
        "--threshold_public",
        help="Request count threshold for suspicious public IP (default: 10).",
    )
    p.add_argument(
        "--threshold_private",
        help="Request count threshold for suspicious private IP. Disabled by default.",
    )
    return p


def main() -> None:
    args = _build_arg_parser().parse_args()

    threshold_public = int(args.threshold_public or DEFAULT_PUBLIC_THRESHOLD)
    threshold_private = int(args.threshold_private) if args.threshold_private else None

    records = parse_log_file(args.file, threshold_public, threshold_private)

    private_count = sum(1 for r in records if r.ip_type == "private")
    public_count = sum(1 for r in records if r.ip_type == "public")

    for record in records:
        if record.suspicious and record.ip_type == "public":
            geo = get_geo(record.ip)
            if geo:
                record.geo = geo
            time.sleep(1.5)

    report = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "total_requests": private_count + public_count,
            "private": private_count,
            "public": public_count,
        },
        "top_ips": [
            {
                "ip": r.ip,
                "count": r.count,
                "type": r.ip_type,
                "suspicious": r.suspicious,
                **({"geo": r.geo} if r.geo else {}),
            }
            for r in records
        ],
    }

    if args.output:
        with open(args.output, "a", encoding="utf-8") as f:
            f.write(json.dumps(report, ensure_ascii=False) + "\n")
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
