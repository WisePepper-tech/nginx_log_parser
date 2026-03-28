import argparse
import contextlib
import json
import logging
import re
import time
import urllib.request
from datetime import datetime

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

IP_PATTERN = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
DEFAULT_PUBLIC_THRESHOLD = 10
DEFAULT_PRIVATE_THRESHOLD = None


def extract_valid_ips(line: str) -> list[str]:
    candidates = re.findall(IP_PATTERN, line)
    valid = []
    for ip_str in candidates:
        octets = ip_str.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            valid.append(ip_str)
    return valid


def is_private(ip):
    try:
        parts = ip.split(".")
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        return a == 192 and b == 168
    except ValueError:
        return None


def get_geo(ip):
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


def is_suspicious(ip, count, threshold_public, threshold_private):
    if is_private(ip):
        return threshold_private is not None and count >= threshold_private
    else:
        return count >= threshold_public


def log(message, file=None):
    logger.info(message)
    if file:
        file.write(message + "\n")


def main():
    parser = argparse.ArgumentParser(description="IP address analyzer for nginx logs")
    parser.add_argument("--file", required=True, help="Path to nginx log file")
    parser.add_argument("--output", help="Save report to file. Recommended: .ndjson.")
    parser.add_argument(
        "--threshold_public",
        help=(
            "Request count threshold for suspicious public IP detection (default: 10)."
            "Threshold counts total requests per log file, not per minute."
        ),
    )
    parser.add_argument(
        "--threshold_private",
        help=(
            "Request count threshold for suspicious private IP detection. "
            "Optional, disabled by default. "
            "Threshold counts total requests per log file, not per minute."
        ),
    )
    args = parser.parse_args()

    threshold_public = (
        int(args.threshold_public)
        if args.threshold_public
        else DEFAULT_PUBLIC_THRESHOLD
    )
    threshold_private = int(args.threshold_private) if args.threshold_private else None

    private_count = 0
    public_count = 0
    ip_counts = {}
    report = {}

    with contextlib.ExitStack() as json_file:
        output_file = (
            json_file.enter_context(open(args.output, "a", encoding="utf-8"))
            if args.output
            else None
        )

        with open(args.file, encoding="utf-8") as f:
            for line in f:
                ips = extract_valid_ips(line)
                if ips:
                    for ip in ips:
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
                        result = is_private(ip)
                        if result is True:
                            private_count += 1
                            log(f"{ip} -> private")
                        elif result is False:
                            public_count += 1
                            log(f"{ip} -> public")
                else:
                    log(f"could not extract IP: {line.strip()}")

            report = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "summary": {
                    "total_requests": private_count + public_count,
                    "private": private_count,
                    "public": public_count,
                },
                "top_ips": [
                    {
                        "ip": ip,
                        "count": count,
                        "type": "private" if is_private(ip) else "public",
                        "suspicious": is_suspicious(
                            ip, count, threshold_public, threshold_private
                        ),
                    }
                    for ip, count in sorted(
                        ip_counts.items(), key=lambda x: x[1], reverse=True
                    )
                ],
            }

            for entry in report["top_ips"]:
                if entry["suspicious"] and entry["type"] == "public":
                    geo = get_geo(entry["ip"])
                    if geo:
                        entry["geo"] = geo
                    time.sleep(1.5)

            if args.output:
                output_file.write(json.dumps(report, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
