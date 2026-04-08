# nginx_log_parser

A lightweight CLI tool for extracting and analyzing IP addresses from nginx access logs.
Detects suspicious activity, classifies public and private addresses, and enriches flagged IPs with geolocation data.

---

## Features

- Two-stage IP validation: regex pattern matching + octet range verification (0–255)
- Private/public IP classification (RFC 1918: `10.x`, `172.16–31.x`, `192.168.x`)
- Configurable suspicion thresholds for public and private IPs independently (threshold counts total requests per log file, not per minute)
- Geolocation lookup via [ip-api.com](http://ip-api.com) for suspicious public IPs
- NDJSON output — one line per run, append mode, ready for log rotation and automation
- Timestamps per report entry for historical analysis with `jq`

---

## Requirements

Python 3.10+ — standard library only, no external dependencies.

---

## Usage

**Full configuration:**
```bash
python nginx_log_parser.py --file nginx.log --output report.ndjson --threshold_public 10 --threshold_private 50
```

**Public IPs only (private threshold disabled):**
```bash
python nginx_log_parser.py --file nginx.log --output report.ndjson --threshold_public 10
```
Private IPs will appear in the report but `suspicious` will always be `false`.

**Defaults only:**
```bash
python nginx_log_parser.py --file nginx.log --output report.ndjson
```
Default: public threshold = 10, private threshold = disabled.

**Console output only (no file):**
```bash
python nginx_log_parser.py --file nginx.log
```

---

## Flags

| Flag                  | Required |  Default |               Description                            |
|-----------------------|----------|----------|------------------------------------------------------|
| `--file`              |    Yes   |    —     | Path to nginx log file                               |
| `--output`            |    No    |    —     | Output file path. Recommended: `.ndjson`             |
| `--threshold_public`  |    No    |    10    | Min request count to flag a public IP as suspicious  |
| `--threshold_private` |    No    | disabled | Min request count to flag a private IP as suspicious |

---

## Output format

Reports are written in **NDJSON** (Newline Delimited JSON) — one JSON object per line.
Each run appends a new line to the output file. Suitable for `logrotate`, Filebeat, and similar tools.

Note: actual output is single-line NDJSON. The example above is formatted for readability.

```json
{
  "timestamp": "2026-03-24T23:28:33",
  "summary": {
    "total_requests": 5,
    "private": 2,
    "public": 3
  },
  "top_ips": [
    {
      "ip": "185.220.101.45",
      "count": 2,
      "type": "public",
      "suspicious": true,
      "geo": {
        "country": "Germany",
        "city": "Brandenburg",
        "org": "ForPrivacyNET"
      }
    },
    {
      "ip": "192.168.1.10",
      "count": 1,
      "type": "private",
      "suspicious": false
    }
  ]
}
```

`geo` field is only present for suspicious public IPs.

---

## Reading reports with jq

```bash
# Last run, pretty-printed
tail -1 report.ndjson | jq .

# All suspicious IPs across all runs
cat report.ndjson | jq '.top_ips[] | select(.suspicious == true)'

# Suspicious IPs from last run with geolocation
tail -1 report.ndjson | jq '.top_ips[] | select(.geo != null)'

# Summary for each run
cat report.ndjson | jq '{timestamp, summary}'
```
---

## Docker & Security

This tool is distributed as a hardened, non-root Docker image. It follows security best practices:
- **Rootless execution**: Runs as UID `10001`.
- **Minimal privileges**: No capabilities, no new privileges escalations.
- **Read-only FS**: The container's filesystem is locked.
- **Supply Chain Security**: Images are signed with **Cosign** and include **SLSA** provenance.

### Running with Docker Compose (Recommended)

The `docker-compose.yml` is included in the repository.
Clone the repo, place your log file, and run:
```bash
docker-compose up
```

**File Contents:**
```yaml
services:
  parser:
    build: .
    image: nginx_log_parser:v1.0.0
    user: "10001:10001"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    environment:
      - LOG_SOURCE=data/current.log
      - OUTPUT_FORMAT=ndjson
      - THRESHOLD_PUB=30
      - THRESHOLD_PRIV=100
    read_only: true
    tmpfs:
      - /tmp
    deploy:
      resources:
        limits:
          memory: 512M
    volumes:
      - ${LOG_SOURCE:-./data/current.log}:/data/input.log:ro
      - ./reports:/reports:rw
    command: >
      --file /data/input.log  --output /reports/report.${OUTPUT_FORMAT}  --threshold_public ${THRESHOLD_PUB} --threshold_private ${THRESHOLD_PRIV}
```
---

### Default run
```bash
docker-compose up
```
---

### Custom log file
The log file path inside the container is always `/data/input.log`.
Use `LOG_SOURCE` to specify which file from the host to mount there:
```bash
# Relative path (file inside project directory)
LOG_SOURCE=data/your_log.log docker-compose up

# Absolute path (any file on host)
LOG_SOURCE=/var/log/nginx/access.log docker-compose up
```
---

### Running with Docker CLI
```bash
docker run --rm \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  -v $(pwd)/logs:/data:ro \
  -v $(pwd)/reports:/reports:rw \
  nginx_log_parser:v1.0.0 \
  --file /data/input.log --output /reports/result.ndjson
```
---

## Installation & Setup
1. **Clone the repository**:
```bash
git clone https://github.com/WisePepper-tech/nginx_log_parser.git
cd nginx_log_parser
```
---

2. **Local Development (venv)**:
```bash
python3 -m venv venv
source venv/bin/activate  # or source venv/Scripts/activate
pip install -r requirements-dev.txt
```
---

3. **Building the Secure Docker Image**:
Since this project uses Supply Chain Protection, dependencies are pre-downloaded (vendored) before the build.

**Step A: Download wheels (if not present)**
```bash
mkdir -p wheels
pip download -r requirements-dev.txt -d wheels --require-hashes
```
---

**Step B: Build the image**
```bash
docker build \
  --network=none \
  --pull=true \
  --build-arg PIP_FIND_LINKS=/app/wheels \
  -t nginx_log_parser:local .
```
---

Note: --network=none ensures no external code is downloaded during the build process, satisfying strict security audits.

---

### Quick Start (Docker)
The easiest way to run the parser is via Docker Compose. It handles volume mounting and security flags automatically.

Prepare your logs: Place your access.log in a directory named logs/.

**Run the parser**:
```bash
# Analyze default logs/current.log and save to reports/
docker-compose up
```
---

**Advanced Docker Usage**
You can override default settings using environment variables without modifying the docker-compose.yml:

| Goal              | Command                                    |
|-------------------|--------------------------------------------|
| Custom log file   | `LOG_SOURCE=my_nginx.log docker-compose up`|
| Change threshold  | `THRESHOLD_PUB=50 docker-compose up`       |

## Maintenance & CI/CD
This project uses Ruff for linting and Pytest for logic verification.

**Run linting**
```bash
ruff check .
```
---

**Run tests with coverage**
```bash
pytest --cov=. --cov-report=term-missing
```
---

**Security Verification**
You can verify the integrity of the official images using Cosign:
```bash
cosign verify \
  --certificate-identity-regexp="https://github.com/WisePepper-tech/*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ghcr.io/wisepepper-tech/nginx_log_parser:latest
```

## Log Rotation (Optional)
To prevent the NDJSON report from growing indefinitely, you can use `logrotate`. 
Create `/etc/logrotate.d/nginx_log_parser`:

```text
/absolute/path/to/reports/*.ndjson {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```
---

## Disclaimer

This project is licensed under the **MIT License**.

Geolocation data is provided by [ip-api.com](http://ip-api.com) (free tier, no API key required, 45 req/min limit).

This tool is intended for authorized use only — analyzing logs on systems you own or have explicit permission to monitor. The author is not responsible for any misuse or damage caused by unauthorized use of this tool.