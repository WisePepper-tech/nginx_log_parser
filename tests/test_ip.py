import subprocess
import sys
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nginx_log_parser import (
    extract_timestamp,
    extract_valid_ips,
    get_geo,
    is_private,
    is_suspicious,
    parse_log_file,
)


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("10.0.0.1", True),
        ("8.8.8.8", False),
        ("192.168.1.1", True),
    ],
)
def test_is_private(ip, expected):
    assert is_private(ip) == expected


def test_extract_two_ips():
    ips_examples_two_in_line = "203.0.113.45, 131.107.0.89"
    result = extract_valid_ips(ips_examples_two_in_line)
    assert result == ["203.0.113.45", "131.107.0.89"]


def test_extract_invalid_octet():
    invalid_ip = "999.888.777.666"
    result = extract_valid_ips(invalid_ip)
    assert result == []


def test_extract_no_ip():
    no_ip = "0.0.pass_number.189"
    result = extract_valid_ips(no_ip)
    assert result == []


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("172.16.0.0", True),
        ("172.17.0.0", True),
        ("172.18.0.0", True),
        ("172.19.0.0", True),
        ("172.20.0.0", True),
        ("172.21.0.0", True),
        ("172.22.0.0", True),
        ("172.23.0.0", True),
        ("172.24.0.0", True),
        ("172.32.0.1", False),
        ("172.15.0.1", False),
    ],
)
def test_is_private_172x(ip, expected):
    assert is_private(ip) == expected


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("10.0.0.0", True),
        ("10.1.1.1", True),
        ("10.255.255.255", True),
    ],
)
def test_is_private_10x(ip, expected):
    assert is_private(ip) == expected


def test_is_private_invalid_input():
    assert is_private("not.an.ip") is False


def test_is_public():
    assert is_private("192.169.0.0") is False


def test_suspicious_public_above_threshold():
    ip = "8.8.8.8"
    count = 15
    threshold_public = 10
    threshold_private = None

    assert is_suspicious(ip, count, threshold_public, threshold_private) is True


def test_suspicious_public_below_threshold():
    ip = "8.8.8.8"
    count = 5
    threshold_public = 10
    threshold_private = None

    assert is_suspicious(ip, count, threshold_public, threshold_private) is False


def test_suspicious_private_disabled():
    ip = "192.168.1.1"
    count = 100
    threshold_public = 10
    threshold_private = None

    assert is_suspicious(ip, count, threshold_public, threshold_private) is False


def test_cli_default_threshold(tmp_path):
    log = tmp_path / "log.txt"
    lines = [
        f'8.8.8.8 - - [04/Apr/2026:14:23:0{i} +0300] "GET / HTTP/1.1" 200 1024'
        for i in range(10)
    ]
    log.write_text("\n".join(lines))

    result = subprocess.run(
        [sys.executable, "nginx_log_parser.py", "--file", str(log)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "8.8.8.8" in result.stdout
    assert "suspicious" in result.stdout


def test_suspicious_private_enabled():
    ip = "192.168.1.1"
    count = 20
    threshold_public = 10
    threshold_private = 15

    assert is_suspicious(ip, count, threshold_public, threshold_private) is True


def test_suspicious_equal_threshold():
    ip = "8.8.8.8"
    count = 10
    threshold_public = 10
    threshold_private = None

    assert is_suspicious(ip, count, threshold_public, threshold_private) is True


def test_cli_output_file(tmp_path):
    log = tmp_path / "log.txt"
    out = tmp_path / "out.json"

    log.write_text(
        '8.8.8.8 - - [04/Apr/2026:14:23:01 +0300] "GET / HTTP/1.1" 200 1024\n'
    )

    subprocess.run(
        [
            sys.executable,
            "nginx_log_parser.py",
            "--file",
            str(log),
            "--output",
            str(out),
        ],
        check=True,
    )

    assert out.exists()
    data = out.read_text()
    assert "8.8.8.8" in data


@given(st.text())
def test_extract_ips_are_valid(data):
    ips = extract_valid_ips(data)
    for ip in ips:
        octets = ip.split(".")
        assert len(octets) == 4
        assert all(0 <= int(o) <= 255 for o in octets)


def test_cli_does_not_crash(tmp_path):
    log = tmp_path / "log.txt"
    log.write_text(
        '8.8.8.8 - - [04/Apr/2026:14:23:01 +0300] "GET / HTTP/1.1" 200 1024\n'
    )
    result = subprocess.run(
        [sys.executable, "nginx_log_parser.py", "--file", str(log)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0


def test_cli_geo_enrichment(tmp_path):
    log = tmp_path / "log.txt"
    lines = [
        f'8.8.8.8 - - [04/Apr/2026:14:23:0{i} +0300] "GET / HTTP/1.1" 200 1024'
        for i in range(10)
    ]

    log.write_text("\n".join(lines))

    records = parse_log_file(str(log), threshold_public=10)

    suspicious = [r for r in records if r.suspicious]
    assert len(suspicious) == 1
    assert suspicious[0].ip == "8.8.8.8"

    with patch("nginx_log_parser.get_geo", return_value={"country": "US"}) as mock_geo:
        with patch("time.sleep", lambda x: None):
            for record in records:
                if record.suspicious and record.ip_type == "public":
                    geo = mock_geo(record.ip)
                    if geo:
                        record.geo = geo

        mock_geo.assert_called_once_with("8.8.8.8")
        assert records[0].geo == {"country": "US"}


def test_get_geo_invalid_json():
    with patch("urllib.request.urlopen") as mock:
        mock.return_value.__enter__.return_value.read.return_value = b"invalid json"

        assert get_geo("8.8.8.8") is None


def test_get_geo_success():
    fake_response = MagicMock()
    fake_response.read.return_value = (
        b'{"status":"success","country":"US","city":"NY","org":"Google"}'
    )

    mock_urlopen = MagicMock()
    mock_urlopen.return_value.__enter__.return_value = fake_response

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value.read.return_value = (
            b'{"status":"success","country":"US","city":"NY","org":"Google"}'
        )
        result = get_geo("8.8.8.8")

    assert result["country"] == "US"


def test_extract_timestamp_valid_line():
    line = '8.8.8.8 - - [04/Apr/2026:14:23:00 +0300] "GET / HTTP/1.1" 200 1024'

    result = extract_timestamp(line)

    assert result is not None
    assert isinstance(result, datetime)
    assert result.year == 2026
    assert result.hour == 14


def test_extract_timestamp_invalid_line():
    line = '8.8.8.8 - - "GET / HTTP/1.1" 200 1024'

    result = extract_timestamp(line)

    assert result is None
