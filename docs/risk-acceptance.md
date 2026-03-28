# Risk Acceptance Log

## CVE-2026-4539 — pygments ReDoS
- **Date accepted:** 2026-03-28
- **Severity:** Low (CVSS 3.3)
- **Component:** pygments (`requirements-dev.txt`, `requirements-security.txt`)
- **Reason:** Local attack vector, affects pytest output rendering only,
  no production exposure
- **Fix available:** No
- **Review date:** When pygments patch released