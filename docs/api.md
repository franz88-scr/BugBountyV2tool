# REST API

ReconChain includes a lightweight REST API server for querying scan findings programmatically.

## Quick Start

```bash
# Start scan with API server
reconchain -d example.com --api-port 8080

# Query findings
curl http://127.0.0.1:8080/api/v1/findings
curl http://127.0.0.1:8080/api/v1/findings?severity=high
curl http://127.0.0.1:8080/api/v1/summary
```

## Endpoints

### Health Check
```
GET /api/v1/health
```
**Response:**
```json
{
  "status": "ok",
  "version": "3.0.0",
  "timestamp": "2025-01-01T00:00:00",
  "outdir": "/path/to/out/example.com"
}
```

### Scan Summary
```
GET /api/v1/summary
```
Returns the full scan summary including domain, tool chain, missing tools, artifact counts, and coverage metrics.

### Findings
```
GET /api/v1/findings
GET /api/v1/findings?severity=high
GET /api/v1/findings?phase=11-INJECT
GET /api/v1/findings?vuln_type=xss
GET /api/v1/findings?host=example.com
GET /api/v1/findings?limit=50&offset=0
```
**Query Parameters:**
| Parameter | Type | Description |
|---|---|---|
| `severity` | string | Filter by severity: critical, high, medium, low, info |
| `phase` | string | Filter by phase ID: 11-INJECT, 24-JWT, etc. |
| `vuln_type` | string | Filter by vulnerability type: xss, sqli, ssrf, etc. |
| `host` | string | Filter by affected host |
| `limit` | int | Max results (default: 500) |
| `offset` | int | Pagination offset |

**Response:**
```json
{
  "total": 42,
  "offset": 0,
  "limit": 500,
  "findings": [
    {
      "id": "RC-a1b2c3d4",
      "phase": "11-INJECT",
      "vuln_type": "xss",
      "severity": "high",
      "confidence": 0.8,
      "title": "Reflected XSS in /search",
      "evidence": "XSS at https://example.com/search?q=<script>alert(1)</script>",
      "url": "https://example.com/search?q=<script>alert(1)</script>",
      "host": "example.com",
      "cwe": "CWE-79",
      "cvss": 6.1
    }
  ]
}
```

### Findings by Category
```
GET /api/v1/findings/by-severity
GET /api/v1/findings/by-phase
GET /api/v1/findings/by-type
```
Returns findings grouped by the respective dimension.

### Coverage
```
GET /api/v1/coverage
```
```json
{
  "tested_phases": 45,
  "total_phases": 164,
  "coverage_pct": 27.4,
  "phases_with_output": ["01-RECON", "02-RESOLVE", ...]
}
```

### Artifacts
```
GET /api/v1/artifacts
```
Returns all artifacts with their counts, file sizes, and metadata.

## CORS

All endpoints include CORS headers (`Access-Control-Allow-Origin: *`) for browser-based dashboards and tools.

## Architecture

The API is built on Python's `http.server` module — zero external dependencies. It runs as a daemon thread alongside the main pipeline. The `FindingStore` class lazily loads findings from the output directory and caches them.

## Programmatic Usage

```python
from reconchain.api import start_api_server, stop_api_server
from pathlib import Path

port = start_api_server(Path("./out/example.com"), port=8080)
# API is now running on http://127.0.0.1:8080
stop_api_server()
```
