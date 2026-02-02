# YARA REST

[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/EclipseFdn/yara-rest)](go.mod)
[![License](https://img.shields.io/badge/License-EPL2.0-blue.svg)](LICENSE.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](Dockerfile)

An internal HTTP service for scanning files with [YARA-X](https://virustotal.github.io/yara-x/) rules. Designed for use behind a reverse proxy or within a private network.

> **Warning:** This service has no authentication. Do not expose it to the public internet. Deploy behind a firewall or internal network only.

## Features

- **Simple REST API** — Upload files via multipart form, get JSON results
- **Archive Support** — Automatically extracts and scans ZIP archives
- **Zip Bomb Protection** — Configurable limits on file count, size, and extraction
- **Security Hardened** — Non-root user, HTTP timeouts, sanitized logging, OpenShift compatible
- **Fully Configurable** — All limits and timeouts via environment variables
- **Health Checks** — Built-in endpoint for liveness/readiness probes

## Quick Start

```bash
# Build and run with Docker
docker build -t yara-rest .
docker run -d -p 9001:9001 -v /path/to/rules:/rules:ro yara-rest

# Test it
curl http://localhost:9001/health
curl -X POST -F "file=@archive.zip" http://localhost:9001/scan
```

## API

### `POST /scan`

Upload a file for YARA-X scanning. Accepts single files or ZIP archives.

```bash
# Scan a single file
curl -X POST -F "file=@suspicious.js" http://localhost:9001/scan

# Scan a ZIP archive (extracts and scans all contents)
curl -X POST -F "file=@package.zip" http://localhost:9001/scan
```

**Response:**

```json
{
  "matches": [
    {
      "rule": "EICAR_Test_Signature",
      "file": "eicar.txt",
      "file_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "severity": "LOW",
      "description": "Detects the EICAR antivirus test file"
    }
  ],
  "scanned_files": 1,
  "scan_time_ms": 45
}
```

### `GET /health`

Health check endpoint. Returns `200 OK` when ready.

```json
{"status": "ok", "rules_path": "/rules"}
```

## Configuration

All settings are configurable via environment variables:

### Server Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `9001` | HTTP server port |
| `YARA_RULES_PATH` | `/rules` | Directory containing `.yar` files |
| `LOG_LEVEL` | `info` | Log level (`info` or `debug`) |

### HTTP Timeouts

Prevents slowloris attacks and resource exhaustion from slow clients.

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_READ_TIMEOUT_SECONDS` | `60` | Max time to read entire request |
| `HTTP_WRITE_TIMEOUT_SECONDS` | `300` | Max time to write response |
| `HTTP_IDLE_TIMEOUT_SECONDS` | `120` | Max idle time for keep-alive |

### Size Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_UPLOAD_SIZE_MB` | `512` | Max upload size (multipart form) |
| `MAX_EXTRACTED_SIZE_MB` | `1024` | Max total extracted size |
| `MAX_FILE_COUNT` | `100000` | Max files in archive |
| `MAX_SINGLE_FILE_MB` | `256` | Max single file size |

### Scan Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_TIMEOUT_MINUTES` | `5` | Max time for YARA-X scan |
| `MAX_RECURSION` | `0` | Max directory recursion depth (0 = unlimited) |

## YARA-X Rules

Place `.yar` or `.yara` files in the rules directory. Subdirectories are scanned recursively.

Rules can include metadata for severity and description:

```yara
rule Example_Rule {
    meta:
        description = "Describes what this rule detects"
        severity = "high"
    
    strings:
        $suspicious = "malicious_pattern"
    
    condition:
        $suspicious
}
```

## Development

A Makefile is provided for common tasks:

```bash
make build        # Build the binary
make test         # Run unit tests
make test-verbose # Run tests with verbose output
make test-cover   # Run tests with coverage report
make fmt          # Format code
make vet          # Run go vet
make clean        # Remove build artifacts
```

### Building from Source

Requires Go 1.23+. YARA-X is only needed at runtime (in container).

```bash
make build
YARA_RULES_PATH=./test ./yara-rest
```

### Docker / Podman

```bash
make docker-build                # Build image
make docker-run                  # Run container
make docker-test                 # Build, run, and test

# Or with Podman
make podman-build
make podman-run
```

Manual commands:

```bash
docker build -t yara-rest .
docker run -d -p 9001:9001 -v ./rules:/rules:ro yara-rest
```

## Deployment

### OpenShift Compatibility

The container follows the **GID 0 pattern** for OpenShift compatibility:

- Files owned by `1001:0` (UID 1001, GID 0)
- Permissions allow group write (`ug+rwx`)
- Works with random UIDs assigned by OpenShift (always GID 0)

### Filesystem Requirements

| Path | Access | Purpose |
|------|--------|---------|
| `/tmp/scans` | Read-Write | Scan workspace |
| `/rules` | Read-Only | YARA-X rules |
| `/app` | Read-Only | Application binary |

Supports **read-only root filesystem** when `/tmp/scans` is mounted as a writable volume.

### Sizing `/tmp/scans`

Each concurrent scan needs temp space for the uploaded file and extracted contents:

```
tmp_size = (MAX_UPLOAD_SIZE_MB + MAX_EXTRACTED_SIZE_MB) × concurrent_scans
```

| Concurrent Scans | Volume Size |
|------------------|-------------|
| 1 | 1.5 GB |
| 5 | 7 GB |
| 20 | 30 GB |

Use **tmpfs** (memory-backed) for performance, or **disk** for high concurrency with limited RAM.

### Resource Limits

Recommended Kubernetes/OpenShift resource configuration:

```yaml
resources:
  limits:
    cpu: "2"
    memory: "2Gi"
  requests:
    cpu: "500m"
    memory: "512Mi"
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop:
      - ALL
```

For read-only root filesystem, mount a writable volume for scans:

```yaml
volumeMounts:
- name: scans
  mountPath: /tmp/scans
volumes:
- name: scans
  emptyDir: {}
```

### Resource Guidelines

| Traffic | Memory | CPU |
|---------|--------|-----|
| Low | 512Mi | 0.5 |
| High (20 concurrent) | 2Gi+ | 2+ |

## Testing

### Unit Tests

Run the test suite locally (no YARA-X required):

```bash
make test              # Run all tests
make test-cover        # Generate coverage report
```

Unit tests cover configuration, HTTP handlers, ZIP extraction, and output parsing. Integration tests that require YARA-X are automatically skipped when running locally.

### Integration Tests

Run full integration tests in container:

```bash
make docker-test
```

### Manual Testing

A test rule is included that detects the [EICAR test signature](https://www.eicar.org/):

```bash
docker run -d --name yara-test -p 9001:9001 -v $(pwd)/test:/rules:ro yara-rest

curl http://localhost:9001/health
curl -X POST -F "file=@test.zip" http://localhost:9001/scan

docker rm -f yara-test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the EPL 2.0 License — see [LICENSE.md](LICENSE.md) for details.
