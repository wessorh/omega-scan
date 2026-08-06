# omega-scan

Holloman3 perceptual hash scanner with gRPC threat intelligence lookup. Computes compact 16-byte fingerprints from files or URLs and optionally queries a remote threat-intel server for malware family, category, and severity.

## Quick Start

```bash
# Build
make build

# Scan a file (local only, no server)
./bin/omega-scan scan /path/to/file

# Scan with threat lookup against a local server
./bin/omega-scan scan --server localhost:8443 --insecure /path/to/malware.exe

# Scan a directory with JSON output and statistics
./bin/omega-scan scan --json --stats /scratch/zoo/2026/0803/

# Use environment variables instead of flags
export DEWILE_SERVER=api.dewile.net:8443
export DEWILE_API_KEY=your-key-here
omega-scan scan /path/to/malware.exe

# Show version and machine ID
./bin/omega-scan version
```

## How It Works

1. **Fingerprint generation**: Input bytes are mapped onto a 2D Hilbert curve, downsampled via Lanczos-3 filtering to a fixed 4×4 grid, then rotated 90°. The result is a 16-byte (128-bit) perceptual hash.

2. **Cluster ID**: Fingerprints are prefixed with a Hilbert order character (e.g. `k.776967757067736e5a780e0658780000`) forming a compact, database-friendly identifier.

3. **Threat lookup** (optional): The cluster ID, SHA-1, and SHA-256 are sent to a gRPC threat-intelligence server which returns family, category, threat score, severity, and nearest-neighbor clusters.

## Command Reference

### `omega-scan scan [flags] <target...>`

Scans one or more files, directories, or URLs. Directories are recursed non-recursively (one level). Symlinks are skipped.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config` | string | | Path to TOML config file |
| `--server` | string | `api.dewile.net:8443` | gRPC threat-lookup server address |
| `--tls-ca` | string | | CA certificate PEM file (default: system roots) |
| `--tls-cert` | string | | Client certificate PEM file for mTLS |
| `--tls-key` | string | | Client key PEM file for mTLS |
| `--tls-server-name` | string | | Override TLS hostname check (use when connecting by IP to a named certificate) |
| `--insecure` | bool | `false` | Skip TLS verification entirely (for dev servers with self-signed certs) |
| `--api-token` | string | | API token for higher server rate limits |
| `--order` | int | `0` | Hilbert curve order (0 = auto-detect from file size) |
| `--threads` | int | `2` | Number of parallel scan workers |
| `--errors-as-warnings` | bool | `false` | Continue scanning directory after individual file errors |
| `--json` | bool | `false` | Output machine-readable JSON instead of tabular text |
| `--stats` | bool | `false` | Print aggregate statistics at exit (and on Ctrl+C) |
| `-v` | bool | `false` | Verbose: print machine ID to stderr |

### Environment Variables

Override defaults without flags or config files:

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `DEWILE_SERVER` | `--server` | gRPC server address (e.g. `api.dewile.net:8443`) |
| `DEWILE_API_KEY` | `--api-token` | API token for rate-limit tiers |

Priority: **command-line flag → environment variable → config file → built-in default**.

### `omega-scan version`

Prints the library version and machine ID.

## Configuration File

All flags can be set via a TOML config file. Command-line flags override file values. Copy `client.toml.example` to `client.toml` and edit:

```toml
[server]
address = "localhost:8443"
insecure = false
tls_server_name = ""
tls_ca = ""
tls_cert = ""
tls_key = ""

[auth]
api_token = ""

[scan]
order = 0          # 0 = auto-detect
threads = 2
errors_as_warnings = false

[output]
json = false
stats = false
verbose = false
```

## Example Output

### Tabular (default)

```
Path:                                      /scratch/zoo/2026/0803/00000e9d...
Size:                                      339968 bytes
SHA-1:                                     9ffff95662d13670b4de9f00257b33fe205a18dd
SHA-256:                                   81d6382e06b0e34f1cf533ae...
Cluster ID:                                k.19706f41000c562c0000030000000000
Order:                                     10
Elapsed:                                   12.827ms
Malicious:                                 true
Threat Score:                              100
Severity:                                  SEVERITY_CRITICAL
Family:
Category:                                  antivirus worm
```

### JSON (`--json`)

```json
{"path":"/scratch/zoo/2026/0803/00000e9d...","size":339968,"sha1":"9ffff...","sha256":"81d63...","cluster_id":"k.19706f...","order":10,"elapsed":"12.827ms"}
```

## Build Requirements

- Go 1.25+
- No CGO required — pure Go with Plan 9 assembly for AVX2 acceleration
- AVX2 support recommended (Intel Haswell 2013+ / AMD Zen 2017+) for optimal Hilbert curve generation

## Hilbert Orders

The Hilbert order is determined by file size and controls the grid dimension (2^order × 2^order). Hamming distance comparisons are only meaningful between fingerprints of the same order.

| Order | Char | Grid | Max file size |
|-------|------|------|---------------|
| 7 | h | 128×128 | 16 KB |
| 8 | i | 256×256 | 65 KB |
| 9 | j | 512×512 | 262 KB |
| 10 | k | 1024×1024 | 1 MB |
| 11 | m | 2048×2048 | 4 MB |
| 12 | n | 4096×4096 | 16 MB |
| 13 | o | 8192×8192 | 64 MB |

## Architecture

```
cmd/omega-scan/     CLI entry point
internal/
  fingerprint/      Hilbert curve + Lanczos-3 pipeline (AVX2 Plan 9 asm)
  scanner/          File, URL, and directory scanning
  threat/           gRPC client for OmegaScan.Lookup
  config/           TOML configuration
api/omega/v1/       Protobuf service definitions
```

## Related Projects

- [omega-server](https://github.com/wessorh/omega-server) — gRPC threat-intel server
- [holloman5](https://github.com/wessorh/yara-c-holloman3) — Reference C implementation
- [research](https://github.com/wessorh/research) — Large-scale Holloman3 evaluation toolkit
