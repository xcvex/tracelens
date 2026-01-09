# TraceLens

🔍 **Enhanced Traceroute** with automatic network intelligence enrichment.

TraceLens is a cross-platform traceroute tool for **Windows** and **Linux** that automatically enriches each hop with:

- **ASN/Organization** information
- **Geographic location** with country flags
- **PTR (reverse DNS)** hostnames
- **Diagnostic tags** for ICMP filtering, latency jumps, and more

## Features

- 🌐 **Multi-protocol support**: ICMP, TCP, and UDP probing
- 📊 **Beautiful CLI output** with colors and emoji icons
- 🏷️ **Smart diagnostics**: Detects ICMP filtering, latency jumps, international egress
- 📁 **JSON export** for automation and reporting
- ⚡ **Fast parallel enrichment** with local caching
- 🔒 **No API keys required** - uses free public data sources

## Installation

```powershell
# Clone or download the project
cd d:\APP\TRACE

# Install dependencies
pip install -r requirements.txt
```

## Usage

> ⚠️ **Elevated privileges required**
>
> - **Windows**: Run PowerShell as Administrator
> - **Linux**: Run with `sudo`

### Basic Usage

```powershell
# ICMP trace (default)
python -m tracelens 8.8.8.8

# TCP trace (bypasses ICMP filtering)
python -m tracelens 8.8.8.8 -p tcp --port 443

# UDP trace (Unix-style)
python -m tracelens 8.8.8.8 -p udp

# Trace hostname
python -m tracelens google.com
```

### Export to JSON

```powershell
python -m tracelens 8.8.8.8 --json output.json
```

### Options

| Option           | Default | Description                    |
| ---------------- | ------- | ------------------------------ |
| `-p, --protocol` | icmp    | Probe protocol: icmp, tcp, udp |
| `--port`         | 80      | Port for TCP/UDP probes        |
| `-m, --max-hops` | 30      | Maximum number of hops         |
| `-q, --probes`   | 3       | Probes per hop                 |
| `-w, --timeout`  | 2.0     | Timeout per probe (seconds)    |
| `--dns/--no-dns` | enabled | Enable/disable PTR lookups     |
| `--geo/--no-geo` | enabled | Enable/disable geo lookups     |
| `--json FILE`    | -       | Export results to JSON file    |
| `--no-cache`     | -       | Disable caching                |

## Output Example

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  🔍 TraceLens v1.0.0                                                         │
│  Target: 8.8.8.8                                                             │
│  Protocol: ICMP  |  Probes: 3 × 30 hops                                      │
╰──────────────────────────────────────────────────────────────────────────────╯

╭─ 📍 Route to 8.8.8.8 ────────────────────────────────────────────────────────╮
│  #   RTT (min/avg/max)    IP               ASN        Organization     ...   │
│ ─────────────────────────────────────────────────────────────────────────────│
│  1   1 / 2 / 3            192.168.1.1      -          -                🏠    │
│  2   5 / 6 / 8            100.64.0.1       -          -                🔒    │
│  3   * / * / *            -                -          -                ⚠️    │
│  4   12 / 14 / 15         202.97.94.1      AS4134     China Telecom    🇨🇳   │
│ ...                                                                          │
╰──────────────────────────────────────────────────────────────────────────────╯

╭─ 📊 Summary ─────────────────────────────────────────────────────────────────╮
│  ✅ Target Reachable: 10 hops, 45ms avg                                      │
│  ⚠️ ICMP Filtering: hops 3, 6                                                │
│  🚀 Latency Jump: +85ms at hop 5                                             │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Diagnostic Tags

| Tag                    | Icon | Meaning                                        |
| ---------------------- | ---- | ---------------------------------------------- |
| `private`              | 🏠   | RFC1918 private IP (10.x, 172.16.x, 192.168.x) |
| `cgnat`                | 🔒   | Carrier-grade NAT (100.64.x)                   |
| `icmp_filtered`        | ⚠️   | ICMP blocked but route continues               |
| `latency_jump`         | 🚀   | Significant RTT increase (≥80ms)               |
| `international_egress` | 🌏   | Large jump suggesting international transit    |
| `high_jitter`          | 📈   | High RTT variance within hop                   |
| `destination`          | ✅   | Final destination reached                      |

## Data Sources

- **ASN/Organization**: [Team Cymru](https://www.team-cymru.com/ip-asn-mapping) (DNS-based, free)
- **Geolocation**: [ip-api.com](https://ip-api.com/) (free tier)

## Cache

Enrichment data is cached locally at `~/.tracelens/cache.json` with 7-day TTL.

## Requirements

### Windows

- Windows 10/11
- Python 3.10+
- Administrator privileges

### Linux

- Any modern Linux distribution
- Python 3.10+
- Root privileges (`sudo`)

## Building Executables

### Local Build

```powershell
# Install PyInstaller
pip install pyinstaller

# Build executable (Windows)
python build.py

# Or manually
pyinstaller tracelens.spec
```

The executable will be created in the `dist/` directory.

### Automated Builds (GitHub Actions)

Push a version tag to trigger automatic builds:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This creates releases with:

- `tracelens-windows-x64.zip` - Windows executable
- `tracelens-linux-x64.tar.gz` - Linux x64 binary
- `tracelens-linux-arm64.tar.gz` - Linux ARM64 binary

## Development

```powershell
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Build locally
python build.py
```

## Project Structure

```
tracelens/
├── probe/          # ICMP/TCP/UDP probing engines
├── enrichment/     # ASN, GeoIP, PTR lookups
├── output/         # Console and JSON output
├── cli.py          # Command-line interface
├── cache.py        # JSON file cache
├── diagnostics.py  # Network issue detection
└── models.py       # Data structures
```

## License

MIT
