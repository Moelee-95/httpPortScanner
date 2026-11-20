# Security Port Scanner

A dependency-free command-line TCP scanner for authorized exposure reviews. Requires **Python 3.10+** on Windows, Linux, or macOS. No administrator privileges or pip packages are required.

## Quick start

From the project directory:

```console
py run.py
```

Running without arguments starts interactive setup. It asks for the target, ports, optional HTTP/TLS checks, concurrency, timeout, address family, display preferences, and optional report file. Press Enter to accept each default; Ctrl+C cancels setup. Invalid entries are prompted again. On systems without the Windows `py` launcher, use `python run.py`.

You can also pass options directly:

```console
python run.py 127.0.0.1
python run.py localhost -p 22,80,443,8000-8100 --web
python run.py https://localhost:8443 --web
```

Scan only systems you own or have explicit permission to assess. Scans generate connections and may trigger monitoring or affect fragile services.

## Features

- TCP connect scanning with bounded workers and a bounded work queue.
- Common ports by default, custom port lists/ranges, or all 65,535 TCP ports.
- Hostnames, IPv4, IPv6, and HTTP(S) target URLs.
- Optional HTTP `HEAD /` probes, including responses such as 401, 403, and 404.
- HTTPS certificate and hostname validation, negotiated TLS version/cipher, and certificate expiration metadata.
- Review hints for exposed remote-access/data services and missing browser security headers.
- JSON and CSV exports containing every completed port result.
- Ctrl+C stops scheduling new work and writes completed results when an output file is specified.

## Usage

```console
python run.py --help
python run.py 127.0.0.1 --all-ports --workers 32 --timeout 0.5
python run.py 127.0.0.1 -p 8000 --web --scheme http
python run.py 127.0.0.1 -p 8443 --web --scheme https
python run.py ::1 --family 6 -p 22,80,443
python run.py localhost -p 22,80,443 --web -o scan.json
python run.py localhost -p 1-1024 --show-all --format csv -o scan.csv
```

| Option | Behavior |
| --- | --- |
| `-p`, `--ports` | Comma-separated ports and inclusive ranges; duplicates removed |
| `--all-ports` | Ports 1–65535; cannot combine with `--ports` |
| `-w`, `--workers` | Concurrent probes, 1–256; default 64 |
| `-t`, `--timeout` | Per socket-operation timeout, 0.1–30 seconds; default 1.5 |
| `--web` | Enable HTTP checks on recognized web ports |
| `--scheme auto` | HTTP on recognized web ports; HTTPS on 443 and 8443 |
| `--scheme http/https` | With `--web`, probe every open selected port using that protocol |
| `--family auto/4/6` | Address family; auto uses the resolver's first address |
| `-o`, `--output` | Write a report; overwrites an existing file |
| `--format json/csv` | Report format, default JSON; independent of filename extension |
| `--show-all` | Print non-open results too; reports always include all completed results |

A URL's explicit port becomes the default selection. Otherwise the common-port list is used, even with a URL. Explicit `--ports` or `--all-ports` overrides the URL port. The URL scheme does not override `--scheme`; use `--scheme https` for TLS on a custom port. Targets must have no credentials, path (except `/`), query, or fragment. One resolved IP is pinned for the scan; the original hostname is used for HTTP Host and TLS SNI/validation. Use an explicit IP to inspect other addresses.

## Understanding results

- **open**: a TCP handshake succeeded. Service names are local port-number mappings, not verified software identification.
- **closed**: the connection was refused.
- **timeout**: no connection completed within the timeout; this does not establish whether a firewall filtered the port.
- **error**: another network/OS error occurred; inspect the attached error.

HTTP/TLS probe errors leave the port marked open. Untrusted, expired, or mismatched TLS certificates are reported without disabling verification or retrying insecurely. Redirects are not followed, and no response body is downloaded. A HEAD response may differ from a normal page response.

Exposure hints and missing headers are review prompts, **not confirmed vulnerabilities**. Header relevance depends on the application. This tool does not detect CVEs, test credentials, exploit services, scan UDP, inspect every TLS configuration, or replace a dedicated vulnerability assessment.

The timeout applies to individual socket operations, not the entire scan or DNS resolution. Web probes add another connection and several operations. Ctrl+C may wait for active probes to finish; results completed before the interrupt was handled are exported, with `interrupted: true` and requested/completed counts in JSON. CSV contains per-port rows only; JSON also contains scan metadata. Keep reports private: they describe network exposure and may contain server-provided headers.

Exit codes: `0` completed without TCP scan errors (findings and web probe errors do not change this), `1` TCP scan error or report write failure, `2` invalid arguments/resolution failure, `130` interrupted. Write failure takes priority over interruption.

## Development

```console
python -m unittest -v
python -m compileall -q run.py test_scanner.py
```

Tests use loopback services and mocks; they do not contact external hosts. Coverage includes input validation, refused connections, timeouts/errors, TLS verification failure handling, HTTP error statuses, CLI integration, and report serialization.
