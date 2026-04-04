---
name: code-scanner
description: Scans GitHub repos, PyPI/npm packages, zip archives, and local skill files for malicious code, supply-chain attacks, backdoors, and credential harvesting — using a disposable Docker sandbox so nothing from the target ever executes on the host. Trigger this skill whenever a user asks to check, scan, or review any code for safety: "is this safe to install?", "scan this repo", "check this GitHub link", "is this npm package malicious?", "is this PyPI package safe to pip install?", "review this code for malware", "should I run this script?", or any time a user pastes a GitHub URL or package name they seem uncertain about. Even without explicit "scan" language, use this skill whenever someone shares an unfamiliar repo or package and safety is implicitly in question.
compatibility: Requires Docker installed and running. Works on Linux, macOS, and Windows (Docker Desktop with WSL2). Claude Code recommended for full automation; see Platform Notes at the bottom for Claude.ai.
---

# Code Scanner

Security analysis of a code repository in a fully disposable Docker sandbox. Nothing from the target touches the host filesystem, and the entire sandbox is destroyed when the scan completes.

**Before running any Docker commands, read `references/scan-commands.md`** — it contains all the exact Docker run templates and grep patterns for every step below.

---

## Step 1: Identify the Target

Extract the target from the user's message:
- GitHub repository URL (e.g. `https://github.com/owner/repo`)
- GitHub subdirectory URL (e.g. `https://github.com/owner/repo/tree/branch/subdir`)
- Direct link to a `.zip` or `.tar.gz` archive
- PyPI package with version (e.g. `litellm==1.82.8` or `pypi:litellm==1.82.8`)
- npm package with version (e.g. `npm:express@4.18.2`)
- Local path already downloaded
- Local path to a skill folder or `SKILL.md` file

> **Source repo ≠ published package.** Scanning a GitHub repository does not validate the corresponding PyPI or npm artifact. Supply chain attacks (like the March 2026 LiteLLM compromise) inject malicious code only into the published package while leaving the source repo clean. When evaluating whether a package is safe to `pip install` or `npm install`, always scan the artifact directly using the PyPI/npm targets above — not the GitHub source.

If the target is a skill folder or `SKILL.md`, follow the **skill scanning** path (Step 4b). Skill scanning checks for prompt injection, dangerous embedded commands, and data exfiltration instructions in addition to the standard suite.

If no target is provided, ask: "Please provide the GitHub repository URL, package name, or archive link you'd like me to scan."

Also check for a `--security-review` flag. If present, set `FORCE_SECURITY_REVIEW=true` — this overrides the default of skipping the Claude Code review when HIGH or CRITICAL findings are present.

Confirm Docker is available:
```bash
docker info > /dev/null 2>&1 && echo "Docker available" || echo "Docker not running — please start Docker Desktop or the Docker daemon"
```

---

## Step 1b: Pre-flight Size Check

Before creating the sandbox, check download size. **Do not proceed if the target exceeds 2 GB. Warn and ask the user to confirm if it exceeds 500 MB.** Use the commands in `references/scan-commands.md` → "Size Check" section.

Interpret results:
- **< 500 MB** — proceed
- **500 MB – 2 GB** — warn and wait for confirmation
- **> 2 GB** — stop: ask the user to clone locally and provide the local path
- **Size unavailable** (rate-limited or no `Content-Length`) — warn and ask to confirm

For local skill files, skip this check — they are always small.

---

## Step 2: Set Up the Docker Sandbox

Create a named Docker volume (repo content stays inside, never touches the host) and a host-side output directory for the report only.

```bash
SCAN_ID="codescan-$(date +%s)"
docker volume create "$SCAN_ID"
OUTPUT_DIR="$(pwd)/codescan-reports"
mkdir -p "$OUTPUT_DIR"
```

Then download the target using the appropriate command from `references/scan-commands.md` → "Download Commands":
- GitHub repo → sparse or full clone
- Archive URL → curl + extract
- PyPI package → `pip download --no-deps`
- npm package → `npm pack`
- Local skill files → volume copy

All downloads strip execute bits from files inside the volume after copying.

---

## Step 3: Map the Repository

Run the structure overview command from `references/scan-commands.md` → "Structure Map" with `--network none`. Before continuing, identify:

1. **Language(s)** — from extensions and manifests (`package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`, `Gemfile`, `pyproject.toml`)
2. **Entry points** — `main.*`, `index.*`, `__main__.py`, `Makefile`, CI/CD configs
3. **Install hooks** — scan these first:
   - `package.json`: `scripts.postinstall`, `scripts.preinstall`, `scripts.install`
   - `setup.py` / `pyproject.toml`: `cmdclass` overrides, custom build commands
   - `.github/workflows/` — actions triggered on push/PR

Report this map to the user before proceeding.

---

## Step 4: Static Analysis — Scan for Malicious Patterns

All analysis runs with `--network none`. See `references/patterns.md` for the full pattern library and severity guidance.

**OSV Scanner** — run first (requires brief network access to query the OSV API; only dependency metadata is sent, no repo code). Use the command in `references/scan-commands.md` → "OSV Scanner".

**dep-scan** — run alongside OSV (also requires network access to query registry APIs). Checks every declared dependency for supply chain attack indicators that go beyond known vulnerabilities:
- **Typosquatting** — package names similar to popular packages (Levenshtein distance)
- **Package age** — recently published packages (< 48 hours)
- **Maintainer changes** — ownership transfers or takeovers since last scan
- **Dependency confusion** — internal-looking names on public registries
- **Malicious install scripts** — eval, exec, child_process, subprocess in hooks

Requires the `dep-scan:latest` Docker image (build once — see `references/scan-commands.md` → "Dependency Supply Chain Analysis"). If the image is not available, skip this step and note "dep-scan not available — dependency supply chain analysis skipped" in the report.

For each flagged dependency, record severity (dep-scan `block` → HIGH, `warn` → MEDIUM), the triggering policy, the package name and version, and a plain-English explanation.

**Standard scan suite** — run the four batched containers from `references/scan-commands.md` → "Standard Scan Suite". They cover, in priority order:
1. Install hooks — run automatically without user action
2. Download-and-execute — fetching and running remote code
3. Obfuscation — encoded payloads, eval/exec of encoded strings
4. Credential harvesting — env vars, SSH keys, cloud credentials
5. Reverse shells / C2
6. Cryptominer indicators
7. Data exfiltration
8. Privilege escalation and persistence

For every finding, record:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Category**: threat type
- **Location**: file path and line number
- **Evidence**: exact code snippet
- **Explanation**: what the code does and why it is dangerous

---

## Step 4b: Skill-Specific Analysis

Run when the target is a skill file or folder — in addition to the standard suite above.

Skill files are markdown documents that instruct Claude how to behave. The threat here is manipulation of Claude itself rather than execution of malicious binaries. Run the five checks from `references/scan-commands.md` → "Skill-Specific Checks":

1. Prompt injection keywords
2. Data exfiltration instructions
3. Credential access instructions
4. Dangerous embedded commands
5. Permission and identity claims

See `references/patterns.md` Category 9 for the full pattern library and severity guidance.

---

## Step 5: Classify Embedded URLs

From the URL list collected in the scan, classify each as:
- **Known safe** — npm, PyPI, crates.io, GitHub, major CDNs, documentation hosts
- **Suspicious** — unknown domains, bare IP addresses, URL shorteners, high-entropy domains
- **Download targets** — URLs ending in `.sh`, `.py`, `.exe`, `.bin`, `.ps1`, `.tar.gz`, `.zip` or passed to `eval`/`exec`/`bash`/`python`

---

## Step 6: Inspect Secondary Payloads

For each **suspicious** or **download target** URL, fetch it into the volume (not the host) and analyze it using the commands in `references/scan-commands.md` → "Secondary Payload Inspection". Repeat up to **depth 2**.

If a URL is unreachable, flag it UNVERIFIED — an inaccessible URL in an install hook is itself suspicious.

---

## Step 7: Write the Report

Compose the report using the structure in `references/report-template.md`. Then write it:

```bash
REPORT_FILE="${OUTPUT_DIR}/scan-report-$(date +%Y%m%d-%H%M%S).md"
cat > "$REPORT_FILE" << 'REPORT'
<FULL REPORT CONTENT>
REPORT
echo "Report saved: $REPORT_FILE"
```

Every CRITICAL and HIGH finding must include the exact code snippet, file path with line number, and a plain-English explanation of what would happen if the code ran.

---

## Step 8: Claude Code Security Review (conditional)

Uses Claude Code's built-in analysis to review source files directly. Runs after the sandbox-based analysis so it only adds signal — it never sees code already confirmed malicious.

**Run this step if:**
- No CRITICAL or HIGH findings were found in Steps 4–6, OR
- The user included `--security-review` (`FORCE_SECURITY_REVIEW=true`)

**Skip if:**
- CRITICAL or HIGH findings exist and `FORCE_SECURITY_REVIEW` is not set
- Running in Claude.ai or any environment without Claude Code shell access

The gate exists because exporting code to the host when the repo is already confirmed malicious serves no purpose. The `--security-review` flag lets the user override this for research purposes.

### Export, review, and clean up

Use the export command from `references/scan-commands.md` → "Step 8 Export" to copy files to a temp directory. The `chmod -R a+rX` inside the container is essential — Docker-created files are root-owned and unreadable by the host user without this step.

Read key source files with your file tools and check for:
- **SQL injection** — string concatenation into queries, unparameterised inputs
- **XSS** — unsanitised output to HTML, unsafe `innerHTML` / `dangerouslySetInnerHTML`
- **Auth flaws** — missing auth checks, hardcoded credentials, insecure session handling
- **Insecure data handling** — unvalidated input, unsafe deserialisation, cleartext secrets

Append findings to the report, then clean up using the cleanup command from `references/scan-commands.md` → "Step 8 Cleanup". The cleanup uses `find /cleanup -mindepth 1 -delete` inside the container — plain `rm -rf /cleanup/*` skips hidden directories like `.git` which are root-owned and cause permission errors on the host.

---

## Step 9: Destroy the Sandbox

```bash
docker volume rm "$SCAN_ID"
echo "Sandbox destroyed. Report: $REPORT_FILE"
```

The report `.md` file is the only artifact that remains.

---

## Behavioral Rules

- Never execute any downloaded code, even to test it
- All analysis containers must use `--network none` except the download step, OSV scanner, dep-scan, and secondary payload fetch
- All containers must use `--security-opt no-new-privileges`
- Do not use `--cap-drop ALL` — dropping `CAP_DAC_READ_SEARCH` prevents reading volume files with restrictive permission bits, causing grep to silently return no results. Isolation is maintained by `--network none`, `--security-opt no-new-privileges`, and non-executable files.
- When exporting to the host for Step 8, always run `chmod -R a+rX` inside the container first — Docker files are root-owned and may be unreadable otherwise
- When cleaning up the temp directory, use a Docker container to delete root-owned files — plain `rm -rf` from the host will fail with permission denied on `.git` and similar directories
- If a file cannot be read (encrypted, corrupted), flag it UNVERIFIED
- Do not dismiss a finding as "probably fine" without a specific technical reason
- When in doubt, escalate severity rather than downgrade
- Always destroy the volume in Step 9

---

## Platform Notes: Claude.ai

In Claude.ai you cannot run Docker directly. Provide these setup commands for the user to run on their machine:

```bash
SCAN_ID="codescan-$(date +%s)"
docker volume create "$SCAN_ID"
mkdir -p ./codescan-reports
docker run --rm --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" alpine:latest \
  sh -c "apk add -q git && git clone --depth=1 <URL> /scan/repo && \
         find /scan/repo -type f -exec chmod ugo-x {} \;"
echo "SCAN_ID=$SCAN_ID"
```

Then provide each analysis command one at a time and ask the user to paste the output back. All commands in `references/scan-commands.md` work the same — the user runs them instead of Claude Code.
