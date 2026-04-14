---
name: code-scanner
description: Scans GitHub repos, PyPI/npm packages, zip archives, and local skill files for malicious code, supply-chain attacks, backdoors, and credential harvesting — using a disposable Docker sandbox so nothing from the target ever executes on the host. Trigger this skill whenever a user asks to check, scan, or review any code for safety: "is this safe to install?", "scan this repo", "check this GitHub link", "is this npm package malicious?", "is this PyPI package safe to pip install?", "review this code for malware", "should I run this script?", or any time a user pastes a GitHub URL or package name they seem uncertain about. Even without explicit "scan" language, use this skill whenever someone shares an unfamiliar repo or package and safety is implicitly in question.
compatibility: Requires Docker installed and running for remote targets (GitHub URLs, archives, PyPI/npm packages). Local paths scan natively without Docker. Works on Linux, macOS, and Windows (Docker Desktop with WSL2). Fully compatible with Docker Sandbox (sbx) environments — scanning containers run normally inside the microVM; ensure your network policy allows image pulls and API access (see Step 1). Claude Code recommended for full automation; see Platform Notes at the bottom for Claude.ai.
---

# Code Scanner

Security analysis of a code repository. Remote targets (URLs, packages) are downloaded into a fully disposable Docker sandbox — nothing from the target touches the host filesystem, and the entire sandbox is destroyed when the scan completes. Local paths already on disk are scanned in place with native tools; no sandbox is created because read-only text analysis of files that already exist on the host cannot execute anything.

**Before running any commands, read `references/scan-commands.md`** — it contains all the exact command templates and grep patterns for every step below, including a dedicated Local Mode section for local-path targets.

---

## Step 1: Identify the Target

Extract the target from the user's message:
- GitHub repository URL (e.g. `https://github.com/owner/repo`) — **remote**
- GitHub subdirectory URL (e.g. `https://github.com/owner/repo/tree/branch/subdir`) — **remote**
- Direct link to a `.zip` or `.tar.gz` archive — **remote**
- PyPI package with version (e.g. `litellm==1.82.8` or `pypi:litellm==1.82.8`) — **remote**
- npm package with version (e.g. `npm:express@4.18.2`) — **remote**
- Local path to a directory already on disk — **local**
- Local path to a skill folder or `SKILL.md` file — **local**

> **Source repo ≠ published package.** Scanning a GitHub repository does not validate the corresponding PyPI or npm artifact. Supply chain attacks (like the March 2026 LiteLLM compromise) inject malicious code only into the published package while leaving the source repo clean. When evaluating whether a package is safe to `pip install` or `npm install`, always scan the artifact directly using the PyPI/npm targets above — not the GitHub source.

**Set the mode**: if the target is a local path that already exists on disk, set `LOCAL_MODE=true` and `SCAN_ROOT="<absolute path to target>"`. In local mode the scan runs against the files in place — **no Docker sandbox is created, no volume, no download step**. The sandbox exists to prevent execution of code downloaded from untrusted sources; code already on the user's disk has already been present there, and read-only text analysis (grep, find) does not execute anything it reads. Skipping the sandbox makes local scans faster and avoids unnecessary Docker churn.

Otherwise set `LOCAL_MODE=false` — the remote target will be downloaded into a Docker sandbox volume (Step 2).

If the target is a skill folder or `SKILL.md`, follow the **skill scanning** path (Step 4b). Skill scanning checks for prompt injection, dangerous embedded commands, and data exfiltration instructions in addition to the standard suite. Skill paths on disk always use local mode.

If no target is provided, ask: "Please provide the GitHub repository URL, package name, archive link, or local path you'd like me to scan."

Also check for a `--security-review` flag. If present, set `FORCE_SECURITY_REVIEW=true` — this overrides the default of skipping the Claude Code review when HIGH or CRITICAL findings are present.

Confirm Docker is available **unless `LOCAL_MODE=true` and you will not run OSV Scanner or dep-scan** (both of those still use Docker as a tool runner, via a read-only bind mount of `SCAN_ROOT`).

Detect the isolation backend — prefer Docker Sandbox (`sbx`) when present:

```bash
if command -v sbx >/dev/null 2>&1; then
    echo "ISOLATION=sbx"
elif command -v docker >/dev/null 2>&1; then
    echo "ISOLATION=docker"
else
    echo "ISOLATION=none"
fi

# Verify Docker is functional (needed for remote targets and OSV/dep-scan)
docker info > /dev/null 2>&1 && echo "Docker available" || echo "Docker not running"
```

- **`ISOLATION=sbx`**: Docker Sandbox detected — scanning containers run normally inside the microVM. If scans fail to pull images or query APIs (OSV, dep-scan, PyPI, npm), your sbx network policy may be blocking them. Use the "Balanced" policy or add these domains to your allow list: `ghcr.io`, `registry-1.docker.io`, `production.cloudflare.docker.com`, `api.github.com`, `pypi.org`, `registry.npmjs.org`, `api.osv.dev`.
- **`ISOLATION=docker`**: Docker Engine available directly — the default path. All scan commands work as documented.
- **`ISOLATION=none`**: No container runtime found. Only pure local mode scans will work (no OSV, no dep-scan, no sandbox for remote targets). Tell the user: "Docker is not available — only local path targets can be scanned, and dependency checks (OSV Scanner, dep-scan) will be skipped."

In pure-local mode with no OSV/dep-scan, Docker is not required at all regardless of isolation backend.

---

## Step 1b: Pre-flight Size Check

**Skip this step entirely if `LOCAL_MODE=true`** — the user already has the files, so there is nothing to download. Run `du -sh "$SCAN_ROOT"` only if you want to report the size in the final report.

For remote targets, check download size before creating the sandbox. **Do not proceed if the target exceeds 2 GB. Warn and ask the user to confirm if it exceeds 500 MB.** Use the commands in `references/scan-commands.md` → "Size Check" section.

Interpret results:
- **< 500 MB** — proceed
- **500 MB – 2 GB** — warn and wait for confirmation
- **> 2 GB** — stop: ask the user to clone locally and provide the local path (which will use local mode and bypass this limit)
- **Size unavailable** (rate-limited or no `Content-Length`) — warn and ask to confirm

---

## Step 2: Set Up the Sandbox (remote targets only)

**Skip this step entirely if `LOCAL_MODE=true`.** Just ensure the output directory exists:

```bash
OUTPUT_DIR="$(pwd)/codescan-reports"
mkdir -p "$OUTPUT_DIR"
# SCAN_ROOT was set in Step 1 to the absolute local path
```

For remote targets, create a named Docker volume (repo content stays inside, never touches the host) and a host-side output directory for the report only.

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

All downloads strip execute bits from files inside the volume after copying.

---

## Step 3: Map the Repository

Run the structure overview command from `references/scan-commands.md`. In sandbox mode, use the "Structure Map" section (Docker, `--network none`). In local mode (`LOCAL_MODE=true`), use the equivalent from the "Local Mode Commands" section — native `find` against `$SCAN_ROOT`, no container. Before continuing, identify:

1. **Language(s)** — from extensions and manifests (`package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`, `Gemfile`, `pyproject.toml`)
2. **Entry points** — `main.*`, `index.*`, `__main__.py`, `Makefile`, CI/CD configs
3. **Install hooks** — scan these first:
   - `package.json`: `scripts.postinstall`, `scripts.preinstall`, `scripts.install`
   - `setup.py` / `pyproject.toml`: `cmdclass` overrides, custom build commands
   - `.github/workflows/` — actions triggered on push/PR

Report this map to the user before proceeding.

---

## Step 4: Static Analysis — Scan for Malicious Patterns

In sandbox mode, all analysis runs in Docker containers with `--network none` against the volume. In local mode, the same grep/find patterns run natively on the host against `$SCAN_ROOT`; no container is involved for the text-search steps. The "Local Mode Commands" section of `references/scan-commands.md` provides the native equivalents. See `references/patterns.md` for the full pattern library and severity guidance.

**OSV Scanner** — run first (requires brief network access to query the OSV API; only dependency metadata is sent, no repo code). Use the command in `references/scan-commands.md` → "OSV Scanner". In local mode, the same OSV container is used but it bind-mounts `$SCAN_ROOT` read-only instead of mounting the sandbox volume — see "Local Mode Commands" → "OSV Scanner (local)".

**dep-scan** — run alongside OSV (also requires network access to query registry APIs). Checks every declared dependency for supply chain attack indicators that go beyond known vulnerabilities:
- **Typosquatting** — package names similar to popular packages (Levenshtein distance)
- **Package age** — recently published packages (< 48 hours)
- **Maintainer changes** — ownership transfers or takeovers since last scan
- **Dependency confusion** — internal-looking names on public registries
- **Malicious install scripts** — eval, exec, child_process, subprocess in hooks

Uses the `dep-scan:latest` Docker image, which is **built automatically on first scan and after Dockerfile changes** — run the build/check block in `references/scan-commands.md` → "Build the dep-scan image" before invoking dep-scan. This step is mandatory; do not skip it. In local mode, the dep-scan container bind-mounts `$SCAN_ROOT` read-only — see "Local Mode Commands" → "dep-scan (local)". If the image build itself fails (network failure, Docker error), record the build error in the report and continue with the remaining scan steps.

For each flagged dependency, record severity (dep-scan `block` → HIGH, `warn` → MEDIUM), the triggering policy, the package name and version, and a plain-English explanation.

**Standard scan suite** — in sandbox mode, run the four batched containers from `references/scan-commands.md` → "Standard Scan Suite". In local mode, run the native equivalents from "Local Mode Commands" → "Standard Scan Suite (local)" — same patterns, run directly against `$SCAN_ROOT` with host `grep`/`find`. They cover, in priority order:
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

Skill files are markdown documents that instruct Claude how to behave. The threat here is manipulation of Claude itself rather than execution of malicious binaries. Run the five checks from `references/scan-commands.md` → "Skill-Specific Checks" (sandbox mode) or "Local Mode Commands" → "Skill-Specific Checks (local)" (local mode, which is the common case for skills):

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

**In local mode (`LOCAL_MODE=true`) skip the export and cleanup entirely** — the files are already on the host. Read them directly from `$SCAN_ROOT` using your file tools.

In sandbox mode, use the export command from `references/scan-commands.md` → "Step 8 Export" to copy files to a temp directory. The `chmod -R a+rX` inside the container is essential — Docker-created files are root-owned and unreadable by the host user without this step.

Read key source files with your file tools and check for:
- **SQL injection** — string concatenation into queries, unparameterised inputs
- **XSS** — unsanitised output to HTML, unsafe `innerHTML` / `dangerouslySetInnerHTML`
- **Auth flaws** — missing auth checks, hardcoded credentials, insecure session handling
- **Insecure data handling** — unvalidated input, unsafe deserialisation, cleartext secrets

Append findings to the report. In sandbox mode, clean up using the cleanup command from `references/scan-commands.md` → "Step 8 Cleanup". The cleanup uses `find /cleanup -mindepth 1 -delete` inside the container — plain `rm -rf /cleanup/*` skips hidden directories like `.git` which are root-owned and cause permission errors on the host. In local mode there is no temp directory to clean up.

---

## Step 9: Destroy the Sandbox

**In local mode, skip this step — there is no sandbox to destroy.** Just print the report path:

```bash
echo "Scan complete (local mode, no sandbox). Report: $REPORT_FILE"
```

In sandbox mode, remove the volume:

```bash
docker volume rm "$SCAN_ID"
echo "Sandbox destroyed. Report: $REPORT_FILE"
```

The report `.md` file is the only artifact that remains.

---

## Behavioral Rules

- Never execute any downloaded or local code, even to test it. In local mode, only ever run read-only tools (`grep`, `find`, `file`, `strings`, `cat`/Read) against `$SCAN_ROOT` — never `bash`, `python`, `node`, `make`, or anything that invokes an interpreter on target files.
- In sandbox mode, all analysis containers must use `--network none` except the download step, OSV scanner, dep-scan, and secondary payload fetch
- In sandbox mode, all containers must use `--security-opt no-new-privileges`
- In sandbox mode, do not use `--cap-drop ALL` — dropping `CAP_DAC_READ_SEARCH` prevents reading volume files with restrictive permission bits, causing grep to silently return no results. Isolation is maintained by `--network none`, `--security-opt no-new-privileges`, and non-executable files.
- In local mode, do not modify files under `$SCAN_ROOT` — no `chmod`, no writes, no deletions. The user's working copy must be left untouched.
- When exporting to the host for Step 8 (sandbox mode only), always run `chmod -R a+rX` inside the container first — Docker files are root-owned and may be unreadable otherwise
- When cleaning up the temp directory (sandbox mode only), use a Docker container to delete root-owned files — plain `rm -rf` from the host will fail with permission denied on `.git` and similar directories
- If a file cannot be read (encrypted, corrupted), flag it UNVERIFIED
- Do not dismiss a finding as "probably fine" without a specific technical reason
- When in doubt, escalate severity rather than downgrade
- In sandbox mode, always destroy the volume in Step 9. In local mode, there is nothing to destroy.

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
