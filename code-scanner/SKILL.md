---
name: code-scanner
description: Scans a code repository or archive for malicious code, suspicious patterns, and links to dangerous payloads. Use when a user asks to scan, check, or review a GitHub repo or zip file for safety, malware, supply-chain attacks, or malicious code. Triggers on phrases like "scan this repo", "is this safe to run", "check this GitHub link", "review this code for malware", or "is this package safe to install".
compatibility: Requires Docker installed and running. Works on Linux, macOS, and Windows (Docker Desktop with WSL2). Claude Code recommended for full automation; Claude.ai requires the user to run Docker commands manually.
---

# Code Scanner

You are performing a thorough security analysis of a code repository to determine whether it is safe to use. All analysis runs inside a disposable Docker container — nothing from the target repo ever touches the host filesystem, and the entire sandbox is destroyed when the scan completes.

## Step 1: Identify the Target

Extract the target from the user's message. It will be one of:
- A GitHub repository URL (e.g. `https://github.com/owner/repo`)
- A GitHub subdirectory URL (e.g. `https://github.com/owner/repo/tree/branch/subdir`)
- A direct link to a `.zip` or `.tar.gz` archive
- A local path the user has already downloaded
- A local path to a skill folder or `SKILL.md` file (e.g. `~/.claude/skills/some-skill/`)

If the target is a skill folder or `SKILL.md` file, follow the **skill scanning** path below. Skill scanning focuses on prompt injection, dangerous embedded commands, and data exfiltration instructions in addition to the standard pattern suite.

If no URL or path is provided, ask: "Please provide the GitHub repository URL or archive link you'd like me to scan."

Also check the user's message for the `--security-review` flag. If present, set `FORCE_SECURITY_REVIEW=true`. This overrides the default behaviour of skipping the Claude Code security review when HIGH or CRITICAL findings are present.

Confirm Docker is available before proceeding:
```bash
docker info > /dev/null 2>&1 && echo "Docker available" || echo "Docker not running — please start Docker Desktop or the Docker daemon"
```

---

## Step 1b: Pre-flight Size Check

Before creating the sandbox, check the download size. **Do not proceed if the target exceeds 2 GB. Warn and ask the user to confirm if it exceeds 500 MB.**

### GitHub repository or subdirectory URL

```bash
# Extract owner/repo from the URL and query the GitHub API
curl -s "https://api.github.com/repos/<OWNER>/<REPO>" \
  | grep '"size"' | head -1
# Size is returned in KB. Divide by 1024 for MB.
```

Interpret the result:
- **`size` missing or API rate-limited** — warn the user you could not verify the size, ask if they want to proceed
- **< 512000 KB (500 MB)** — proceed
- **512000–2097152 KB (500 MB – 2 GB)** — warn: *"This repo is approximately X MB. Scans on large repos can take several minutes and use significant disk space. Proceed?"* Wait for confirmation.
- **> 2097152 KB (2 GB)** — stop: *"This repo is approximately X GB, which exceeds the 2 GB scan limit. Please clone it locally and provide the local path instead."*

### Archive URL (zip / tar.gz)

```bash
# Check Content-Length header — no download occurs
curl -sI "<ARCHIVE_URL>" | grep -i content-length
# Value is in bytes. Divide by 1048576 for MB.
```

Apply the same 500 MB / 2 GB thresholds. If `Content-Length` is absent, warn the user and ask to confirm before proceeding.

### Local path

```bash
du -sh "<LOCAL_PATH>"
```

Apply the same thresholds. For skill files this check can be skipped — they are always small.

---

## Step 2: Set Up the Docker Sandbox

Create a named Docker volume and a dedicated output directory. **All repo content stays inside the volume — it never touches the host filesystem.**

```bash
# Generate a unique scan ID
SCAN_ID="codescan-$(date +%s)"
echo "Scan ID: $SCAN_ID"

# Create an isolated Docker volume for the repo
docker volume create "$SCAN_ID"

# Create a host-side output directory for the report only
OUTPUT_DIR="$(pwd)/codescan-reports"
mkdir -p "$OUTPUT_DIR"

echo "Volume: $SCAN_ID"
echo "Report output: $OUTPUT_DIR"
```

### Download into the volume (GitHub repo)

```bash
docker run --rm \
  --name "${SCAN_ID}-download" \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" \
  alpine:latest \
  sh -c "
    apk add -q git 2>/dev/null
    git clone --depth=1 <REPO_URL> /scan/repo 2>&1 | tail -3
    find /scan/repo -type f -exec chmod ugo-x {} \;
    find /scan/repo -type d -exec chmod ugo-rwx {} \;
    echo 'Download complete. Files made non-executable.'
  "
```

### Download into the volume (zip/tar archive)

```bash
docker run --rm \
  --name "${SCAN_ID}-download" \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" \
  alpine:latest \
  sh -c "
    apk add -q curl unzip tar 2>/dev/null
    curl -sL --max-filesize 524288000 '<ARCHIVE_URL>' -o /scan/archive
    file /scan/archive
    # Unzip or untar based on file type:
    unzip -q /scan/archive -d /scan/repo 2>/dev/null || tar -xf /scan/archive -C /scan/repo 2>/dev/null
    find /scan/repo -type f -exec chmod ugo-x {} \;
    find /scan/repo -type d -exec chmod ugo-rwx {} \;
    rm /scan/archive
    echo 'Download complete. Files made non-executable.'
  "
```

### For GitHub subdirectory URLs

Use sparse checkout to fetch only the relevant subtree:

```bash
docker run --rm \
  --name "${SCAN_ID}-download" \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" \
  alpine:latest \
  sh -c "
    apk add -q git 2>/dev/null
    git clone --depth=1 --filter=blob:none --sparse <REPO_ROOT_URL> /scan/repo 2>&1 | tail -3
    cd /scan/repo && git sparse-checkout set <SUBDIR_PATH>
    find /scan/repo -type f -exec chmod ugo-x {} \;
    find /scan/repo -type d -exec chmod ugo-rwx {} \;
    echo 'Sparse checkout complete.'
  "
```

### Copy local skill files into the volume

Use this when the target is a local skill folder or `SKILL.md` file:

```bash
docker run --rm \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" \
  -v "<LOCAL_SKILL_PATH>:/input:ro" \
  alpine:latest \
  sh -c "
    cp -r /input /scan/repo
    find /scan/repo -type f -exec chmod ugo-x {} \;
    echo 'Skill files copied.'
  "
```

Replace `<LOCAL_SKILL_PATH>` with the absolute path to the skill folder or file (e.g. `/home/user/.claude/skills/some-skill`).

---

### In Claude.ai (no shell access)

You cannot run Docker directly. Provide these instructions to the user:

```bash
# User runs this on their machine:
SCAN_ID="codescan-$(date +%s)"
docker volume create "$SCAN_ID"
mkdir -p ./codescan-reports

docker run --rm --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" alpine:latest \
  sh -c "apk add -q git && git clone --depth=1 <URL> /scan/repo && \
         find /scan/repo -type f -exec chmod ugo-x {} \;"

echo "SCAN_ID=$SCAN_ID"
```

Then ask the user to paste the output of each analysis command you provide.

---

## Step 3: Map the Repository

Run a structure overview **inside the volume, with no network access**:

```bash
docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" \
  alpine:latest \
  sh -c "
    echo '=== File count ==='
    find /scan/repo -type f | wc -l
    echo ''
    echo '=== Top-level structure ==='
    find /scan/repo -maxdepth 3 -not -path '*/.git/*' | sort | head -100
    echo ''
    echo '=== File types ==='
    find /scan/repo -type f -not -path '*/.git/*' | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -20
  "
```

Before continuing, identify:
1. **Language(s)** — from file extensions and manifest files (`package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`, `Gemfile`, `pyproject.toml`)
2. **Entry points** — `main.*`, `index.*`, `__main__.py`, `Makefile`, CI/CD configs
3. **Install hooks** — highest priority, check immediately:
   - `package.json`: `scripts.postinstall`, `scripts.preinstall`, `scripts.install`
   - `setup.py` / `pyproject.toml`: `cmdclass` overrides, custom build commands
   - `Makefile` `install` targets
   - `.github/workflows/` — actions triggered on push/PR
   - `Dockerfile`, `docker-compose.yml`

Report this map to the user before proceeding.

---

## Step 4: Static Analysis — Scan for Malicious Patterns

All analysis runs in containers with `--network none`. Consult `references/patterns.md` for the full pattern library.

### OSV Scanner — Known Vulnerability Check

Run this first. OSV Scanner checks all dependency manifests (`package-lock.json`, `go.sum`, `requirements.txt`, `Cargo.lock`, etc.) against the [Open Source Vulnerabilities](https://osv.dev) database. This requires brief network access to query the OSV API — only dependency metadata is sent, no repo code.

```bash
docker run --rm \
  --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" \
  ghcr.io/google/osv-scanner:latest \
  --recursive /scan/repo \
  --format json 2>/dev/null \
  | jq '.results[]?.packages[]? | {package: .package, vulns: [.vulnerabilities[]? | {id: .id, severity: (.severity // "UNKNOWN"), summary: (.summary // "")}]}' 2>/dev/null \
  || echo "No vulnerabilities found or OSV scan produced no output."
```

For every OSV finding, record severity as:
- **CRITICAL/HIGH** — CVSS 7.0+ or any vulnerability with a known exploit
- **MEDIUM** — CVSS 4.0–6.9
- **LOW** — CVSS below 4.0 or unscored

Include the CVE/GHSA ID, affected package and version, and the fix version if available.

For every finding, record:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Category**: threat type
- **Location**: file path and line number
- **Evidence**: exact code snippet
- **Explanation**: what the code does and why it is dangerous

### Priority order

1. **Install hooks** — run automatically without user action
2. **Download-and-execute** — fetching and running remote code
3. **Obfuscation** — encoded payloads, eval/exec of encoded strings
4. **Credential harvesting** — env vars, SSH keys, cloud credentials
5. **Reverse shells / C2**
6. **Cryptominer indicators**
7. **Data exfiltration**
8. **Privilege escalation**

### Analysis command template

Run each grep inside a `--network none` container. Repeat this pattern for each category:

```bash
docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" \
  alpine:latest \
  sh -c "grep -rn '<PATTERN>' /scan/repo --include='<GLOB>' 2>/dev/null | head -50"
```

### Standard scan suite

Run these in sequence:

```bash
# --- Download and execute ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEn 'curl.+\|.+sh|wget.+\|.+sh|bash\s*<\(curl|IEX.+Download|fetch.+exec' \
         /scan/repo 2>/dev/null | head -30"

# --- Obfuscation ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEn 'eval\(base64|exec\(base64|atob\(|fromCharCode|\\\\x[0-9a-f]{2}' \
         /scan/repo 2>/dev/null | head -30"

# --- Supply chain hooks (package.json) ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rn 'postinstall\|preinstall\|\"install\"' /scan/repo \
         --include='package.json' 2>/dev/null"

# --- Supply chain hooks (Python) ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rn 'cmdclass\|setup_requires\|CustomInstall\|subprocess' /scan/repo \
         --include='setup.py' --include='setup.cfg' 2>/dev/null"

# --- Credential harvesting ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEn 'process\.env\.|os\.environ|getenv\(|HOME.*\.ssh|\.aws/credentials|\.netrc' \
         /scan/repo 2>/dev/null | head -30"

# --- Reverse shells ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEn '/dev/tcp|/dev/udp|nc\s+-e|ncat.*-e|socat.*exec|bash\s+-i|sh\s+-i' \
         /scan/repo 2>/dev/null | head -30"

# --- Binary strings (for compiled/binary files) ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "apk add -q binutils 2>/dev/null
         find /scan/repo -type f | while read f; do
           ft=\$(file \"\$f\" 2>/dev/null)
           case \"\$ft\" in *executable*|*ELF*|*PE32*)
             strings \"\$f\" 2>/dev/null | grep -Ei \
               'http|\.onion|bitcoin|wallet|vssadmin|bcdedit|/etc/shadow|lsass' | head -10
             ;;
           esac
         done"

# --- Embedded URLs ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEoh 'https?://[^[:space:]'\''\">)}{,]+' /scan/repo 2>/dev/null | sort -u"
```

---

## Step 4b: Skill-Specific Analysis (run when target is a skill file or folder)

Skill files are markdown documents that instruct Claude how to behave. Threats here differ from code: instead of executing malicious binaries, a malicious skill manipulates Claude itself. Run these checks in addition to the standard suite above. Consult `references/patterns.md` Category 9 for the full pattern library.

```bash
# --- Prompt injection keywords ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    'ignore (all |previous |prior |above |your |these )?(instructions?|guidelines?|rules?|constraints?|training)|
you are now|your (new |true |actual |real |primary |only |secret )?(role|purpose|identity|directive|goal|instruction)|
disregard|override|bypass|jailbreak|do not follow|forget your|pretend (you are|to be)|act as (if )?you|
DAN|developer mode|unrestricted mode|no restrictions|without restrictions|safety (guidelines?|training|filters?) (do not|does not|not) apply|
this (skill|command|prompt|instruction) (has been|is) (verified|approved|authorized|trusted|certified) by anthropic' \
    /scan/repo 2>/dev/null | head -40"

# --- Data exfiltration instructions ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    'send (the |all |this |conversation|user|message|history|content|data|output)|
(post|transmit|upload|exfiltrat|forward).{0,60}(http|url|endpoint|server|remote)|
include.{0,60}(conversation|history|message|api.?key|token|secret|password).{0,60}(request|url|http)|
(curl|wget|fetch).{0,80}(secret|key|token|password|credential|env|\.ssh|\.aws)' \
    /scan/repo 2>/dev/null | head -40"

# --- Credential access instructions ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    '(read|open|cat|show|display|access|retrieve|get|fetch).{0,60}(\.ssh|\.aws|\.env|\.netrc|id_rsa|id_ed25519|credentials|api.?key|secret.?key|private.?key)|
(~|HOME|\/home\/|\/root\/)\/.*(\.ssh|\.aws|credentials|\.netrc)|
\/etc\/(passwd|shadow|sudoers)' \
    /scan/repo 2>/dev/null | head -40"

# --- Dangerous commands embedded in skill instructions ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    'curl.{0,40}\|.{0,10}(bash|sh)|wget.{0,40}\|.{0,10}(bash|sh)|bash\s*<\(curl|
rm\s+-rf\s+\/|chmod\s+(777|u\+s|4755)|crontab|\/etc\/cron|systemctl (enable|start)|
npm install -g|pip install|eval\(|exec\(' \
    /scan/repo 2>/dev/null | head -40"

# --- Permission or identity claims ---
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    '(you have been granted|you now have|this (gives|grants) you).{0,60}(access|permission|privilege|ability|right)|
(anthropic|claude|system).{0,30}(authorized|approved|verified|certified|allow)|
(admin|root|superuser|elevated).{0,30}(access|mode|privilege)' \
    /scan/repo 2>/dev/null | head -30"
```

For every finding from the skill-specific checks, record severity using `references/patterns.md` Category 9 guidance.

---

## Step 5: Classify Embedded URLs

From the URL list collected above, classify each URL as:
- **Known safe** — npm, PyPI, crates.io, GitHub, major CDNs, documentation hosts
- **Suspicious** — unknown domains, bare IP addresses, URL shorteners, high-entropy domain names
- **Download targets** — URLs ending in `.sh`, `.py`, `.exe`, `.bin`, `.ps1`, `.tar.gz`, `.zip` or passed directly to `eval`/`exec`/`bash`/`python`

---

## Step 6: Inspect Secondary Payloads

For each **suspicious** or **download target** URL, fetch it into the volume (not the host) and analyze:

```bash
# Fetch secondary payload (limited network, sandboxed)
docker run --rm \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 256m \
  -v "${SCAN_ID}:/scan" \
  alpine:latest \
  sh -c "
    apk add -q curl file 2>/dev/null
    mkdir -p /scan/secondary
    curl -sL --max-filesize 10485760 '<SUSPICIOUS_URL>' -o /scan/secondary/payload-1 2>&1
    file /scan/secondary/payload-1
    chmod ugo-x /scan/secondary/payload-1
  "

# Analyze it with no network
docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" \
  alpine:latest \
  sh -c "
    grep -Ean 'curl|wget|exec|eval|base64|/dev/tcp|bitcoin|vssadmin' \
      /scan/secondary/payload-1 2>/dev/null | head -30
    grep -Eaoh 'https?://[^[:space:]'\''\">)}{,]+' \
      /scan/secondary/payload-1 2>/dev/null | sort -u
  "
```

Repeat up to **depth 2**. If a URL is unreachable, flag it UNVERIFIED — an inaccessible URL in an install hook is itself suspicious.

---

## Step 7: Write the Report as a Markdown File

Compose the full report using the structure in `references/report-template.md`. Then write it to the output directory:

```bash
REPORT_FILE="${OUTPUT_DIR}/scan-report-$(date +%Y%m%d-%H%M%S).md"

cat > "$REPORT_FILE" << 'REPORT'
<FULL REPORT CONTENT HERE — paste the markdown report you composed>
REPORT

echo "Report saved: $REPORT_FILE"
```

Every CRITICAL and HIGH finding must include:
- The exact code snippet
- The file path and line number
- A plain-English explanation of what the code does and why it is dangerous

---

## Step 8: Claude Code Security Review (conditional)

This step uses Claude Code's built-in security analysis to review the scanned source code directly. It runs **after** the sandbox-based analysis so it only adds signal — it never sees code that was already flagged as confirmed malicious.

**Run this step if either condition is true:**
- No CRITICAL or HIGH findings were found in Steps 4–6
- The user included `--security-review` in their request (`FORCE_SECURITY_REVIEW=true`)

**Skip this step if:**
- CRITICAL or HIGH findings exist **and** `FORCE_SECURITY_REVIEW` is not set
- This skill is running in Claude.ai or any environment without Claude Code shell access

**Why the gate exists:** Exporting code to the host filesystem when the repo is already confirmed malicious serves no purpose and unnecessarily touches the host. The `--security-review` flag lets the user override this for research or curiosity purposes.

### Export the repo to a temporary host directory

```bash
TEMP_DIR=$(mktemp -d /tmp/codescan-review-XXXXXX)
docker run --rm \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" \
  -v "${TEMP_DIR}:/output" \
  alpine:latest \
  sh -c "cp -r /scan/repo/. /output/ && find /output -type f -exec chmod ugo-x {} \;"
echo "Exported to: $TEMP_DIR"
```

### Run the security review

With the files now accessible on the host, read the key source files directly and apply Claude Code's security analysis — the same checks the `/security-review` command performs:

- **SQL injection** — string concatenation into queries, unparameterised inputs
- **XSS** — unsanitised output to HTML, unsafe `innerHTML` / `dangerouslySetInnerHTML`
- **Authentication and authorisation flaws** — missing auth checks, hardcoded credentials, insecure session handling
- **Insecure data handling** — unvalidated input, unsafe deserialisation, cleartext secrets
- **Dependency vulnerabilities** — anything missed by OSV (version ranges, indirect deps)

Focus on entry points, request handlers, authentication code, and any file that directly handles user input. Read files using your file tools — do not execute anything.

### Append findings to the report

Add a new section to the saved report file:

```bash
cat >> "$REPORT_FILE" << 'REVIEW'

---

## Claude Code Security Review

*Run as a supplementary check via Claude Code's built-in security analysis.*

<findings here, or "No additional findings." if clean>
REVIEW
```

### Clean up the temp directory

```bash
rm -rf "$TEMP_DIR"
echo "Temp directory removed."
```

---

## Step 9: Destroy the Sandbox

Remove the Docker volume and all its contents — the repo and any fetched payloads are completely gone from the system:

```bash
docker volume rm "$SCAN_ID"
echo "Sandbox destroyed. Volume $SCAN_ID removed."
echo "Report is at: $REPORT_FILE"
```

---

## Behavioral Rules

- **Never execute any downloaded code**, even to test it
- All analysis containers must use `--network none` except the download step
- All analysis containers must use `--cap-drop ALL` and `--security-opt no-new-privileges`
- If a file cannot be read (encrypted, corrupted), flag it as UNVERIFIED
- Do not dismiss a finding as "probably fine" without a specific technical reason
- When in doubt, escalate severity rather than downgrade
- Always destroy the volume in Step 9 — do not leave malware on the system
- The report `.md` file is the only artifact that remains after the scan
