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

If no URL or path is provided, ask: "Please provide the GitHub repository URL or archive link you'd like me to scan."

Confirm Docker is available before proceeding:
```bash
docker info > /dev/null 2>&1 && echo "Docker available" || echo "Docker not running — please start Docker Desktop or the Docker daemon"
```

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
  --cap-drop ALL \
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
  --cap-drop ALL \
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
  --cap-drop ALL \
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

## Step 8: Destroy the Sandbox

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
- Always destroy the volume in Step 8 — do not leave malware on the system
- The report `.md` file is the only artifact that remains after the scan
