# Scan Commands Reference

All Docker run commands for the code-scanner skill. Read this file at the start of every scan — SKILL.md references it throughout.

## Table of Contents

**Sandbox mode** (remote targets — URLs, archives, packages):
1. [Size Check](#size-check)
2. [Download Commands](#download-commands)
3. [Structure Map](#structure-map)
4. [OSV Scanner](#osv-scanner)
5. [Dependency Supply Chain Analysis (dep-scan)](#dependency-supply-chain-analysis-dep-scan)
6. [Standard Scan Suite](#standard-scan-suite)
7. [Skill-Specific Checks](#skill-specific-checks)
8. [Secondary Payload Inspection](#secondary-payload-inspection)
9. [Step 8: Export, Review, Cleanup](#step-8-export-review-cleanup)

**Local mode** (target is a path already on disk — no sandbox, no download):
10. [Local Mode Commands](#local-mode-commands)

---

## Size Check

### GitHub repository
```bash
curl -s "https://api.github.com/repos/<OWNER>/<REPO>" \
  | grep '"size"' | head -1
# Size is in KB. Divide by 1024 for MB.
```

### Archive URL (zip / tar.gz)
```bash
curl -sI "<ARCHIVE_URL>" | grep -i content-length
# Value is in bytes. Divide by 1048576 for MB.
```

### Local path
```bash
du -sh "<LOCAL_PATH>"
```

---

## Download Commands

### GitHub repository (full clone)
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

### GitHub subdirectory (sparse checkout)
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

### Zip or tar.gz archive
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
    mkdir -p /scan/repo
    unzip -q /scan/archive -d /scan/repo 2>/dev/null || tar -xf /scan/archive -C /scan/repo 2>/dev/null
    find /scan/repo -type f -exec chmod ugo-x {} \;
    find /scan/repo -type d -exec chmod ugo-rwx {} \;
    rm /scan/archive
    echo 'Download complete. Files made non-executable.'
  "
```

### PyPI package
Downloads the actual published wheel/sdist — the artifact `pip install` would fetch, not the GitHub source. Use this when the target is a package version like `litellm==1.82.8`.

```bash
docker run --rm \
  --name "${SCAN_ID}-download" \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" \
  python:3.12-alpine \
  sh -c "
    pip download --no-deps '<PACKAGE>==<VERSION>' -d /tmp/pkgs 2>&1
    mkdir -p /scan/repo
    for f in /tmp/pkgs/*.whl; do [ -f \"\$f\" ] && unzip -q \"\$f\" -d /scan/repo; done
    for f in /tmp/pkgs/*.tar.gz; do [ -f \"\$f\" ] && tar -xf \"\$f\" -C /scan/repo; done
    find /scan/repo -type f -exec chmod ugo-x {} \;
    find /scan/repo -type d -exec chmod ugo-rwx {} \;
    echo 'PyPI package download complete.'
  "
```

### npm package
Downloads the tarball that `npm install` would fetch.

```bash
docker run --rm \
  --name "${SCAN_ID}-download" \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan" \
  node:20-alpine \
  sh -c "
    mkdir -p /scan/repo
    cd /tmp && npm pack '<PACKAGE>@<VERSION>' 2>&1
    for f in /tmp/*.tgz; do [ -f \"\$f\" ] && tar -xf \"\$f\" -C /scan/repo; done
    find /scan/repo -type f -exec chmod ugo-x {} \;
    find /scan/repo -type d -exec chmod ugo-rwx {} \;
    echo 'npm package download complete.'
  "
```

### Local paths (including skill files)

Local targets do **not** use the download commands above. When the target is already on disk, skip sandbox setup entirely and scan in place using the commands in the [Local Mode Commands](#local-mode-commands) section at the bottom of this file.

---

## Structure Map

```bash
docker run --rm \
  --network none \
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

---

## OSV Scanner

Checks dependency manifests against the Open Source Vulnerabilities database. Requires brief network access — only dependency metadata is sent, no repo code.

```bash
docker run --rm \
  --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" \
  ghcr.io/google/osv-scanner:latest \
  --recursive /scan/repo \
  --format json 2>/dev/null \
  | jq '.results[]?.packages[]? | {package: .package, vulns: [.vulnerabilities[]? | {id: .id, severity: (.severity // "UNKNOWN"), summary: (.summary // "")}]}' 2>/dev/null \
  || echo "No vulnerabilities found or no supported manifest files present."
```

For every OSV finding, record the CVE/GHSA ID, affected package and version, and fix version if available.

---

## Dependency Supply Chain Analysis (dep-scan)

Checks every declared dependency for typosquatting, suspicious package age, maintainer changes, known vulnerabilities, dependency confusion, and malicious install scripts. Goes beyond OSV by querying registry metadata directly.

Requires the `dep-scan:latest` Docker image — see build instructions below. If the image is not available, skip this step and note it in the report.

### Build the dep-scan image (auto-rebuild on Dockerfile changes)

The dep-scan image is built once and reused across scans. A SHA256 hash of the Dockerfile is stored as a Docker label — the image rebuilds automatically when the Dockerfile content changes (new dep-scan version, base image update, etc.). Existing scan volumes are unaffected.

```bash
DEP_SCAN_DOCKERFILE="$CLAUDE_SKILL_DIR/docker/Dockerfile.dep-scan"
CURRENT_HASH=$(sha256sum "$DEP_SCAN_DOCKERFILE" | cut -d' ' -f1)
STORED_HASH=$(docker image inspect dep-scan:latest \
    --format '{{index .Config.Labels "dev.codescan.dockerfile-hash"}}' 2>/dev/null || echo "missing")

if [ "$CURRENT_HASH" != "$STORED_HASH" ]; then
    echo "Building dep-scan image..."
    docker build \
        --label "dev.codescan.dockerfile-hash=$CURRENT_HASH" \
        -t dep-scan:latest \
        -f "$DEP_SCAN_DOCKERFILE" \
        "$(dirname "$DEP_SCAN_DOCKERFILE")"
    echo "dep-scan image ready."
else
    echo "dep-scan image is up-to-date — skipping build."
fi
```

If `$CLAUDE_SKILL_DIR` is not set (e.g. manual install or non-Claude tool), build directly:
```bash
docker build -t dep-scan:latest -f code-scanner/docker/Dockerfile.dep-scan .
```

### Run dependency supply chain analysis

This step requires network access to query registry APIs and the OSV database. Do NOT add `--network none`.

```bash
docker run --rm \
  --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" \
  dep-scan:latest \
  sh -c '
    found_any=false

    # npm dependencies (from package.json)
    for pj in $(find /scan/repo -name package.json -not -path "*/node_modules/*" -not -path "*/.git/*"); do
      deps=$(jq -r "(.dependencies // {}) + (.devDependencies // {}) | keys[]" "$pj" 2>/dev/null | tr "\n" " ")
      if [ -n "$deps" ]; then
        found_any=true
        echo "=== npm deps from ${pj#/scan/repo/} ==="
        dep-scan check $deps --registry npm --json 2>&1
      fi
    done

    # PyPI dependencies (from requirements*.txt)
    for req in $(find /scan/repo \( -name "requirements.txt" -o -name "requirements-*.txt" -o -name "requirements_*.txt" \) -not -path "*/.git/*"); do
      deps=$(grep -v "^\s*#" "$req" | grep -v "^\s*$" | grep -v "^\s*-" | sed "s/[>=<!\[].*//" | sed "s/\s*$//" | tr "\n" " ")
      if [ -n "$deps" ]; then
        found_any=true
        echo "=== PyPI deps from ${req#/scan/repo/} ==="
        dep-scan check $deps --registry pypi --json 2>&1
      fi
    done

    # PyPI dependencies (from pyproject.toml — extract [project.dependencies])
    for pp in $(find /scan/repo -name "pyproject.toml" -not -path "*/.git/*"); do
      if grep -q "\[project\]" "$pp" 2>/dev/null; then
        deps=$(sed -n "/^dependencies\s*=/,/^\]/p" "$pp" 2>/dev/null \
          | grep -oE "\"[a-zA-Z0-9_-]+\"" | tr -d "\"" | tr "\n" " ")
        if [ -n "$deps" ]; then
          found_any=true
          echo "=== PyPI deps from ${pp#/scan/repo/} ==="
          dep-scan check $deps --registry pypi --json 2>&1
        fi
      fi
    done

    if [ "$found_any" = false ]; then
      echo "No dependency manifests found (package.json, requirements*.txt, pyproject.toml)."
    fi
  '
```

### Interpreting dep-scan output

dep-scan returns JSON when `--json` is used. Each package entry includes a `result` field and per-policy breakdown:

| dep-scan result | CodeScan severity | Action |
|-----------------|-------------------|--------|
| `block` | HIGH | Record as finding — the dependency failed a blocking policy |
| `warn` | MEDIUM | Record as finding — the dependency triggered a warning |
| `pass` | — | No action needed |

dep-scan exit code `1` means at least one policy violation was found. Exit code `0` means all clean.

The six policies checked: **age** (< 48h), **install_scripts** (eval/exec/subprocess in hooks), **typosquatting** (Levenshtein distance to popular packages), **vulnerability** (CVEs via OSV.dev), **maintainer_change** (ownership transfers), **dependency_confusion** (internal-looking names on public registries).

---

## Standard Scan Suite

Run these four containers in sequence. Batching related patterns into a single container eliminates Docker startup overhead compared to running each grep separately.

### Container 1 — Execution and obfuscation threats

```bash
docker run --rm --network none --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "
    echo '=== Download-and-execute ==='
    grep -rEn 'curl.+\|.+sh|wget.+\|.+sh|bash\s*<\(curl|IEX.+Download|fetch.+exec' \
         /scan/repo 2>/dev/null | grep -v '/.git/' | head -30

    echo '=== Obfuscation ==='
    grep -rEn 'eval\(base64|exec\(base64|atob\(|fromCharCode|\\\\x[0-9a-f]{2}' \
         /scan/repo 2>/dev/null | grep -v '/.git/' | head -30

    echo '=== Reverse shells ==='
    grep -rEn '/dev/tcp|/dev/udp|nc\s+-e|ncat.*-e|socat.*exec|bash\s+-i|sh\s+-i' \
         /scan/repo 2>/dev/null | grep -v '/.git/' | head -30
  "
```

### Container 2 — Supply chain and persistence threats

```bash
docker run --rm --network none --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "
    echo '=== npm install hooks ==='
    grep -rn 'postinstall\|preinstall\|\"install\"' /scan/repo \
         --include='package.json' 2>/dev/null

    echo '=== Python setup hooks ==='
    grep -rn 'cmdclass\|setup_requires\|CustomInstall\|subprocess' /scan/repo \
         --include='setup.py' --include='setup.cfg' 2>/dev/null

    echo '=== .pth persistence (runs on every Python startup) ==='
    find /scan/repo -name '*.pth' 2>/dev/null | while read f; do
      grep -qE 'import|exec|subprocess|os\.' \"\$f\" 2>/dev/null \
        && echo \"SUSPICIOUS .pth: \$f\" && cat \"\$f\"
    done || true

    echo '=== Systemd/launchd persistence ==='
    grep -rEn '\.config/systemd|systemd/user|/etc/systemd|LaunchAgents|LaunchDaemons|systemctl.*(enable|start)|launchctl' \
         /scan/repo 2>/dev/null | grep -v '/.git/' | head -20

    echo '=== Unpinned third-party GitHub Actions (mutable tags) ==='
    grep -rEn 'uses:\s+[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+@v[0-9]' \
         /scan/repo/.github 2>/dev/null \
      | grep -vE 'uses:\s+actions/|uses:\s+github/' | head -20
  "
```

### Container 3 — Credential harvesting and URLs

```bash
docker run --rm --network none --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "
    echo '=== Credential harvesting ==='
    grep -rEn 'process\.env\.|os\.environ|getenv\(|HOME.*\.ssh|\.aws/credentials|\.netrc' \
         /scan/repo 2>/dev/null | grep -v '/.git/' | head -30

    echo '=== Cloud metadata endpoints ==='
    grep -rEn '169\.254\.169\.254|fd00:ec2::254|metadata\.google\.internal|metadata\.azure\.com' \
         /scan/repo 2>/dev/null | grep -v '/.git/' | head -20

    echo '=== Embedded URLs ==='
    grep -rEoh 'https?://[^[:space:]'\''\">\)}{,]+' \
         /scan/repo 2>/dev/null | grep -v '/.git/' | sort -u
  "
```

### Container 4 — Binary and compiled file strings

```bash
docker run --rm --network none --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "
    apk add -q binutils 2>/dev/null
    find /scan/repo -type f -not -path '*/.git/*' | while read f; do
      ft=\$(file \"\$f\" 2>/dev/null)
      case \"\$ft\" in *executable*|*ELF*|*PE32*)
        echo \"=== Binary: \$f ===\"
        strings \"\$f\" 2>/dev/null | grep -Ei \
          'http|\.onion|bitcoin|wallet|vssadmin|bcdedit|/etc/shadow|lsass' | head -10
        ;;
      esac
    done
  "
```

---

## Skill-Specific Checks

Run when the target is a skill file or folder (Step 4b). Run all five in sequence.

```bash
# Check 1 — Prompt injection keywords
docker run --rm --network none --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    'ignore (all |previous |prior |above |your |these )?(instructions?|guidelines?|rules?|constraints?|training)|
you are now|your (new |true |actual |real |primary |only |secret )?(role|purpose|identity|directive|goal|instruction)|
disregard|override|bypass|jailbreak|do not follow|forget your|pretend (you are|to be)|act as (if )?you|
DAN|developer mode|unrestricted mode|no restrictions|without restrictions|safety (guidelines?|training|filters?) (do not|does not|not) apply|
this (skill|command|prompt|instruction) (has been|is) (verified|approved|authorized|trusted|certified) by anthropic' \
    /scan/repo 2>/dev/null | head -40"

# Check 2 — Data exfiltration instructions
docker run --rm --network none --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    'send (the |all |this |conversation|user|message|history|content|data|output)|
(post|transmit|upload|exfiltrat|forward).{0,60}(http|url|endpoint|server|remote)|
include.{0,60}(conversation|history|message|api.?key|token|secret|password).{0,60}(request|url|http)|
(curl|wget|fetch).{0,80}(secret|key|token|password|credential|env|\.ssh|\.aws)' \
    /scan/repo 2>/dev/null | head -40"

# Check 3 — Credential access instructions
docker run --rm --network none --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    '(read|open|cat|show|display|access|retrieve|get|fetch).{0,60}(\.ssh|\.aws|\.env|\.netrc|id_rsa|id_ed25519|credentials|api.?key|secret.?key|private.?key)|
(~|HOME|\/home\/|\/root\/)\/.*(\.ssh|\.aws|credentials|\.netrc)|
\/etc\/(passwd|shadow|sudoers)' \
    /scan/repo 2>/dev/null | head -40"

# Check 4 — Dangerous embedded commands
docker run --rm --network none --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    'curl.{0,40}\|.{0,10}(bash|sh)|wget.{0,40}\|.{0,10}(bash|sh)|bash\s*<\(curl|
rm\s+-rf\s+\/|chmod\s+(777|u\+s|4755)|crontab|\/etc\/cron|systemctl (enable|start)|
npm install -g|pip install|eval\(|exec\(' \
    /scan/repo 2>/dev/null | head -40"

# Check 5 — False permission or identity claims
docker run --rm --network none --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" alpine:latest \
  sh -c "grep -rEin \
    '(you have been granted|you now have|this (gives|grants) you).{0,60}(access|permission|privilege|ability|right)|
(anthropic|claude|system).{0,30}(authorized|approved|verified|certified|allow)|
(admin|root|superuser|elevated).{0,30}(access|mode|privilege)' \
    /scan/repo 2>/dev/null | head -30"
```

---

## Secondary Payload Inspection

For each suspicious URL found in Step 5, fetch into the volume and analyze. Repeat up to depth 2.

```bash
# Fetch the payload (limited network, sandboxed)
docker run --rm \
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

# Analyze with no network
docker run --rm \
  --network none \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" \
  alpine:latest \
  sh -c "
    grep -Ean 'curl|wget|exec|eval|base64|/dev/tcp|bitcoin|vssadmin' \
      /scan/secondary/payload-1 2>/dev/null | head -30
    grep -Eaoh 'https?://[^[:space:]'\''\">\)}{,]+' \
      /scan/secondary/payload-1 2>/dev/null | sort -u
  "
```

---

## Step 8: Export, Review, Cleanup

### Export to temp directory

```bash
TEMP_DIR=$(mktemp -d /tmp/codescan-review-XXXXXX)
docker run --rm \
  --security-opt no-new-privileges \
  -v "${SCAN_ID}:/scan:ro" \
  -v "${TEMP_DIR}:/output" \
  alpine:latest \
  sh -c "
    cp -r /scan/repo/. /output/
    chmod -R a+rX /output
    find /output -type f -exec chmod a-x {} \;
  "
echo "Exported to: $TEMP_DIR"
```

The `chmod -R a+rX /output` step runs first to grant read permission across all files and directories. Docker-created files are owned by root and may have restrictive permissions — without this step, the host user cannot read them. The follow-up `find` strips execute bits from individual files.

### Clean up temp directory

```bash
# Remove all contents including hidden directories (e.g. root-owned .git)
# using find inside the container — plain `rm -rf /cleanup/*` skips dotfiles
docker run --rm \
  --security-opt no-new-privileges \
  -v "${TEMP_DIR}:/cleanup" \
  alpine:latest \
  sh -c "find /cleanup -mindepth 1 -delete"
rmdir "$TEMP_DIR"
echo "Temp directory removed."
```

---

## Local Mode Commands

Use these commands when `LOCAL_MODE=true` — i.e. the target is a path that already exists on the user's disk (a cloned repo, a skill folder, a downloaded project). No Docker volume is created, no download happens, and the host's own `grep`/`find` scan the files in place.

**Why no sandbox?** The Docker sandbox exists to prevent *execution* of code fetched from an untrusted source (install hooks, setup scripts, postinstall triggers). Read-only text analysis — `grep`, `find`, `file`, `strings` — never executes the code it reads. If the user already has the files on disk, any risk from their presence has already materialised; scanning them with text tools adds none.

**Prerequisites:** `SCAN_ROOT` is set to the absolute path of the target on the host. Commands are run directly from the shell, not inside a container, unless noted. Do not modify files under `$SCAN_ROOT` — no `chmod`, no writes.

### Structure Map (local)

```bash
echo '=== File count ==='
find "$SCAN_ROOT" -type f -not -path '*/.git/*' | wc -l
echo ''
echo '=== Top-level structure ==='
find "$SCAN_ROOT" -maxdepth 3 -not -path '*/.git/*' | sort | head -100
echo ''
echo '=== File types ==='
find "$SCAN_ROOT" -type f -not -path '*/.git/*' | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -20
```

### OSV Scanner (local)

Still uses the OSV container as a tool runner, but bind-mounts `$SCAN_ROOT` read-only instead of a sandbox volume. Requires network access to query the OSV API.

```bash
docker run --rm \
  --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ROOT}:/scan/repo:ro" \
  ghcr.io/google/osv-scanner:latest \
  --recursive /scan/repo \
  --format json 2>/dev/null \
  | jq '.results[]?.packages[]? | {package: .package, vulns: [.vulnerabilities[]? | {id: .id, severity: (.severity // "UNKNOWN"), summary: (.summary // "")}]}' 2>/dev/null \
  || echo "No vulnerabilities found or no supported manifest files present."
```

### dep-scan (local)

Same `dep-scan:latest` image as sandbox mode, with `$SCAN_ROOT` bind-mounted read-only. Requires network access.

```bash
docker run --rm \
  --security-opt no-new-privileges \
  --memory 512m \
  -v "${SCAN_ROOT}:/scan/repo:ro" \
  dep-scan:latest \
  sh -c '
    found_any=false

    # npm dependencies (from package.json)
    for pj in $(find /scan/repo -name package.json -not -path "*/node_modules/*" -not -path "*/.git/*"); do
      deps=$(jq -r "(.dependencies // {}) + (.devDependencies // {}) | keys[]" "$pj" 2>/dev/null | tr "\n" " ")
      if [ -n "$deps" ]; then
        found_any=true
        echo "=== npm deps from ${pj#/scan/repo/} ==="
        dep-scan check $deps --registry npm --json 2>&1
      fi
    done

    # PyPI dependencies (from requirements*.txt)
    for req in $(find /scan/repo \( -name "requirements.txt" -o -name "requirements-*.txt" -o -name "requirements_*.txt" \) -not -path "*/.git/*"); do
      deps=$(grep -v "^\s*#" "$req" | grep -v "^\s*$" | grep -v "^\s*-" | sed "s/[>=<!\[].*//" | sed "s/\s*$//" | tr "\n" " ")
      if [ -n "$deps" ]; then
        found_any=true
        echo "=== PyPI deps from ${req#/scan/repo/} ==="
        dep-scan check $deps --registry pypi --json 2>&1
      fi
    done

    # PyPI dependencies (from pyproject.toml — extract [project.dependencies])
    for pp in $(find /scan/repo -name "pyproject.toml" -not -path "*/.git/*"); do
      if grep -q "\[project\]" "$pp" 2>/dev/null; then
        deps=$(sed -n "/^dependencies\s*=/,/^\]/p" "$pp" 2>/dev/null \
          | grep -oE "\"[a-zA-Z0-9_-]+\"" | tr -d "\"" | tr "\n" " ")
        if [ -n "$deps" ]; then
          found_any=true
          echo "=== PyPI deps from ${pp#/scan/repo/} ==="
          dep-scan check $deps --registry pypi --json 2>&1
        fi
      fi
    done

    if [ "$found_any" = false ]; then
      echo "No dependency manifests found (package.json, requirements*.txt, pyproject.toml)."
    fi
  '
```

### Standard Scan Suite (local)

Native host `grep`/`find` against `$SCAN_ROOT`. Same patterns as the sandbox version. Run all four groups in sequence.

#### Group 1 — Execution and obfuscation threats

```bash
echo '=== Download-and-execute ==='
grep -rEn 'curl.+\|.+sh|wget.+\|.+sh|bash\s*<\(curl|IEX.+Download|fetch.+exec' \
     "$SCAN_ROOT" 2>/dev/null | grep -v '/.git/' | head -30

echo '=== Obfuscation ==='
grep -rEn 'eval\(base64|exec\(base64|atob\(|fromCharCode|\\x[0-9a-f]{2}' \
     "$SCAN_ROOT" 2>/dev/null | grep -v '/.git/' | head -30

echo '=== Reverse shells ==='
grep -rEn '/dev/tcp|/dev/udp|nc\s+-e|ncat.*-e|socat.*exec|bash\s+-i|sh\s+-i' \
     "$SCAN_ROOT" 2>/dev/null | grep -v '/.git/' | head -30
```

#### Group 2 — Supply chain and persistence threats

```bash
echo '=== npm install hooks ==='
grep -rn 'postinstall\|preinstall\|"install"' "$SCAN_ROOT" \
     --include='package.json' 2>/dev/null

echo '=== Python setup hooks ==='
grep -rn 'cmdclass\|setup_requires\|CustomInstall\|subprocess' "$SCAN_ROOT" \
     --include='setup.py' --include='setup.cfg' 2>/dev/null

echo '=== .pth persistence (runs on every Python startup) ==='
find "$SCAN_ROOT" -name '*.pth' 2>/dev/null | while read f; do
  grep -qE 'import|exec|subprocess|os\.' "$f" 2>/dev/null \
    && echo "SUSPICIOUS .pth: $f" && cat "$f"
done

echo '=== Systemd/launchd persistence ==='
grep -rEn '\.config/systemd|systemd/user|/etc/systemd|LaunchAgents|LaunchDaemons|systemctl.*(enable|start)|launchctl' \
     "$SCAN_ROOT" 2>/dev/null | grep -v '/.git/' | head -20

echo '=== Unpinned third-party GitHub Actions (mutable tags) ==='
if [ -d "$SCAN_ROOT/.github" ]; then
  grep -rEn 'uses:\s+[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+@v[0-9]' \
       "$SCAN_ROOT/.github" 2>/dev/null \
    | grep -vE 'uses:\s+actions/|uses:\s+github/' | head -20
fi
```

#### Group 3 — Credential harvesting and URLs

```bash
echo '=== Credential harvesting ==='
grep -rEn 'process\.env\.|os\.environ|getenv\(|HOME.*\.ssh|\.aws/credentials|\.netrc' \
     "$SCAN_ROOT" 2>/dev/null | grep -v '/.git/' | head -30

echo '=== Cloud metadata endpoints ==='
grep -rEn '169\.254\.169\.254|fd00:ec2::254|metadata\.google\.internal|metadata\.azure\.com' \
     "$SCAN_ROOT" 2>/dev/null | grep -v '/.git/' | head -20

echo '=== Embedded URLs ==='
grep -rEoh 'https?://[^[:space:]'\''\">\)}{,]+' \
     "$SCAN_ROOT" 2>/dev/null | grep -v '/.git/' | sort -u
```

#### Group 4 — Binary and compiled file strings

Uses host `file` and `strings` (binutils). These are pure readers — they never execute the file. If `strings` is missing, install `binutils` or fall back to the sandbox Container 4 command with a read-only bind mount.

```bash
find "$SCAN_ROOT" -type f -not -path '*/.git/*' | while read f; do
  ft=$(file "$f" 2>/dev/null)
  case "$ft" in *executable*|*ELF*|*PE32*)
    echo "=== Binary: $f ==="
    strings "$f" 2>/dev/null | grep -Ei \
      'http|\.onion|bitcoin|wallet|vssadmin|bcdedit|/etc/shadow|lsass' | head -10
    ;;
  esac
done
```

### Skill-Specific Checks (local)

Native host `grep` — same patterns as the sandbox version. Run all five in sequence.

```bash
# Check 1 — Prompt injection keywords
grep -rEin \
  'ignore (all |previous |prior |above |your |these )?(instructions?|guidelines?|rules?|constraints?|training)|
you are now|your (new |true |actual |real |primary |only |secret )?(role|purpose|identity|directive|goal|instruction)|
disregard|override|bypass|jailbreak|do not follow|forget your|pretend (you are|to be)|act as (if )?you|
DAN|developer mode|unrestricted mode|no restrictions|without restrictions|safety (guidelines?|training|filters?) (do not|does not|not) apply|
this (skill|command|prompt|instruction) (has been|is) (verified|approved|authorized|trusted|certified) by anthropic' \
  "$SCAN_ROOT" 2>/dev/null | head -40

# Check 2 — Data exfiltration instructions
grep -rEin \
  'send (the |all |this |conversation|user|message|history|content|data|output)|
(post|transmit|upload|exfiltrat|forward).{0,60}(http|url|endpoint|server|remote)|
include.{0,60}(conversation|history|message|api.?key|token|secret|password).{0,60}(request|url|http)|
(curl|wget|fetch).{0,80}(secret|key|token|password|credential|env|\.ssh|\.aws)' \
  "$SCAN_ROOT" 2>/dev/null | head -40

# Check 3 — Credential access instructions
grep -rEin \
  '(read|open|cat|show|display|access|retrieve|get|fetch).{0,60}(\.ssh|\.aws|\.env|\.netrc|id_rsa|id_ed25519|credentials|api.?key|secret.?key|private.?key)|
(~|HOME|\/home\/|\/root\/)\/.*(\.ssh|\.aws|credentials|\.netrc)|
\/etc\/(passwd|shadow|sudoers)' \
  "$SCAN_ROOT" 2>/dev/null | head -40

# Check 4 — Dangerous embedded commands
grep -rEin \
  'curl.{0,40}\|.{0,10}(bash|sh)|wget.{0,40}\|.{0,10}(bash|sh)|bash\s*<\(curl|
rm\s+-rf\s+\/|chmod\s+(777|u\+s|4755)|crontab|\/etc\/cron|systemctl (enable|start)|
npm install -g|pip install|eval\(|exec\(' \
  "$SCAN_ROOT" 2>/dev/null | head -40

# Check 5 — False permission or identity claims
grep -rEin \
  '(you have been granted|you now have|this (gives|grants) you).{0,60}(access|permission|privilege|ability|right)|
(anthropic|claude|system).{0,30}(authorized|approved|verified|certified|allow)|
(admin|root|superuser|elevated).{0,30}(access|mode|privilege)' \
  "$SCAN_ROOT" 2>/dev/null | head -30
```

### Step 8: Review (local)

No export or cleanup needed in local mode — the files are already on the host. Use your file tools (Read, Grep) to examine key source files directly under `$SCAN_ROOT` and append findings to the report.

### Secondary Payload Inspection (local mode)

Secondary payloads come from URLs discovered during the scan, not from the local filesystem — so fetching them always uses Docker (same commands as the sandbox-mode [Secondary Payload Inspection](#secondary-payload-inspection) section above). The fetch container writes into its own ephemeral volume; it does not touch `$SCAN_ROOT`.
