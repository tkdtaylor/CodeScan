# CodeScan — A Claude Skill for Malicious Code Detection

A portable [Agent Skill](https://www.anthropic.com/news/agent-skills) that scans a code repository for malicious patterns, suspicious links, and supply-chain attack indicators. Works across Claude Code, GitHub Copilot, Cursor, Windsurf, Kiro, and Google Antigravity.

> [!IMPORTANT]
> **Docker is required for remote targets** (GitHub URLs, archives, PyPI/npm packages). When the target is a remote source, it is downloaded into a disposable Docker volume — nothing from the target repo ever touches the host filesystem, and the entire sandbox is destroyed when the scan completes.
>
> **Local paths scan natively without Docker.** If you point the scanner at a folder already on your disk (a cloned repo, a skill folder, a downloaded project), it skips the sandbox entirely and runs read-only text analysis (`grep`, `find`) in place. The sandbox exists to prevent execution of *downloaded* code; files already on your machine have already been there, and reading them with text tools does not execute them. OSV Scanner and dep-scan still use Docker as a tool runner in local mode (via a read-only bind mount), but you can skip both if you don't need dependency checks.
>
> | Platform | Install |
> |---|---|
> | Linux | [Docker Engine](https://docs.docker.com/engine/install/) |
> | macOS | [Docker Desktop](https://docs.docker.com/desktop/install/mac-install/) |
> | Windows | [Docker Desktop](https://docs.docker.com/desktop/install/windows-install/) with WSL2 |
> | Docker Sandbox (`sbx`) | Scanning containers run normally inside the microVM. Use the "Balanced" network policy or add `ghcr.io`, `registry-1.docker.io`, `pypi.org`, `registry.npmjs.org` to your allow list. |
>
> Verify Docker is running before use: `docker info`

> [!WARNING]
> **No automated tool can guarantee that code is safe.** This skill looks for known malicious patterns, but novel, obfuscated, or sufficiently complex threats may go undetected. Use the results as one input alongside your own judgement — not as a definitive safety certificate.

## What it does

Given a GitHub repository URL, a zip archive, a PyPI or npm package name, or a local path already on disk, this skill instructs Claude to:

1. **Remote targets**: create an isolated Docker volume and download the code into it, stripping all execute permissions. **Local paths**: skip the sandbox entirely and scan the files in place with native `grep`/`find` — no volume, no download, no copy.
2. Check dependency manifests against the OSV vulnerability database and *(optionally)* run dep-scan supply chain analysis — typosquatting, package age, maintainer changes, dependency confusion
3. Statically analyze the code for malicious patterns (using `--network none` containers in sandbox mode, or native host tools in local mode)
4. Follow any embedded download URLs and inspect those payloads inside an ephemeral Docker volume
5. Write a structured Markdown report to `./codescan-reports/` on your machine
6. *(Claude Code only)* If no HIGH or CRITICAL findings were found, run a supplementary review using Claude Code's built-in security analysis and append the results to the report
7. **Remote targets**: destroy the Docker volume. **Local paths**: nothing to destroy — your files are left untouched.

## Trigger phrases

- "Scan this repo and tell me if it's safe to run: `<url>`"
- "Check if this GitHub repo is malicious: `<url>`"
- "Is it safe to install this? `<url>`"
- "Run a security scan on `<url>`"
- "Scan the PyPI package `litellm==1.82.8` before I install it"
- "Check the npm package `express@4.18.2` for malware"
- "Scan this skill before I install it: `<path or url>`"
- "Is this Claude skill safe to use?"

Add `--security-review` to any phrase to force the Claude Code security review step even if HIGH or CRITICAL findings are present — e.g. `"Scan https://github.com/... --security-review"`.

## What it detects

**Code repositories, archives, and published packages (PyPI / npm):**

> **Scanning the GitHub source repo is not the same as scanning the published package.** Supply chain attacks like the March 2026 LiteLLM compromise inject malicious code only into the PyPI/npm artifact while leaving the source repo untouched. Use the `litellm==1.82.8` or `npm:package@version` target formats to scan the actual artifact before installing.

- **Known CVEs** — dependency vulnerabilities checked against the [OSV database](https://osv.dev) (via [OSV Scanner](https://github.com/google/osv-scanner))
- **Dependency supply chain** *(optional)* — typosquatting detection, minimum package age enforcement (< 48h), maintainer change/takeover detection, dependency confusion warnings, malicious install script analysis. Powered by [dep-scan](https://github.com/tkdtaylor/dep-scan) — build the image once: `docker build -t dep-scan:latest -f code-scanner/docker/Dockerfile.dep-scan .`
- **Obfuscation** — base64/hex encoded payloads, eval/exec patterns
- **Download & execute** — `curl | bash`, `wget | sh`, fetching and running remote scripts
- **Supply chain hooks** — malicious `postinstall`, `setup.py`, `__init__.py` install triggers
- **Python `.pth` persistence** — executable code in `.pth` files that run on every Python startup (used in the LiteLLM attack)
- **Credential harvesting** — reading env vars, `.env` files, SSH keys, cloud credentials, cloud instance metadata endpoints (`169.254.169.254`)
- **Reverse shells** — outbound connection patterns, netcat, socat
- **Cryptominers** — known miner binaries and pool addresses
- **Data exfiltration** — sending data to remote endpoints
- **Suspicious domains/IPs** — hardcoded C2 infrastructure indicators
- **Persistence mechanisms** — systemd user services, launchd agents, cron injection, SUID bits, sudo abuse
- **Unpinned CI/CD actions** — third-party GitHub Actions using mutable version tags instead of commit SHAs (the Trivy/LiteLLM attack vector)
- **Recursive payloads** — secondary download URLs fetched and inspected inside the sandbox

**Claude skill files:**
- **Prompt injection** — instructions designed to override Claude's behaviour or safety guidelines
- **Identity manipulation** — attempts to replace Claude's role or claim special permissions
- **False endorsement** — falsely claiming the skill is verified or authorized by Anthropic
- **Exfiltration instructions** — directing Claude to send conversation data to remote endpoints
- **Credential access instructions** — directing Claude to read and expose SSH keys, API keys, `.env` files
- **Dangerous embedded commands** — harmful shell commands within skill instructions

## Output

You can see sample reports here: [SAFE — BHIL toolkit](./sample-reports/scan-report-20260322.md) · [CRITICAL — obfuscated backdoor + private key exfiltration](./sample-reports/scan-report-20260330.md). The skill writes a Markdown report to `./codescan-reports/scan-report-YYYYMMDD-HHMMSS.md`:

```markdown
# Code Scan Report

**Target:** https://github.com/...
**Risk Level:** CRITICAL

## Summary
...

## Findings

### [CRITICAL] JavaScript dropper with embedded PE32 payload
**File:** GoldenEye/GoldenEye.js
**Evidence:** ...
**Explanation:** ...

## Recommendation
DO NOT INSTALL — ...
```

## Installation

> **Prerequisite:** Docker must be installed and running. See the requirement note at the top of this page.

### Your preferred Tool

Try asking the tool itself, Claude for example, to install the skill and give it the link to this repo.

### Claude Code
**Mac OS / Linux:**
```bash
# Clone and copy the skill into your Claude skills directory
git clone https://github.com/tkdtaylor/CodeScan /tmp/CodeScan
cp -r /tmp/CodeScan/code-scanner ~/.claude/skills/

# Optional: build the dep-scan image for dependency supply chain analysis
docker build -t dep-scan:latest -f /tmp/CodeScan/code-scanner/docker/Dockerfile.dep-scan /tmp/CodeScan
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/tkdtaylor/CodeScan
Copy-Item -Recurse CodeScan\code-scanner "$env:USERPROFILE\.claude\skills\"

# Optional: build the dep-scan image for dependency supply chain analysis
docker build -t dep-scan:latest -f CodeScan\code-scanner\docker\Dockerfile.dep-scan CodeScan
```

### Google Antigravity
Antigravity has native Agent Skills support. Check [https://antigravity.google/docs/skills](https://antigravity.google/docs/skills) for the exact install path — the skill format is compatible. Docker commands run automatically via the integrated terminal.

1. Create a new folder in your workspace at <workspace-root>/.agents/skills/code-scanner/ (or if you prefer global, ~/.gemini/antigravity/skills/code-scanner/)
2. Copy `code-scanner/SKILL.md` to `./skills/code-scanner/SKILL.md`
3. Copy all files in `code-scanner/references/` to `./skills/code-scanner/references/`
4. Create a new folder `examples` at `./skills/code-scanner/` (./skills/code-scanner/examples/)
5. Copy the file in `code-scanner/sample-reports/` to `./skills/code-scanner/examples/`
6. Switch agent to **Planning Mode** and trigger with a phrase from the [Trigger phrases](#trigger-phrases) section

### GitHub Copilot (Agent Mode)
GitHub Copilot has native Agent Skills support (shipped December 2025). The SKILL.md format is compatible — install it at `.github/skills/` and Copilot will load it automatically when the task matches, without polluting every other chat request.

```bash
mkdir -p .github/skills/code-scanner
cp code-scanner/SKILL.md .github/skills/code-scanner/
cp -r code-scanner/references .github/skills/code-scanner/
```

Use **Agent Mode** in VS Code and trigger with a phrase from the [Trigger phrases](#trigger-phrases) section. Copilot will ask for confirmation before running each Docker command — click **Continue** or enable **Bypass Approvals** in the Copilot settings to allow all commands automatically.

> **Troubleshooting:** If Docker commands appear to hang indefinitely, this is a known VS Code shell integration issue with ZSH themes (especially Powerlevel10k). Copilot uses shell prompt markers to detect when a command has finished — custom themes overwrite these markers. Switch the integrated terminal to Bash, or disable `RPS1` in your ZSH theme config.

### Cursor
Cursor Agent can execute terminal commands, so the full Docker-based scan runs automatically.

1. Open Cursor Settings → **Rules for AI**
2. Paste the full contents of `code-scanner/SKILL.md` into the rules field
3. Copy `code-scanner/references/` into your project and update the relative paths in the rules to match, or add the reference file contents directly below the skill instructions
4. Use Agent mode and trigger with a phrase from the [Trigger phrases](#trigger-phrases) section

Alternatively, add a `.cursorrules` file to your project root with the same content for a project-scoped install.

### Windsurf
Windsurf's Cascade can execute terminal commands, so the full Docker-based scan runs automatically.

1. Add a `.windsurfrules` file to your project root
2. Paste the full contents of `code-scanner/SKILL.md` into it
3. Copy `code-scanner/references/` into your project and update the relative paths to match
4. Use Cascade in **Write** mode and trigger with a phrase from the [Trigger phrases](#trigger-phrases) section

### Kiro (AWS)
Kiro uses steering files which follow the same markdown format as SKILL.md — this is the most direct install of any non-Claude platform.

```bash
mkdir -p .kiro/steering
cp code-scanner/SKILL.md .kiro/steering/code-scanner.md
cp -r code-scanner/references .kiro/steering/
```

Kiro's agent can execute terminal commands, so the full Docker-based scan runs automatically.


## Skill structure

```
code-scanner/           ← skill folder (upload this)
├── SKILL.md            ← main skill file (required)
├── docker/
│   └── Dockerfile.dep-scan ← builds the dep-scan supply chain scanner image
└── references/
    ├── patterns.md        ← malicious pattern reference library
    ├── scan-commands.md   ← Docker run commands for each scan step
    └── report-template.md ← output format template
```

## How the Docker sandbox works

### Docker Sandbox (`sbx`) environments

When running Claude Code inside a Docker Sandbox (`sbx`), all scanning containers work normally — `sbx` provides Docker access within the microVM. The scanner auto-detects `sbx` and proceeds with the standard Docker workflow.

The only consideration is network policies. Scans need network access for:
- **Image pulls**: `registry-1.docker.io`, `production.cloudflare.docker.com`, `ghcr.io` (OSV Scanner)
- **API queries**: `api.osv.dev` (OSV), `api.github.com`, `pypi.org`, `registry.npmjs.org` (dep-scan)

The "Balanced" sbx network policy allows all of these by default. If you use a restrictive policy, add these domains to your allow list.

The dep-scan image auto-rebuilds when its Dockerfile changes — a SHA256 hash is stored as a Docker label and checked before each scan. No manual rebuild needed after skill updates.

### Remote targets (sandbox mode)

```
Host machine
├── ./codescan-reports/        ← report .md files written here (host)
│   └── scan-report-*.md
│
├── /tmp/codescan-review-*/    ← temp dir for Claude Code review (if run)
│   └── ...                    ← non-executable copy, deleted after review
│
└── Docker volume: codescan-TIMESTAMP  ← all repo content stays here
    └── /scan/repo/            ← cloned repository (non-executable)
        └── ...                ← never touches the host filesystem

After scan: docker volume rm codescan-TIMESTAMP
            rm -rf /tmp/codescan-review-*
            → all content permanently deleted
```

The temp directory is only created when the Claude Code security review runs (no HIGH/CRITICAL findings, or `--security-review` flag). Files are copied with execute permissions stripped and deleted immediately after the review.

Each analysis step runs in a container with:
- `--network none` — no outbound connections during analysis
- `--security-opt no-new-privileges` — no privilege escalation

### Local paths (no sandbox)

```
Host machine
├── ./codescan-reports/        ← report .md files written here
│   └── scan-report-*.md
│
└── <your local path>          ← SCAN_ROOT — scanned in place, read-only
    └── ...                    ← files left untouched, no copies made
```

No Docker volume, no download, no temp directory, no export, no cleanup. Only `grep`/`find` read the files. OSV Scanner and dep-scan (if run) still use Docker as a tool runner, but bind-mount `SCAN_ROOT` read-only — they never write to it.

**Why is this safe?** The sandbox exists to prevent *execution* of code fetched from an untrusted source (install hooks, setup scripts, postinstall triggers). Read-only text analysis tools never execute the code they read. If the code is already on your disk, any risk from its presence has already materialised; scanning it with `grep` adds none.

## Contributing

Issues and PRs welcome.

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

**Free for:** personal use, research, education, hobby projects, charitable and government organisations.

**Commercial use** (companies, paid products, internal business tooling) requires a separate commercial license. Contact: kevin@taylorguard.me
