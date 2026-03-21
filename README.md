# CodeScan — A Claude Skill for Malicious Code Detection

A portable [Agent Skill](https://www.anthropic.com/news/agent-skills) that scans a code repository for malicious patterns, suspicious links, and supply-chain attack indicators. Works across Claude.ai, Claude Code, and the Claude API.

> [!IMPORTANT]
> **Docker is required.** This skill will not work without Docker installed and running on your machine. All analysis runs inside a disposable Docker container — nothing from the target repo ever touches the host filesystem, and the entire sandbox is destroyed when the scan completes.
>
> | Platform | Install |
> |---|---|
> | Linux | [Docker Engine](https://docs.docker.com/engine/install/) |
> | macOS | [Docker Desktop](https://docs.docker.com/desktop/install/mac-install/) |
> | Windows | [Docker Desktop](https://docs.docker.com/desktop/install/windows-install/) with WSL2 |
>
> Verify Docker is running before use: `docker info`

## What it does

Given a GitHub repository URL or a link to a zip archive, this skill instructs Claude to:

1. Create an isolated Docker volume and download the code into it
2. Strip all execute permissions before any analysis begins
3. Statically analyze the code for malicious patterns using `--network none` containers
4. Follow any embedded download URLs and inspect those payloads inside the sandbox too
5. Write a structured Markdown report to `./codescan-reports/` on your machine
6. Destroy the Docker volume — removing all repo content from your system

## Trigger phrases

- "Scan this repo and tell me if it's safe to run: `<url>`"
- "Check if this GitHub repo is malicious: `<url>`"
- "Is it safe to install this? `<url>`"
- "Run a security scan on `<url>`"

## What it detects

- **Obfuscation** — base64/hex encoded payloads, eval/exec patterns
- **Download & execute** — `curl | bash`, `wget | sh`, fetching and running remote scripts
- **Supply chain hooks** — malicious `postinstall`, `setup.py`, `__init__.py` install triggers
- **Credential harvesting** — reading env vars, `.env` files, SSH keys, cloud credentials
- **Reverse shells** — outbound connection patterns, netcat, socat
- **Cryptominers** — known miner binaries and pool addresses
- **Data exfiltration** — sending data to remote endpoints
- **Suspicious domains/IPs** — hardcoded C2 infrastructure indicators
- **Privilege escalation** — sudo abuse, SUID bits, cron injection
- **Recursive payloads** — secondary download URLs fetched and inspected inside the sandbox

## Output

The skill writes a Markdown report to `./codescan-reports/scan-report-YYYYMMDD-HHMMSS.md`:

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

### Claude Code
```bash
# Clone and copy the skill into your Claude skills directory
git clone https://github.com/tkdtaylor/CodeScan /tmp/CodeScan
cp -r /tmp/CodeScan/code-scanner ~/.claude/skills/
```

### Claude.ai
1. Download or zip this repository's `code-scanner/` folder
2. Go to Settings → Capabilities → Skills
3. Upload the zip

## Skill structure

```
code-scanner/           ← skill folder (upload this)
├── SKILL.md            ← main skill file (required)
└── references/
    ├── patterns.md     ← malicious pattern reference library
    └── report-template.md ← output format template
```

## How the Docker sandbox works

```
Host machine
├── ./codescan-reports/        ← report .md files written here (host)
│   └── scan-report-*.md
│
└── Docker volume: codescan-TIMESTAMP  ← all repo content stays here
    └── /scan/repo/            ← cloned repository (non-executable)
        └── ...                ← never touches the host filesystem

After scan: docker volume rm codescan-TIMESTAMP
            → volume and all contents permanently deleted
```

Each analysis step runs in a container with:
- `--network none` — no outbound connections during analysis
- `--cap-drop ALL` — no Linux capabilities
- `--security-opt no-new-privileges` — no privilege escalation

## Contributing

Issues and PRs welcome.

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

**Free for:** personal use, research, education, hobby projects, charitable and government organisations.

**Commercial use** (companies, paid products, internal business tooling) requires a separate commercial license. Contact: kevin@taylorguard.me
