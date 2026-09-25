# Sentinel License Key Crackme — ARM64 Reverse Engineering Walkthrough

**Lab**: [Reverse Engineering: License Key Crackme](https://hackerdna.com/labs/reverse-engineering-crackme)
**Platform**: HackerDNA
**Category**: Reverse Engineering
**Architecture**: ARM64 (aarch64)

---

## Overview

This challenge presents a Linux license validation binary called `sentinel-activate` — an ARM64 ELF that validates license keys for a fictional "Sentinel License Manager." The goal is to reverse engineer the binary, understand the key validation algorithm, recover a hidden flag, and forge a valid admin license key.

It's a hands-on crackme that tests static analysis, ARM64 disassembly reading, and cryptographic primitive reversal — no bruteforce needed, just clear thinking and a disassembler.

**Lab link**: [https://hackerdna.com/labs/reverse-engineering-crackme](https://hackerdna.com/labs/reverse-engineering-crackme)

---

## Reconnaissance

The challenge starts with a web portal at the target IP — **Sentinel License Manager** running on nginx.

The portal offers:
1. A download link for the `sentinel-activate` binary (ARM64 ELF)
2. A trial license key: `SENT-3B00-1C47-EF00` for account `trial`
3. A web form at `/activate` that validates license keys server-side

**First step**: Download the binary and check what we're dealing with.

```bash
$ file sentinel-activate
sentinel-activate: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, not stripped
```

A 70KB ARM64 binary, dynamically linked, **not stripped** — symbol names intact. This is a gift for static analysis.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `strings` | Quick reconnaissance of embedded strings and function names |
| `aarch64-linux-gnu-objdump` | ARM64 disassembly and symbol table inspection |
| `qemu-user-static` | Running the ARM64 binary on an x86_64 host |
| Python 3 | Writing the keygen and testing the algorithm |
| `curl` | Interacting with the web activation endpoint |

---

## Step 1 — Reconnaissance

The lab presents a web portal — **Sentinel License Manager** — with:

- A download link for the `sentinel-activate` binary
- A trial license key (`SENT-3B00-1C47-EF00` for account `trial`)
- A web form at `/activate` that validates license keys server-side

**First move**: Download the binary and run `strings` to get a lay of the land.

```bash
$ file sentinel-activate
sentinel-activate: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, not stripped
```

Key strings found:
- `decode_token`, `derive_key`, `validate`, `g_token_enc` — function names
- `SENT-%c%c%c%c-%c%c%c%c-%c%c%c%c` — license key format
- `--account`, `--key`, `--diag` — CLI arguments
- `User Flag: %s` — hidden output
- `g_token_enc` — a 36-byte obfuscated blob in `.rodata`

---

## Step 1 — Decoding the Hidden Token

The symbol table revealed `g_token_enc` — a 36-byte blob at address `0x400cc0`. The `decode_token` function XORs each byte with `0x5A`:

```asm
decode_token:
  ldrb  w2, [x1, x0]      // load byte from g_token_enc
  mov   w1, #0x5a          // XOR key
  eor   w1, w2, w1         // XOR each byte with 0x5A
  strb  w1, [x0]           // store decoded byte
  // loop 36 times (0x23 = 35, so 0..35 = 36 bytes)
```

A quick Python one-liner reveals the decoded content — a UUID that serves as the user flag.

**Insight**: XOR obfuscation is the simplest form of hiding data in a binary. It won't stop a determined analyst, but it prevents casual `strings` discovery. Always check `.rodata` for suspicious blobs when reverse engineering.

---

## Step 2 — Understanding the Validation Logic

The `main` function parses three CLI flags:
- `--account <name>` — the account to validate
- `--key <SENT-XXXX-XXXX-XXXX>` — the license key
- `--diag` — diagnostic mode that decodes and prints the hidden user flag

The `validate(account, key)` function:
1. Calls `derive_key(account)` to compute the expected key
2. Uppercases the input key
3. Compares them with `strcmp`

## Step 3 — Reversing the Key Derivation Algorithm

The `derive_key` function is the heart of the challenge. Here's what it does:

1. Initializes a 6-byte buffer to all zeros
2. For each character in the account name, applies a series of transforms:
   - Multiply by 27
   - Add 61
   - XOR with 71
   - Add the character's position index
   - XOR with the account name length
3. XORs the result into a rotating 6-byte buffer (index wraps at 6)
4. Converts the final 6-byte buffer to 12 hex characters
5. Formats the result as `SENT-XXXX-XXXX-XXXX`

The `validate` function then:
1. Calls `derive_key(account)` to compute the expected key
2. Uppercases the user-supplied key
3. Compares them with `strcmp`

## The Keygen

With the algorithm understood, writing a keygen is straightforward:

```python
def derive_key(account_name):
    buf = [0] * 6
    name_len = len(account_name)
    j = 0

    for i, c in enumerate(account_name):
        c = ord(c)
        c = (c << 1) + c       # multiply by 3
        c = (c << 3) + c       # multiply by 27 total
        c = (c + 0x3d) & 0xFF  # add 61
        c = c ^ 0x47           # XOR with 71
        c = (c + i) & 0xFF     # add character index
        c = c ^ name_len       # XOR with name length
        buf[j] = (buf[j] ^ c) & 0xFF
        j = (j + 1) % 6

    # Convert 6-byte buffer to 12 hex chars
    hex_chars = '0123456789ABCDEF'
    result = ''
    for b in buf:
        result += hex_chars[(b >> 4) & 0xf]
        result += hex_chars[b & 0xf]
    return f'SENT-{result[0:4]}-{result[4:8]}-{result[8:12]}'
```

This keygen can forge a valid license key for **any** account name.

---

## Methodology

### Phase 1 — Static Analysis

**Tools**: `strings`, `aarch64-linux-gnu-objdump`

The binary was not stripped, so all function names were preserved in the symbol table. This is a huge advantage — instead of guessing what each subroutine does, the names tell you directly:

| Function | Address | Purpose |
|----------|---------|---------|
| `decode_token` | `0x400744` | XOR-decodes a 36-byte obfuscated blob |
| `derive_key` | `0x4007b0` | Derives a license key from an account name |
| `validate` | `0x4009f8` | Compares derived key against user input |
| `main` | `0x400ac4` | Argument parsing and orchestration |

**Insight**: Always check if a binary is stripped. Preserved symbol names are a massive time-saver — they tell you exactly what each function does.

### Phase 2 — Understanding decode_token

The `g_token_enc` blob at `0x400cc0` is 36 bytes of seemingly random data. The `decode_token` function XORs each byte with `0x5A`:

```asm
decode_token:
  ldrb  w2, [x1, x0]      // load byte from g_token_enc
  mov   w1, #0x5a          // XOR key
  eor   w1, w2, w1         // XOR
  strb  w1, [x0]           // store decoded byte
  // loop 36 times
```

This is textbook XOR obfuscation — simple to implement, trivial to reverse. The decoded result is a UUID that serves as the user flag.

**Learning insight**: XOR obfuscation in `.rodata` is one of the most common hiding techniques in crackmes. It won't stop a determined analyst, but it prevents casual `strings` discovery. Always dump and inspect data sections when reverse engineering.

### Phase 2 — Reversing the Key Derivation

The `derive_key` function is the heart of the challenge. It transforms an account name into a 12-hex-character license key through a series of arithmetic and logical operations:

1. **Initialize** a 6-byte rolling buffer to zero
2. **For each character** in the account name:
   - Multiply by 27
   - Add 61
   - XOR with 71
   - Add the character's position index
   - XOR with the account name length
   - XOR into the rotating buffer position
3. **Convert** the 6-byte buffer to 12 hex characters
4. **Format** as `SENT-XXXX-XXXX-XXXX`

The `validate` function then uppercases the user's input and compares it against the derived key using `strcmp`.

### Phase 3 — The Admin Key

With the keygen working, generating the admin key is trivial — just run `derive_key("admin")` and format the result. The admin key unlocks premium tier on the web portal and reveals the root flag.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `strings` | Initial reconnaissance of embedded strings and symbol names |
| `aarch64-linux-gnu-objdump` | Full ARM64 disassembly with symbol table |
| `qemu-user-static` | Running ARM64 binaries on x86_64 via user-mode emulation |
| Python 3 | Writing the keygen and testing the algorithm |
| `curl` | Interacting with the web activation endpoint |

## Key Learning Insights

### 1. Symbol names are your roadmap
An unstripped binary gives you the function names for free. `decode_token`, `derive_key`, and `validate` tell you exactly what each subroutine does before you read a single instruction.

### 2. XOR obfuscation is everywhere in crackmes
It's the simplest hiding technique — XOR each byte with a constant key. It stops `strings` but falls to the most basic static analysis. Always dump `.rodata` and look for suspicious blobs.

### 3. ARM64 is approachable with the right tools
The ARM64 instruction set is clean and regular. With `aarch64-linux-gnu-objdump` and a reference for instructions like `ubfiz`, `eor`, and `strb`, you can read the disassembly fluently even without hardware.

### 4. Rolling XOR is a common key derivation pattern
The 6-byte rolling buffer with XOR accumulation is a lightweight way to derive a fixed-size key from variable-length input. It's not cryptographically secure, but it's compact and fast — exactly what you'd expect in a license key validator.

---

## Lab Link

Try this challenge yourself: [https://hackerdna.com/labs/reverse-engineering-crackme](https://hackerdna.com/labs/reverse-engineering-crackme)

---

## Key Takeaways

1. **Always check if a binary is stripped** — preserved symbol names are a roadmap to the code.
2. **Dump `.rodata`** — obfuscated data blobs (XOR, ROT, base64) are often hiding flags or keys.
3. **ARM64 disassembly is readable** — with `objdump` and a reference for `ubfiz`, `eor`, and `strb`, you can trace through the logic without hardware.
4. **Keygen is the goal** — understanding the algorithm well enough to reproduce it is the point of a crackme. Don't just patch the binary; write a generator.
5. **Check for diagnostic modes** — the `--diag` flag was a deliberate easter egg that revealed the user flag directly.

## Lab Link

Try this challenge yourself: [https://hackerdna.com/labs/reverse-engineering-crackme](https://hackerdna.com/labs/reverse-engineering-crackme)