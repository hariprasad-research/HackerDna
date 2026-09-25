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

# Reverse Engineering — Sentinel Activate

## 0. Enter the Challenge Directory

```bash
cd ~/Desktop/HackerDna/"Reverse Engineering: License Key Crackme"
```

Check the files:

```bash
ls
```

You should have:

```text
sentinel-activate
```

---

# PART A — Understand the Binary

## 1. Identify the Binary

```bash
file sentinel-activate
```

Look for:

```text
ELF 64-bit
ARM aarch64
not stripped
```

### Why?

- `aarch64` tells us the CPU architecture.
- `not stripped` means useful function names may still be available.

---

# PART B — Find Interesting Strings

## 2. Search Strings

```bash
strings sentinel-activate
```

Better:

```bash
strings sentinel-activate | grep -E 'decode_token|derive_key|validate|g_token_enc|User Flag|SENT-'
```

Look for:

```text
decode_token
derive_key
validate
g_token_enc
User Flag: %s
SENT-%c%c%c%c-%c%c%c%c-%c%c%c%c
```

### What this tells us

```text
decode_token → probably handles hidden flag
derive_key   → probably creates license key
validate     → probably checks license
```

`User Flag: %s` is an important clue.

---

# PART C — Find Function Addresses

## 3. List Symbols

```bash
aarch64-linux-gnu-objdump -t sentinel-activate | grep -E 'decode_token|derive_key|validate|main'
```

Example:

```text
400744  decode_token
4007b0  derive_key
4009f8  validate
```

You don't need to memorize the addresses.

---

# PART D — Find the User Flag

## 4. Find `g_token_enc`

```bash
aarch64-linux-gnu-nm -a sentinel-activate | grep g_token_enc
```

You should find something similar to:

```text
0000000000400cc0 r g_token_enc
```

This means:

```text
g_token_enc
    ↓
address = 0x400cc0
```

This is the location of the **obfuscated User Flag data**.

The challenge documentation identifies it as a **36-byte blob**.

---

## 5. Find the Section Containing It

```bash
aarch64-linux-gnu-objdump -h sentinel-activate | grep -E 'rodata|text|data'
```

Look for:

```text
.rodata
```

### Why?

`g_token_enc` is stored in read-only data (`.rodata`).

---

## 6. Dump `.rodata`

```bash
aarch64-linux-gnu-objdump -s -j .rodata sentinel-activate
```

You'll see something similar to:

```text
400cb8  01000200 00000000 62633b3c 6c6e3c6d
400cc8  77383938 3e776e63 6a3b7762 6f6e6877
400cd8  3f386f3e 3f6a3f3e 6e6c393f 00000000
```

---

## 7. Extract the Correct Bytes

We found:

```text
g_token_enc = 0x400cc0
```

Therefore, start reading at:

```text
400cc0
```

**Do not include `400cc8` or `400cd8`.**

Those are addresses printed by `objdump`, not data.

The 36 bytes are:

```text
62633b3c6c6e3c6d773839383e776e636a3b77626f6e68773f386f3e3f6a3f3e6e6c393f
```

---

## 8. Decode the Bytes

`decode_token()` XORs each byte with:

```text
0x5A
```

Conceptually:

```text
encrypted byte
      ↓
   XOR 0x5A
      ↓
plain character
```

Run your helper:

```bash
python3 DecodeFlag.py
```

Or use:

```python
binary = "sentinel-activate"

offset = 0xCC0
length = 36

with open(binary, "rb") as f:
    f.seek(offset)
    encrypted = f.read(length)

decoded = bytes(b ^ 0x5A for b in encrypted)

print("[+] User Flag:")
print(decoded.decode())
```

Run:

```bash
python3 DecodeFlag.py
```

Expected format:

```text
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

That is the **User Flag**.

---

# PART E — Understand the License Key

## 9. Inspect `derive_key`

```bash
aarch64-linux-gnu-objdump -d sentinel-activate | less
```

Inside `less`:

```text
/derive_key
```

Press Enter.

The function transforms:

```text
account name
      ↓
calculation
      ↓
6 bytes
      ↓
12 hexadecimal characters
      ↓
SENT-XXXX-XXXX-XXXX
```

Important operations:

```text
× 27
+ 61
XOR 71
+ character index
XOR account length
rolling XOR into 6-byte buffer
```

---

## 10. Use `KeyGen.py`

The algorithm has been reproduced in Python.

Run:

```bash
python3 KeyGen.py
```

It asks:

```text
Account name:
```

For a test account in the authorized lab, enter the account name.

Example:

```text
admin
```

It produces:

```text
SENT-XXXX-XXXX-XXXX
```

This is **not brute force**. It is a reproduction of the `derive_key()` algorithm found in the binary.

---

# PART F — Test the License

## 11. Make the Binary Executable

If you get:

```text
Permission denied
```

run:

```bash
chmod +x sentinel-activate
```

Then:

```bash
./sentinel-activate --account admin --key YOUR_KEY
```

Replace `YOUR_KEY` with the key generated by `KeyGen.py`.

---

# PART G — Get the Second Flag

If the admin license is accepted, the program unlocks the privileged/premium path.

Follow the challenge's activation flow and look for the **root/admin flag**.

The important distinction is:

```text
                 sentinel-activate
                       │
          ┌────────────┴────────────┐
          ↓                         ↓
    decode_token()             derive_key()
          ↓                         ↓
     User Flag               Admin License Key
                                    ↓
                               validate()
                                    ↓
                              privileged access
                                    ↓
                              Root/Admin Flag
```

---

# 🧠 What You Should Remember for a CTF

You don't need to memorize every command.

Remember this workflow:

```text
1. file
      ↓
2. strings
      ↓
3. objdump -t / nm
      ↓
4. Find interesting function/data
      ↓
5. Find address
      ↓
6. Dump section
      ↓
7. Extract bytes
      ↓
8. Understand the decoding algorithm
      ↓
9. Reproduce algorithm with Python
      ↓
10. Get flag
```

---

# Most Important Commands

### Identify the binary

```bash
file sentinel-activate
```

### Search useful strings

```bash
strings sentinel-activate | grep -E 'decode_token|derive_key|validate|g_token_enc|User Flag|SENT-'
```

### Find `g_token_enc`

```bash
aarch64-linux-gnu-nm -a sentinel-activate | grep g_token_enc
```

### Dump `.rodata`

```bash
aarch64-linux-gnu-objdump -s -j .rodata sentinel-activate
```

### Disassemble the binary

```bash
aarch64-linux-gnu-objdump -d sentinel-activate | less
```

### Run the flag decoder

```bash
python3 DecodeFlag.py
```

### Run the key generator

```bash
python3 KeyGen.py
```

### Make the binary executable

```bash
chmod +x sentinel-activate
```

---

# Complete From-Scratch Workflow

```text
Enter challenge directory
        ↓
Identify binary with file
        ↓
Search strings
        ↓
Find useful symbols
        ↓
Locate g_token_enc
        ↓
Find .rodata
        ↓
Extract encoded bytes
        ↓
Understand decode_token()
        ↓
XOR bytes with 0x5A
        ↓
Recover User Flag
        ↓
Inspect derive_key()
        ↓
Understand key-generation operations
        ↓
Reproduce algorithm in Python
        ↓
Generate a test license key
        ↓
Validate in the authorized lab
        ↓
Observe the resulting lab output
```

---

# Final Takeaway

The key reverse-engineering concepts demonstrated by this lab are:

1. **Identify the binary architecture**
2. **Use strings for reconnaissance**
3. **Use symbols when the binary is not stripped**
4. **Locate interesting data and functions**
5. **Understand how data is transformed**
6. **Translate assembly logic into higher-level pseudocode**
7. **Reimplement the discovered algorithm in Python**
8. **Verify the result in the authorized CTF/lab environment**

The important mindset is:

```text
Inspect
  ↓
Locate
  ↓
Disassemble
  ↓
Understand
  ↓
Reimplement
  ↓
Verify
```
