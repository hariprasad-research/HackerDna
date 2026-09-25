# Week 5 — Reverse Engineering Lab: Sentinel Activate

## Objective

The goal of this lab is to understand the ARM64 `sentinel-activate` binary, reverse the `derive_key()` algorithm, reproduce it in Python, and understand how a valid license key is generated.

### Overall Flow

```text
Account name
     ↓
derive_key()
     ↓
Valid license key
     ↓
Admin account
     ↓
Flag
```

> **Important:** We do not guess the admin key. We reverse the algorithm that generates it.

---

# Part 1 — Understand What We Are Looking For

The challenge uses an ARM64 binary named:

```text
sentinel-activate
```

The important functions are:

- `decode_token`
- `derive_key`
- `validate`
- `main`

The main focus is `derive_key()` because it generates the license key from an account name.

---

# Step 1 — Get the Binary

Download:

```text
sentinel-activate
```

Check the binary type:

```bash
file sentinel-activate
```

Expected output will be similar to:

```text
ELF 64-bit LSB executable, ARM aarch64
```

### Why?

This tells us the architecture of the binary.

Here:

```text
ARM aarch64
```

means the program contains ARM64 instructions.

The binary is also **not stripped**, which is useful because function names are still available.

---

# Step 2 — Look at Strings

Run:

```bash
strings sentinel-activate
```

Look for useful strings such as:

```text
decode_token
derive_key
validate
g_token_enc
--account
--key
--diag
User Flag: %s
```

### Why are these useful?

They give us a roadmap for the binary:

```text
decode_token → handles the encoded token/flag

derive_key → generates the license key

validate → checks whether the supplied key is valid

main → handles program execution and arguments
```

Instead of reversing the entire binary, we can focus on the relevant functions.

---

# Step 3 — Inspect the Symbols

Run:

```bash
aarch64-linux-gnu-objdump -t sentinel-activate
```

Look for:

```text
decode_token
derive_key
validate
main
```

The relevant addresses from the lab walkthrough are:

```text
decode_token → 0x400744
derive_key   → 0x4007b0
validate     → 0x4009f8
main         → 0x400ac4
```

### Why?

Because the binary is not stripped, we can see meaningful function names instead of generic names such as:

```text
sub_4007b0
```

This makes reverse engineering much easier.

---

# Step 4 — Find the Hidden Flag Mechanism

An important global object is:

```text
g_token_enc
```

The walkthrough identifies it as a **36-byte blob** at:

```text
0x400cc0
```

The function responsible for decoding it is:

```text
decode_token
```

---

# Step 5 — Understand `decode_token`

The important ARM64 instructions include:

```text
ldrb
mov ... 0x5a
eor
strb
```

The important instruction is:

```text
eor
```

`EOR` is the ARM64 XOR operation.

The function essentially performs:

```text
encoded_byte XOR 0x5A
```

for each byte.

The overall process is:

```text
g_token_enc
     ↓
XOR every byte with 0x5A
     ↓
Decoded text
     ↓
UUID
     ↓
User Flag
```

### Important Lesson

Simply running:

```bash
strings sentinel-activate
```

may not reveal the flag because the data is obfuscated.

---

# Step 6 — Move to `derive_key`

Now we focus on the most important function:

```text
derive_key
```

Disassemble the binary:

```bash
aarch64-linux-gnu-objdump -d sentinel-activate
```

Then locate the section around:

```text
derive_key
```

The function processes every character in the account name.

It starts with a:

```text
6-byte buffer = zeros
```

Then each character is transformed and accumulated into the buffer.

---

# Step 7 — Follow One Character

Suppose the account name is:

```text
admin
```

Take the first character:

```text
a
```

Its ASCII value is:

```text
97
```

The algorithm transforms the character through several operations:

```text
character
    ↓
multiply by 27
    ↓
add 61
    ↓
XOR 71
    ↓
add character index
    ↓
XOR account length
```

These operations are then accumulated into the 6-byte buffer.

---

# Step 8 — Understand ×27

The ARM64 implementation represents multiplication by 27 using shifts/additions.

For example:

```text
(c << 1) + c
```

produces:

```text
c × 3
```

And:

```text
(c << 3) + c
```

produces:

```text
c × 9
```

Together:

```text
3 × 9 = 27
```

So the effective operation is:

```text
c × 27
```

---

# Step 9 — Add 61

Next:

```text
c = c + 61
```

The Python representation can use:

```python
(c + 0x3d) & 0xFF
```

because:

```text
0x3d = 61
```

and:

```text
& 0xFF
```

keeps the result within one byte.

---

# Step 10 — XOR with 71

Next:

```text
c = c XOR 71
```

In hexadecimal:

```text
71 decimal = 0x47
```

So the Python representation is:

```python
c ^ 0x47
```

---

# Step 11 — Add the Character Index

Next:

```text
c = c + i
```

where:

```text
i = character position
```

For:

```text
admin
```

the indexes are:

```text
a → 0
d → 1
m → 2
i → 3
n → 4
```

Therefore:

```text
a → +0
d → +1
m → +2
i → +3
n → +4
```

---

# Step 12 — XOR with Account Length

The account:

```text
admin
```

contains:

```text
5 characters
```

Therefore:

```text
name_len = 5
```

Each transformed character is then:

```text
c XOR 5
```

The account-name length is therefore part of the key-generation algorithm.

---

# Step 13 — Put the Result into the 6-Byte Buffer

The program maintains:

```text
buf[0]
buf[1]
buf[2]
buf[3]
buf[4]
buf[5]
```

Initially:

```text
0 0 0 0 0 0
```

For each character:

```text
buf[j] = buf[j] XOR c
```

Then:

```text
j = j + 1
```

When `j` reaches 6:

```text
j = 0
```

This creates a **rotating 6-byte buffer**.

### Concept

```text
Character 1 → buf[0]
Character 2 → buf[1]
Character 3 → buf[2]
Character 4 → buf[3]
Character 5 → buf[4]
Character 6 → buf[5]
Character 7 → buf[0]
...
```

---

# Step 14 — Convert the Buffer to Hexadecimal

After all account characters are processed, the program has:

```text
6 bytes
```

Each byte is represented using:

```text
2 hexadecimal characters
```

Therefore:

```text
6 × 2 = 12 hexadecimal characters
```

Example:

```text
A1B2C3D4E5F6
```

The program formats those characters as:

```text
SENT-A1B2-C3D4-E5F6
```

So the final license-key structure is:

```text
SENT-XXXX-XXXX-XXXX
```

---

# Step 15 — Why Create `KeyGen.py`?

The purpose of `KeyGen.py` is to reproduce the behavior discovered in the ARM64 assembly.

We are not using Python to magically crack the binary.

The process is:

```text
ARM64 instructions
       ↓
Understand operations
       ↓
Translate operations into Python
       ↓
KeyGen.py
       ↓
Generate license key
```

This is a core reverse-engineering technique: **reimplementing a discovered algorithm in a higher-level language.**

---

# Step 16 — KeyGen Algorithm

The Python implementation should perform these steps:

```text
1. Create a 6-byte buffer
2. Get the account length
3. Loop through each character
4. Convert character to ASCII
5. Multiply by 27
6. Add 61
7. XOR with 71
8. Add the character index
9. XOR with the account length
10. XOR the result into buffer[j]
11. Rotate j
12. Convert the buffer to hexadecimal
13. Format as SENT-XXXX-XXXX-XXXX
```

---

# Step 17 — Generate a Key for an Account

After saving your `KeyGen.py` script:

```bash
python KeyGen.py
```

When prompted for an account name, enter the account you are authorized to test in the lab environment.

The script should produce a value in the format:

```text
SENT-XXXX-XXXX-XXXX
```

The key is generated mathematically from the reversed algorithm rather than guessed.

---

# Step 18 — Understand Why the Generated Key Works

The validation flow can be understood conceptually as:

```text
Account name
      ↓
derive_key(account)
      ↓
Expected key
      ↓
Compare with supplied key
      ↓
Accept / Reject
```

If the Python implementation correctly reproduces `derive_key()`, the generated key should match the expected value for that account in the lab.

---

# Step 19 — Understand the Full Lab Flow

The complete reverse-engineering workflow is:

```text
sentinel-activate
       ↓
strings
       ↓
identify useful symbols
       ↓
decode_token
       ↓
understand token decoding
       ↓
derive_key
       ↓
reverse key-generation algorithm
       ↓
implement KeyGen.py
       ↓
generate a test license key
       ↓
validate in the authorized lab
       ↓
observe the resulting lab output
```

---

# 🧠 Test / Viva Explanation

If someone asks:

### "How did you find the license key?"

A strong answer is:

> **"I first identified the `derive_key` function in the unstripped ARM64 binary. I traced its operations: multiplying each character by 27, adding 61, XORing with 71, adding the character index, XORing with the account length, and accumulating the results in a rotating 6-byte buffer. I reproduced that algorithm in Python and used it to generate the license key for the test account."**

---

# Key Reverse-Engineering Lessons

## 1. Identify the architecture

```bash
file sentinel-activate
```

This tells us how to interpret the instructions.

## 2. Use strings for reconnaissance

```bash
strings sentinel-activate
```

Useful strings can reveal:

- Function names
- Command-line arguments
- Error messages
- Validation logic clues
- Encoded-data names

## 3. Use symbols when available

```bash
aarch64-linux-gnu-objdump -t sentinel-activate
```

An unstripped binary can expose useful function names.

## 4. Follow data transformations

For `decode_token`:

```text
byte → XOR 0x5A → decoded byte
```

For `derive_key`:

```text
character
→ ×27
→ +61
→ XOR 71
→ +index
→ XOR length
→ rotating 6-byte XOR buffer
→ hexadecimal
→ formatted key
```

## 5. Reimplement the algorithm

Reverse engineering is not only about reading assembly.

A common workflow is:

```text
Assembly
   ↓
Logic
   ↓
Pseudocode
   ↓
Python implementation
   ↓
Verification
```

---

# Quick Command Reference

```bash
# Identify binary
file sentinel-activate

# Inspect readable strings
strings sentinel-activate

# Inspect symbols
aarch64-linux-gnu-objdump -t sentinel-activate

# Disassemble
aarch64-linux-gnu-objdump -d sentinel-activate

# Run the Python reimplementation
python KeyGen.py
```

---

# Final Summary

The important discovery was that the license key is **deterministic**.

It is derived from:

```text
account name
     +
character index
     +
account length
     +
fixed arithmetic/XOR operations
     ↓
6-byte rotating buffer
     ↓
12 hexadecimal characters
     ↓
SENT-XXXX-XXXX-XXXX
```

Therefore, the correct reverse-engineering approach is:

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

That demonstrates the actual reasoning behind the lab rather than simply running a prepared script.
