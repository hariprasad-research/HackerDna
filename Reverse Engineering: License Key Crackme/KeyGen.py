def derive_key(account_name):
    buf = [0] * 6
    name_len = len(account_name)

    j = 0

    for i, c in enumerate(account_name):
        c = ord(c)

        # Multiply by 27
        c = (c << 1) + c
        c = (c << 3) + c

        # Add 61
        c = (c + 0x3D) & 0xFF

        # XOR with 71
        c = c ^ 0x47

        # Add character index
        c = (c + i) & 0xFF

        # XOR with account name length
        c = c ^ name_len

        # Rolling 6-byte XOR buffer
        buf[j] = (buf[j] ^ c) & 0xFF

        j = (j + 1) % 6

    # Convert 6 bytes → 12 hexadecimal characters
    hex_chars = "0123456789ABCDEF"
    result = ""

    for b in buf:
        result += hex_chars[(b >> 4) & 0xF]
        result += hex_chars[b & 0xF]

    return f"SENT-{result[0:4]}-{result[4:8]}-{result[8:12]}"


# Ask for account name
account = input("Account name: ")

key = derive_key(account)

print("\n[+] Account:", account)
print("[+] License Key:", key)
