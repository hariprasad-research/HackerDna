hex_data = input("Enter encrypted bytes: ").replace(" ", "").strip()

data = bytes.fromhex(hex_data)

if len(data) != 36:
    print(f"[-] Error: expected 36 bytes, got {len(data)} bytes")
    exit()

decoded = bytes(b ^ 0x5A for b in data)

flag = decoded.decode()

print("\n[+] Decoded User Flag:", flag)
print("[+] Length:", len(flag))

if len(flag) == 36 and flag.count("-") == 4:
    print("[+] UUID format: OK")
else:
    print("[-] UUID format: WRONG")
