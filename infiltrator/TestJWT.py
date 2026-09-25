import jwt

try:
    with open("jwt.txt") as f:
        token = f.read().strip()
except:
    print("[-] jwt.txt not found")
    exit()

secret = "!!!secret!!!"

try:
    data = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"verify_exp": False}
    )

    print("[+] SECRET IS VALID")
    print("[+] Payload:", data)

except jwt.InvalidSignatureError:
    print("[-] Wrong secret")

except Exception as e:
    print("[-] Error:", e)
