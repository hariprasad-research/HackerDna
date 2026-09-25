import jwt
import sys
from datetime import datetime, timezone


COOKIE_FILE = "cookies.txt"


def get_token():
    # If JWT is supplied manually:
    if len(sys.argv) > 1:
        return sys.argv[1].strip()

    # Otherwise automatically read cookies.txt
    try:
        with open(COOKIE_FILE, "r") as f:
            for line in f:
                parts = line.strip().split("\t")

                if len(parts) >= 7 and parts[5] == "jwt":
                    return parts[6]

    except FileNotFoundError:
        print("[-] cookies.txt not found")
        sys.exit(1)

    print("[-] JWT cookie not found in cookies.txt")
    sys.exit(1)


token = get_token()

print("=" * 50)
print("             JWT DECODER")
print("=" * 50)

try:
    header = jwt.get_unverified_header(token)

    payload = jwt.decode(
        token,
        options={"verify_signature": False}
    )

    print("\n[+] HEADER")
    print("-" * 30)

    for key, value in header.items():
        print(f"{key}: {value}")

    print("\n[+] PAYLOAD")
    print("-" * 30)

    for key, value in payload.items():
        print(f"{key}: {value}")

    if "exp" in payload:
        exp = payload["exp"]
        expiry = datetime.fromtimestamp(exp, timezone.utc)

        print("\n[+] EXPIRATION")
        print("-" * 30)
        print(f"Timestamp : {exp}")
        print(f"UTC       : {expiry}")

    print("\n[+] TOKEN STRUCTURE")
    print("-" * 30)
    print(f"Parts: {len(token.split('.'))}")

except jwt.DecodeError:
    print("\n[-] Invalid JWT")

print("\n" + "=" * 50)
