import jwt

secret = "!!!secret!!!"

payload = {
    "username": "admin",
    "role": "admin",
    "exp": 4102444800
}

token = jwt.encode(
    payload,
    secret,
    algorithm="HS256"
)

print("\n[+] ADMIN JWT\n")
print(token)

with open("admin_jwt.txt", "w") as f:
    f.write(token)

print("\n[+] Saved to admin_jwt.txt")
