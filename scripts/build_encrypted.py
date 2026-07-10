#!/usr/bin/env python3
"""
Self-Encrypting Python Wrapper Generator
Takes a python script, encrypts it, and wraps it in a decryption stub.
"""

import os
import sys
import base64
import zlib
import argparse
import getpass
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "cryptography"])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

def main():
    parser = argparse.ArgumentParser(description="Encrypt a Python script into a self-decrypting wrapper.")
    parser.add_argument("input", help="Input Python script")
    parser.add_argument("output", help="Output encrypted Python script")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found.")
        sys.exit(1)

    password = getpass.getpass("Encryption password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)

    with open(args.input, "rb") as f:
        plaintext = f.read()

    compressed = zlib.compress(plaintext, level=9)

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000,
    )
    key = kdf.derive(password.encode())

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, compressed, None)

    b64_salt = base64.b64encode(salt).decode()
    b64_nonce = base64.b64encode(nonce).decode()
    b64_ct = base64.b64encode(ciphertext).decode()

    stub = f'''#!/usr/bin/env python3
import sys, os, base64, zlib, getpass
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing cryptography. Please install it.")
    sys.exit(1)

_S = "{b64_salt}"
_N = "{b64_nonce}"
_C = "{b64_ct}"

def _run():
    p = os.environ.get("SCRIPT_PASSWORD")
    if not p:
        p = getpass.getpass("Password: ")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=base64.b64decode(_S), iterations=300_000)
    try:
        k = kdf.derive(p.encode())
        d = AESGCM(k).decrypt(base64.b64decode(_N), base64.b64decode(_C), None)
        exec(zlib.decompress(d), {{"__name__": "__main__"}})
    except Exception:
        print("Decryption failed.")
        sys.exit(1)

if __name__ == "__main__":
    _run()
'''
    with open(args.output, "w") as f:
        f.write(stub)
    os.chmod(args.output, 0o755)

    print(f"Successfully encrypted '{args.input}' -> '{args.output}'")
    print(f"Run with: SCRIPT_PASSWORD='...' python3 {args.output}")

if __name__ == "__main__":
    main()
