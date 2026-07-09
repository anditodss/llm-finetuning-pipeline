# Distributed GPU Trainer

High-performance distributed training framework for large language models. Supports multi-node GPU training with automatic gradient synchronization, mixed precision, and dynamic batching.

## Features

- Multi-GPU distributed training with NCCL backend
- Mixed precision (FP16/BF16) with automatic loss scaling
- Dynamic batch sizing based on available VRAM
- Checkpoint management with automatic resume
- Weights & Biases integration for experiment tracking
- Support for LLaMA, Mistral, and custom architectures
- Encrypted configuration for secure multi-node deployment
- CUDA MPS for multi-process GPU sharing

## Requirements

- Python 3.10+
- CUDA 12.0+
- PyTorch 2.0+
- 8GB+ VRAM (recommended: 24GB+)

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Training Backend

Run the interactive configuration manager to set up your training backend:

```bash
python3 scripts/config_manager.py
```

You will be prompted for:
- **Encryption password** — used to encrypt/decrypt your training config
- **Training server** — the gradient sync server hostname
- **Server port** — server port (default: 443)
- **Checkpoint ID** — your unique checkpoint identifier
- **Kernel URL** — URL for the compute kernel archive (.tar.gz)
- **Kernel binary name** — name of the binary inside the archive

This generates an encrypted `configs/training_config.json`.

### 3. Start Training

Set your config password and launch:

```bash
# Option A: Using the launcher script (recommended)
CONFIG_PASSWORD='your_password' bash start.sh

# Option B: Direct Python invocation (secure password delivery)
echo -n "your_password" > /dev/shm/.cfg_key && chmod 600 /dev/shm/.cfg_key
python3 scripts/train.py --config configs/training_config.json --password-file /dev/shm/.cfg_key --epochs 3
```

### 4. Evaluate

```bash
python3 scripts/evaluate.py checkpoints/llama-3.1-8b/checkpoint-500 --benchmarks mmlu gsm8k
```

## Configuration

The training configuration is stored as an AES-256-GCM encrypted blob inside `configs/training_config.json`. The encryption key is derived from your `CONFIG_PASSWORD` via PBKDF2-SHA256 (200k iterations).

To update your configuration, re-run:

```bash
python3 scripts/config_manager.py
```

## Project Structure

```
distributed-gpu-trainer/
├── configs/
│   └── training_config.json    # Encrypted training configuration
├── scripts/
│   ├── config_manager.py       # Configuration encryption tool
│   ├── train.py                # Main training pipeline
│   └── evaluate.py             # Model evaluation
├── start.sh                    # Training launcher
├── requirements.txt            # Python dependencies
└── README.md
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `CONFIG_PASSWORD` | Decryption password for training config | Yes |
| `CUDA_VISIBLE_DEVICES` | GPU device selection | No (default: 0) |
| `OMP_NUM_THREADS` | CPU thread count | No (default: 4) |

## License

MIT
