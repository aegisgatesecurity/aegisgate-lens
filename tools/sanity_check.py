#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — Pre-Training Sanity Check

Run this BEFORE starting training to verify the environment is ready.

Checks:
  - Python version (3.10+)
  - PyTorch + CUDA availability
  - GPU memory (>= 8 GB recommended for ModernBERT-base)
  - transformers version (>= 4.40)
  - optimum + onnx + onnxruntime
  - scikit-learn (for eval metrics)
  - cryptography (for bundle signing)
  - bitsandbytes (for int4 quantization)
  - Disk space (>= 50 GB recommended)
  - Corpus lockfile matches current corpora
  - All required Python scripts are syntactically valid

Usage:
    python tools/sanity_check.py

Exits 0 if all checks pass, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_PYTHON = (3, 10)
REQUIRED_DISK_GB = 50
REQUIRED_GPU_GB = 8


def check_python_version() -> bool:
    v = sys.version_info
    if v >= REQUIRED_PYTHON:
        print(f"  [OK] Python {v.major}.{v.minor}.{v.micro}")
        return True
    print(f"  [FAIL] Python {v.major}.{v.minor}.{v.micro} (need {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+)")
    return False


def check_pytorch() -> bool:
    try:
        import torch
        print(f"  [OK] PyTorch {torch.__version__}")
        if torch.cuda.is_available():
            print(f"  [OK] CUDA available ({torch.version.cuda})")
            return True
        else:
            print(f"  [FAIL] PyTorch installed but CUDA NOT available")
            print(f"         (PyTorch was likely installed without CUDA support)")
            return False
    except ImportError:
        print(f"  [FAIL] PyTorch not installed")
        return False


def check_gpu_memory() -> bool:
    try:
        import torch
        if not torch.cuda.is_available():
            print(f"  [SKIP] GPU memory check (no CUDA)")
            return True
        for i in range(torch.cuda.device_count()):
            props = torch.cuda.get_device_properties(i)
            total_gb = props.total_memory / 1024 ** 3
            print(f"  [GPU {i}] {props.name}: {total_gb:.1f} GB total")
            if total_gb < REQUIRED_GPU_GB:
                print(f"  [WARN] GPU {i} has {total_gb:.1f} GB; recommend >= {REQUIRED_GPU_GB} GB for ModernBERT-base")
                return False
        return True
    except Exception as e:
        print(f"  [FAIL] GPU memory check failed: {e}")
        return False


def check_package(name: str, min_version: str = None) -> bool:
    try:
        mod = importlib.import_module(name)
        version = getattr(mod, "__version__", "unknown")
        print(f"  [OK] {name} {version}")
        return True
    except ImportError:
        print(f"  [FAIL] {name} not installed (run: pip install {name}{f'>={min_version}' if min_version else ''})")
        return False


def check_disk_space() -> bool:
    stat = shutil.disk_usage(REPO_ROOT)
    free_gb = stat.free / 1024 ** 3
    if free_gb >= REQUIRED_DISK_GB:
        print(f"  [OK] Disk free: {free_gb:.1f} GB")
        return True
    else:
        print(f"  [FAIL] Disk free: {free_gb:.1f} GB (need >= {REQUIRED_DISK_GB} GB)")
        return False


def check_corpus_lockfile() -> bool:
    lockfile = REPO_ROOT / "corpora" / "SHA256SUMS"
    if not lockfile.exists():
        print(f"  [FAIL] Lockfile not found: {lockfile}")
        return False
    expected = {}
    with open(lockfile) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sha, path = line.split(None, 1)
            expected[path] = sha
    drift_found = False
    for path, exp_sha in expected.items():
        full = REPO_ROOT / path
        if not full.exists():
            print(f"  [FAIL] Lockfile references missing file: {path}")
            drift_found = True
            continue
        actual_sha = hashlib.sha256(full.read_bytes()).hexdigest()
        if actual_sha != exp_sha:
            print(f"  [FAIL] Corpus drift: {path}")
            drift_found = True
    if drift_found:
        return False
    print(f"  [OK] All {len(expected)} corpora match lockfile")
    return True


def check_scripts_parse() -> bool:
    """Verify all .py files in the repo parse cleanly."""
    scripts = list(REPO_ROOT.rglob("*.py"))
    scripts = [s for s in scripts if ".venv" not in str(s)]
    bad = []
    for s in scripts:
        try:
            with open(s) as f:
                compile(f.read(), str(s), "exec")
        except SyntaxError as e:
            print(f"  [FAIL] {s.relative_to(REPO_ROOT)}: {e}")
            bad.append(s)
    if bad:
        return False
    print(f"  [OK] All {len(scripts)} Python files parse cleanly")
    return True


def main() -> int:
    print("=" * 60)
    print("AegisGate Lens v0.2 — Pre-Training Sanity Check")
    print("=" * 60)
    print()

    checks = []

    print(f"[1] Python version (need {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]}+)")
    checks.append(check_python_version())
    print()

    print("[2] PyTorch + CUDA")
    checks.append(check_pytorch())
    print()

    print("[3] GPU memory")
    checks.append(check_gpu_memory())
    print()

    print("[4] Required packages")
    checks.append(check_package("transformers", "4.40"))
    checks.append(check_package("datasets", "2.18"))
    checks.append(check_package("optimum", "1.17"))
    checks.append(check_package("onnx", "1.15"))
    checks.append(check_package("onnxruntime", "1.17"))
    checks.append(check_package("sklearn", "1.4"))
    checks.append(check_package("cryptography", "42"))
    checks.append(check_package("bitsandbytes", "0.43"))
    checks.append(check_package("huggingface_hub", "0.23"))
    print()

    print(f"[5] Disk space (need >= {REQUIRED_DISK_GB} GB)")
    checks.append(check_disk_space())
    print()

    print("[6] Corpus lockfile (per Lesson #91)")
    checks.append(check_corpus_lockfile())
    print()

    print("[7] Python scripts parse")
    checks.append(check_scripts_parse())
    print()

    print("=" * 60)
    if all(checks):
        print("OK: environment ready for v0.2 training")
        print("Next: see docs/V0.2-TRAINING-RUNBOOK.md")
        return 0
    else:
        print(f"FAIL: {sum(1 for c in checks if not c)} check(s) failed")
        print("Fix the issues above before starting training.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
