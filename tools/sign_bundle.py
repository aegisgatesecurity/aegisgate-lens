#!/usr/bin/env python3
"""
AegisGate Lens v0.2 — Bundle Signing Script (Phase A — pipeline-only)
=====================================================================

Bundles the exported ONNX model + tokenizer + config into a single
Ed25519-signed bundle per the format defined in
`plans/AEGISGATE-LENS-V02-MODEL-DECISION.md` §3.

Bundle format (reproduced for reference):

    aegisgate-lens-{facet}-v0.2.0.bundle
    ├── magic: "AEGISGATE_LENS_BUNDLE_V1"
    ├── header (JSON, signed):
    │   ├── bundle_version: "0.2.0"
    │   ├── facet: "prompt-injection" | "toxicity"
    │   ├── total_payload_size: int
    │   ├── payload_sha256: hex
    │   ├── files: [{name, size, sha256, offset}]
    │   └── signing_pub_key_id: "lens-v02-2026-06-26"
    ├── payload: <concatenated files>
    └── signature: <64 bytes Ed25519>

Keys: Generate a fresh Ed25519 keypair for v0.2. The private key is
NEVER committed to the repo; it's stored in a GitHub Actions secret
(LENS_V02_SIGNING_KEY) at release time.

This script:
    1. Reads files from `models/<facet>-onnx/`
    2. Builds the payload (concatenated file bytes)
    3. Computes payload SHA-256
    4. Builds the JSON header (with file SHA-256s)
    5. Signs (header || payload) with Ed25519
    6. Writes the bundle to `src/vendor/bundles/`

Usage:
    # Generate a new keypair (run ONCE, store privkey in secret store):
    python tools/sign_bundle.py --gen-key --priv-out /tmp/v02-priv.pem \\
        --pub-out src/vendor/bundles/lens-v02-pub.pem

    # Sign a bundle (run per release):
    python tools/sign_bundle.py --facet prompt-injection \\
        --input models/prompt-injection-onnx/ \\
        --priv-key /path/to/v02-priv.pem

Per F-02 from the threat model (LENS-THREAT-MODEL.md): the bundle
signature is verified at load time by `src/util/bundle-loader.js`. If
verification fails, the model is NOT loaded.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUNDLES_DIR = REPO_ROOT / "src" / "vendor" / "bundles"
BUNDLE_MAGIC = b"AEGISGATE_LENS_BUNDLE_V1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sign_bundle")


def ed25519_sign(message: bytes, private_key_path: Path) -> bytes:
    """Sign a message using a PEM-encoded Ed25519 private key.

    Requires the `cryptography` library: pip install cryptography
    (development dependency; not in shipped extension).
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key  # type: ignore
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_bytes = private_key_path.read_bytes()
    priv_key = load_pem_private_key(key_bytes, password=None)
    if not isinstance(priv_key, Ed25519PrivateKey):
        raise ValueError(f"{private_key_path} is not an Ed25519 key")
    return priv_key.sign(message)


def ed25519_pub_from_priv(private_key_path: Path) -> bytes:
    """Extract the public key bytes from a private key PEM."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key  # type: ignore
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv_key = load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(priv_key, Ed25519PrivateKey):
        raise ValueError(f"{private_key_path} is not an Ed25519 key")
    pub_key = priv_key.public_key()
    return pub_key.public_bytes_raw()


def gen_keypair(priv_out: Path, pub_out: Path) -> None:
    """Generate a new Ed25519 keypair."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    log.info("Generating new Ed25519 keypair...")
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    priv_out.parent.mkdir(parents=True, exist_ok=True)
    priv_out.write_bytes(priv_pem)
    os.chmod(priv_out, 0o600)  # private key: owner read/write only

    pub_out.parent.mkdir(parents=True, exist_ok=True)
    pub_out.write_text(
        f"# AegisGate Lens v0.2 — bundle signing public key\n"
        f"# Generated: {priv_out.stat().st_mtime}\n"
        f"# Format: base64(32-byte raw Ed25519 public key)\n"
        f"SIGNING_PUBLIC_KEY_B64 = '{pub_b64}'\n"
    )
    log.info("Wrote private key to %s (chmod 600)", priv_out)
    log.info("Wrote public key to %s", pub_out)
    log.info("KEY ID (the bundle's signing_pub_key_id field):")
    log.info("  lens-v02-%s", _key_id_from_pub(pub_bytes))


def _key_id_from_pub(pub_bytes: bytes) -> str:
    """Derive a human-readable key ID from the public key (first 8 hex of SHA-256)."""
    return hashlib.sha256(pub_bytes).hexdigest()[:8]


def build_bundle(
    facet: str,
    input_dir: Path,
    output_path: Path,
    private_key_path: Path,
    bundle_version: str = "0.2.0",
) -> None:
    """Build a signed bundle from files in `input_dir`."""
    if not input_dir.is_dir():
        raise ValueError(f"input directory does not exist: {input_dir}")

    files = sorted(p for p in input_dir.iterdir() if p.is_file())
    if not files:
        raise ValueError(f"no files in {input_dir}")

    log.info("Bundling %d files from %s", len(files), input_dir)
    for f in files:
        log.info("  %s (%d bytes)", f.name, f.stat().st_size)

    # 1. Concatenate payload
    payload = b""
    file_meta = []
    for f in files:
        data = f.read_bytes()
        offset = len(payload)
        size = len(data)
        sha256 = hashlib.sha256(data).hexdigest()
        file_meta.append({
            "name": f.name,
            "size": size,
            "sha256": sha256,
            "offset": offset,
        })
        payload += data
    payload_sha = hashlib.sha256(payload).hexdigest()

    # 2. Build header
    pub_bytes = ed25519_pub_from_priv(private_key_path)
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    key_id = f"lens-v02-{_key_id_from_pub(pub_bytes)}"

    header = {
        "magic": BUNDLE_MAGIC.decode("ascii"),
        "bundle_version": bundle_version,
        "facet": facet,
        "total_payload_size": len(payload),
        "payload_sha256": payload_sha,
        "files": file_meta,
        "signing_pub_key_id": key_id,
        "signing_pub_key_b64": pub_b64,
    }
    header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")

    # 3. Sign (header || payload)
    to_sign = header_bytes + payload
    signature = ed25519_sign(to_sign, private_key_path)

    # 4. Write bundle: header || payload || signature
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(header_bytes)
        f.write(payload)
        f.write(signature)
    log.info("Wrote bundle: %s (%d bytes)", output_path, len(header_bytes) + len(payload) + len(signature))

    # 5. Update SHA256SUMS
    _update_sha256sums(output_path)


def _update_sha256sums(bundle_path: Path) -> None:
    """Update the SHA256SUMS file in vendor/bundles/."""
    sha_file = BUNDLES_DIR / "SHA256SUMS"
    sha_file.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
    line = f"{digest}  {bundle_path.name}\n"
    existing = sha_file.read_text() if sha_file.exists() else ""
    # Replace existing entry for this file, or append
    lines = [l for l in existing.splitlines() if not l.endswith(f"  {bundle_path.name}")]
    lines.append(line.strip())
    sha_file.write_text("\n".join(sorted(set(lines))) + "\n")
    log.info("Updated %s", sha_file)


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisGate Lens v0.2 — bundle signing")
    parser.add_argument("--facet", choices=["prompt-injection", "toxicity"],
                        help="Which model's bundle to sign")
    parser.add_argument("--input", type=Path,
                        help="Directory containing the files to bundle")
    parser.add_argument("--output", type=Path,
                        help="Output bundle path (default: src/vendor/bundles/aegisgate-lens-<facet>-v0.2.0.bundle)")
    parser.add_argument("--priv-key", type=Path,
                        help="Ed25519 private key PEM file")
    parser.add_argument("--gen-key", action="store_true",
                        help="Generate a new keypair instead of signing")
    parser.add_argument("--priv-out", type=Path,
                        help="Where to write the new private key (for --gen-key)")
    parser.add_argument("--pub-out", type=Path,
                        help="Where to write the new public key (for --gen-key)")
    args = parser.parse_args()

    if args.gen_key:
        if not args.priv_out or not args.pub_out:
            parser.error("--gen-key requires --priv-out and --pub-out")
        gen_keypair(args.priv_out, args.pub_out)
        return

    if not args.facet or not args.input or not args.priv_key:
        parser.error("--facet, --input, and --priv-key are required for signing")

    output = args.output or (BUNDLES_DIR / f"aegisgate-lens-{args.facet}-v0.2.0.bundle")
    build_bundle(args.facet, args.input, output, args.priv_key)


if __name__ == "__main__":
    main()
