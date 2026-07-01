"""
AegisGate Lens v0.2.0 — Build a signed ONNX bundle

Bundle format (from v0.1's aegisgate-lens-v0.1.1.bundle):
  Header JSON:
    {
      "magic": "AEGISGATE_LENS_BUNDLE_V1",
      "format_version": 1,
      "bundle_version": "<semver>",
      "created_at": "<ISO 8601>",
      "n_files": <int>,
      "total_payload_size": <int>,
      "payload_sha256": "<hex of full payload>",
      "signing_public_key": "<hex of Ed25519 public key>",
      "files": [
        {"name": "<relative>", "size": <int>, "sha256": "<hex>", "offset": <int>},
        ...
      ]
    }
  Payload: <concatenated file bytes, in offset order>
  Signature: <64-byte Ed25519 signature over header+payload>

Keys are raw 32-byte files (Ed25519 seed + public key separately).

Usage:
  python3 build_signed_bundle.py \
    --version 0.2.0 \
    --output lens-final-dist/vendor/bundles/aegisgate-lens-prompt-injection-v0.2.0.bundle \
    --files test/bundles/model.onnx test/bundles/tokenizer.json test/bundles/tokenizer_config.json
"""
import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_private_key_raw(path):
    """Load a 32-byte Ed25519 seed and construct the private key."""
    seed = path.read_bytes()
    if len(seed) != 32:
        raise ValueError(f'Expected 32-byte Ed25519 seed, got {len(seed)} bytes')
    return Ed25519PrivateKey.from_private_bytes(seed)


def build_bundle(files, version, private_key):
    """Build a signed bundle from a list of (name, data) tuples."""
    public_key = private_key.public_key()

    # Build file metadata
    file_infos = []
    offset = 0
    for name, data in files:
        file_infos.append({
            'name': name,
            'size': len(data),
            'sha256': sha256(data),
            'offset': offset,
        })
        offset += len(data)

    # Concatenate payload
    payload = b''.join(data for _, data in files)
    payload_sha = sha256(payload)

    # Derive public key bytes (32 bytes raw)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Build header
    header = {
        'magic': 'AEGISGATE_LENS_BUNDLE_V1',
        'format_version': 1,
        'bundle_version': version,
        'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'n_files': len(files),
        'total_payload_size': len(payload),
        'payload_sha256': payload_sha,
        'signing_public_key': public_key_bytes.hex(),  # 32-byte raw public key as hex
        'files': file_infos,
    }
    header_bytes = json.dumps(header, indent=2).encode('utf-8')

    # Sign header+payload
    message = header_bytes + payload
    signature = private_key.sign(message)

    # Combine: header + payload + signature
    return message + signature


def main():
    parser = argparse.ArgumentParser(description='Build a signed AegisGate Lens bundle')
    parser.add_argument('--version', required=True, help='Bundle version (e.g., 0.2.0)')
    parser.add_argument('--output', required=True, help='Output bundle path')
    parser.add_argument('--files', nargs='+', required=True, help='Files to include in bundle (name:path pairs)')
    parser.add_argument('--private-key', default='keys/lens-signing-private.pem',
                        help='Path to raw 32-byte Ed25519 seed file')
    args = parser.parse_args()

    # Parse files
    files = []
    for spec in args.files:
        if ':' in spec:
            name, path = spec.split(':', 1)
        else:
            name = Path(spec).name
            path = spec
        with open(path, 'rb') as f:
            data = f.read()
        files.append((name, data))
        print(f'  Loaded: {name} ({len(data)} bytes)')

    # Load private key
    key_path = Path(args.private_key)
    if not key_path.exists():
        print(f'ERROR: private key not found at {key_path}')
        sys.exit(1)
    private_key = load_private_key_raw(key_path)
    print(f'  Loaded private key: {key_path}')

    print(f'\nBuilding bundle version {args.version}...')
    bundle = build_bundle(files, args.version, private_key)
    print(f'  Bundle size: {len(bundle):,} bytes ({len(bundle) / 1024 / 1024:.2f} MB)')

    # Write bundle
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(bundle)
    print(f'  Wrote: {out_path}')

    # Compute SHA256 of bundle
    bundle_sha = sha256(bundle)
    print(f'  Bundle SHA256: {bundle_sha}')


if __name__ == '__main__':
    main()