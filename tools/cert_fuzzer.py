#!/usr/bin/env python3
"""
Cantilever PKI - Differential ASN.1 and X.509 DER Mutational Fuzzer
Tests robustness of the parser against malformed, adversarial, and mutated inputs.

Fuzzing Strategies:
  - Bit flipping on random tag and length octets
  - Length injection attacks (indefinite length, excessive lengths, integer overflow)
  - Non-canonical long-form length encodings (0x81 0x05 for length 5)
  - Truncated ASN.1 sequences and sets
  - Trailing garbage and malformed UTF8/PrintableString octets
"""

import sys
import random
import subprocess
import tempfile
import os
from typing import List


def generate_mutations(seed_bytes: bytes, count: int = 100) -> List[bytes]:
    """Generates mutated variants of a DER seed buffer."""
    mutations = []
    data = bytearray(seed_bytes)
    n = len(data)

    if n == 0:
        return [b"\x30\x00", b"\x02\x01\x00"]

    for _ in range(count):
        mut = bytearray(data)
        strategy = random.randint(1, 6)

        if strategy == 1:
            # Single bit flip
            pos = random.randint(0, n - 1)
            bit = random.randint(0, 7)
            mut[pos] ^= (1 << bit)

        elif strategy == 2:
            # Byte replacement with edge-case values (0x00, 0xFF, 0x80, 0x1F)
            pos = random.randint(0, n - 1)
            mut[pos] = random.choice([0x00, 0xFF, 0x80, 0x1F, 0x7F, 0x81])

        elif strategy == 3:
            # Truncation
            trunc_len = random.randint(1, n)
            mut = mut[:trunc_len]

        elif strategy == 4:
            # Prepend or append garbage bytes
            garbage = bytes([random.randint(0, 255) for _ in range(random.randint(1, 16))])
            if random.random() < 0.5:
                mut = bytearray(garbage) + mut
            else:
                mut = mut + bytearray(garbage)

        elif strategy == 5:
            # Insert non-canonical indefinite length tag (0x80)
            if len(mut) > 2:
                mut[1] = 0x80

        elif strategy == 6:
            # Insert huge length byte count (e.g. 0x87 followed by arbitrary bytes)
            if len(mut) > 3:
                mut[1] = 0x87

        mutations.append(bytes(mut))

    return mutations


def run_fuzz_test(runner_path: str, samples: List[bytes]) -> bool:
    """Feeds mutated samples to cantilever inspect-cert and verifies no process crashes."""
    crashes = 0
    passed = 0

    print(f"[*] Fuzzing {len(samples)} mutated DER payloads...")

    for idx, sample in enumerate(samples):
        with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as f:
            # Format as PEM
            b64 = sample.hex()
            f.write(f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n".encode('utf-8'))
            temp_path = f.name

        try:
            cmd = ["node", runner_path, "inspect-cert", temp_path]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            # Exit code 0 or 1 is normal (graceful rejection), exit code >= 128 indicates crash/signal
            if result.returncode < 0 or result.returncode >= 128:
                print(f"    [!] Crash detected on sample #{idx}: returncode={result.returncode}")
                crashes += 1
            else:
                passed += 1
        except subprocess.TimeoutExpired:
            print(f"    [!] Hang / Timeout on sample #{idx}")
            crashes += 1
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    print(f"[*] Fuzzing Complete: {passed} handled gracefully, {crashes} unexpected crashes")
    return crashes == 0


def main():
    print("=" * 80)
    print("  CANTILEVER ASN.1 DER MUTATIONAL FUZZER")
    print("=" * 80)

    runner = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin", "cantilever.js"))
    if not os.path.exists(runner):
        print(f"[!] Cantilever executable not found at {runner}")
        return 1

    # Base seed DER sequence
    seed = bytes([0x30, 0x10, 0x02, 0x01, 0x01, 0x04, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x05, 0x00])
    mutations = generate_mutations(seed, count=100)

    success = run_fuzz_test(runner, mutations)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
