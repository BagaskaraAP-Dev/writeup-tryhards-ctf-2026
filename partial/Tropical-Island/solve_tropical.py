#!/usr/bin/env python3
"""CTF Tropical Island: convert one $10 voucher into 10 valid vouchers.

Online:
    pip install pwntools
    python3 solve_tropical.py HOST PORT
    python3 solve_tropical.py HOST PORT --tls

Offline (only generate 10 payloads from an existing voucher):
    python3 solve_tropical.py --voucher BASE64_VOUCHER
"""
import argparse
import base64
import hashlib
import json


def decode(voucher):
    raw = base64.b64decode(voucher.strip(), validate=True).decode()
    groups = raw.rstrip(";").split(";")
    if len(groups) != 3:
        raise ValueError("Expected 3 polynomial groups")
    return [[int(c) for c in group.split(",")] for group in groups]


def encode(groups):
    raw = ";".join(",".join(str(c) for c in group) for group in groups)
    return base64.b64encode(raw.encode()).decode()


def variants(voucher, count=10):
    original = decode(voucher)
    assert len(original) == 3
    seen = set()
    results = []
    for k in range(count):
        groups = [
            [x + k for x in original[0]],      # A' = A + k
            [x + k for x in original[1]],      # B' = B + k
            [x + 2 * k for x in original[2]],  # N' = N + 2k
        ]
        # Mirrors server's seen_voucher check; all vectors must be fresh.
        hashes = [
            hashlib.sha256(json.dumps([[coef, i] for i, coef in enumerate(group)]).encode()).hexdigest()
            for group in groups
        ]
        if len(set(hashes)) != 3 or any(h in seen for h in hashes):
            raise ValueError("Unexpected duplicate polynomial; choose different shift values")
        seen.update(hashes)
        results.append(encode(groups))
    return results


def exploit(host, port, tls=False):
    from pwn import remote
    io = remote(host, port, ssl=tls)

    io.sendlineafter(b"> ", b"1")
    io.recvuntil(b"Here's your voucher ")
    original = io.recvline().decode().strip()
    print("[+] Received one valid $10 voucher")

    for i, v in enumerate(variants(original), 1):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", v.encode())
        response = io.recvline(timeout=10).decode(errors="replace").strip()
        print(f"[{i:02d}/10] {response}")
        if "Valid voucher" not in response:
            raise RuntimeError(f"Server rejected forged voucher #{i}: {response}")

    io.sendlineafter(b"> ", b"3")
    io.recvuntil(b"Here's your free vacation code ", timeout=10)
    flag = io.recvline(timeout=10).decode(errors="replace").strip()
    print(f"\n[FLAG] {flag}")
    io.close()
    return flag


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("host", nargs="?")
    ap.add_argument("port", nargs="?", type=int)
    ap.add_argument("--tls", action="store_true", help="Use TLS/SSL connection")
    ap.add_argument("--voucher", help="Generate 10 payloads offline from the supplied voucher")
    args = ap.parse_args()
    if args.voucher:
        for i, payload in enumerate(variants(args.voucher), 1):
            print(f"Voucher #{i}: {payload}")
    elif args.host and args.port:
        exploit(args.host, args.port, args.tls)
    else:
        ap.error("Supply HOST PORT for online solve or --voucher for offline generation")


if __name__ == "__main__":
    main()
