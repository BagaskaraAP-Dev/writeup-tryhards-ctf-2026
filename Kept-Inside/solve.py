#!/usr/bin/env python3
"""Solver for Kept Inside (CTF Network Forensics).

Extracts and decrypts AES-256-CBC payloads from keptinside.pcap.
Dependencies: pip install cryptography
"""
import base64
import hashlib
import re
import struct
import sys
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ZIP_PASSWORD = b"tryhards"
AES_PASSPHRASE = b"sumo-broth-2026"
AES_IV = bytes.fromhex("00112233445566778899aabbccddeeff")


def pcap_frames(raw: bytes):
    """Parse raw pcap packet data."""
    if raw[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("Header PCAP format little-endian tidak valid")
    offset = 24
    while offset + 16 <= len(raw):
        _, _, included, _ = struct.unpack_from("<IIII", raw, offset)
        offset += 16
        frame = raw[offset:offset + included]
        if len(frame) != included:
            break
        offset += included
        yield frame


def http_tcp_payload(frame: bytes) -> bytes:
    """Extract TCP payload from IPv4 frame."""
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return b""
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 6:
        return b""
    ihl = (ip[0] & 15) * 4
    total_len = int.from_bytes(ip[2:4], "big")
    tcp = ip[ihl:total_len]
    if len(tcp) < 20:
        return b""
    offset = (tcp[12] >> 4) * 4
    return tcp[offset:]


def aes_decrypt(b64_text: str) -> str:
    """Decrypt base64 ciphertext using AES-256-CBC."""
    encrypted = base64.b64decode(b64_text)
    key = hashlib.sha256(AES_PASSPHRASE).digest()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(AES_IV)).decryptor()
    plain = decryptor.update(encrypted) + decryptor.finalize()
    padding = plain[-1]
    if not (1 <= padding <= 16 and plain.endswith(bytes([padding]) * padding)):
        raise ValueError("Padding PKCS#7 tidak valid")
    return plain[:-padding].decode("utf-8")


def main(zip_path: str):
    with zipfile.ZipFile(zip_path) as z:
        pcap_data = z.read("keptinside.pcap", pwd=ZIP_PASSWORD)

    stages = {}
    flag = None
    for frame in pcap_frames(pcap_data):
        payload = http_tcp_payload(frame)
        if payload.startswith(b"POST /control "):
            match = re.search(rb"stage=(\d+)&data=([A-Za-z0-9+/=]+)", payload)
            if match:
                stage_num = int(match.group(1))
                stages[stage_num] = aes_decrypt(match.group(2).decode())
        elif payload.startswith(b"HTTP/1.1 ") and b"\r\n\r\nresult=" in payload:
            ciphertext = payload.split(b"\r\n\r\nresult=", 1)[1].strip().decode()
            flag = aes_decrypt(ciphertext)

    for number in sorted(stages):
        print(f"Stage {number}: {stages[number]}")
    if flag:
        print(f"FLAG: {flag}")
    else:
        print("Flag tidak ditemukan di payload HTTP")


if __name__ == "__main__":
    target_zip = sys.argv[1] if len(sys.argv) > 1 else "kept-inside.zip"
    main(target_zip)
