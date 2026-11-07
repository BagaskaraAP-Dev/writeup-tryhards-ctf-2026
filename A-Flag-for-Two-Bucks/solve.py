#!/usr/bin/env python3
"""Solver for A Flag for Two Bucks (CTF Reverse Engineering).

Recovers the 39-character flag by matching the 2-byte state transitions
against printable ASCII characters.
"""

target = bytes.fromhex(
    "feb6ef6004fd471df65f1b87e2bb7068"
    "1bae94f0bbdb9681ed090da94e43f551"
    "736585474d6690"
)

state = 0
flag = bytearray()

for i in range(0, len(target) - (len(target) % 2), 2):
    expected = int.from_bytes(target[i:i + 2], "little")
    candidates = []

    for a in range(32, 127):
        for b in range(32, 127):
            next_state = (
                (state * 33) ^ (a * 257) ^ (b * 509)
            ) & 0xffffffff

            if (next_state & 0xffff) == expected:
                candidates.append((a, b, next_state))

    if len(candidates) != 1:
        raise ValueError(f"Offset {i}: ditemukan {len(candidates)} kandidat")

    a, b, state = candidates[0]
    flag.extend((a, b))

if len(target) % 2:
    last_char = ((state * 33) ^ target[-1]) & 0xff
    flag.append(last_char)

recovered = flag.decode("ascii")
print(recovered)
