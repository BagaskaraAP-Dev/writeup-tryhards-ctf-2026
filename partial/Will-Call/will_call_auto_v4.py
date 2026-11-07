#!/usr/bin/env python3
"""
Will Call CTF automated solver (v4)
Usage: python3 will_call_auto_v4.py [host] [port]
       python3 will_call_auto_v4.py --capture will_call_capture.json
Dependency: pip install sympy

Stage 1: recover ECDSA window key via quadratic nonce recurrence + modular polynomial GCD.
Stage 2: forge tier=staff; test nonce-reuse, recurrence, short and affine nonce models.
Stage 3: forge tier=allaccess to get the flag.
"""
import hashlib
import json
import itertools
import re
import socket
import sys

from sympy import Matrix

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
KMAX = 1 << 240


def h(m):
    return int.from_bytes(hashlib.sha256(m).digest(), "big") % N


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1+y2) % P == 0:
        return None
    if a == b:
        slope = 3 * x1*x1 * pow(2*y1, -1, P) % P
    else:
        slope = (y2-y1) * pow(x2-x1, -1, P) % P
    x3 = (slope*slope - x1 - x2) % P
    return (x3, (slope*(x1-x3)-y1) % P)


def ec_mul(k, p=G):
    res = None
    while k:
        if k & 1:
            res = ec_add(res, p)
        p = ec_add(p, p)
        k >>= 1
    return res


# Ring F_N[x] represented by low-degree-first coefficient lists.
def norm(a):
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def padd(a, b):
    c = [0] * max(len(a), len(b))
    for i, v in enumerate(a):
        c[i] = (c[i] + v) % N
    for i, v in enumerate(b):
        c[i] = (c[i] + v) % N
    return norm(c)


def pneg(a):
    return [-v % N for v in a]


def psub(a, b):
    return padd(a, pneg(b))


def pmul(a, b):
    c = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            c[i+j] = (c[i+j] + x*y) % N
    return norm(c)


PERMS = list(itertools.permutations(range(4)))


def det4(rows):
    result = [0]
    for order in PERMS:
        term = [1]
        for i in range(4):
            term = pmul(term, rows[i][order[i]])
        inversions = sum(order[i] > order[j] for i in range(4) for j in range(i+1, 4))
        result = psub(result, term) if inversions % 2 else padd(result, term)
    return result


def pmod(a, b):
    r = a[:]
    lead_inv = pow(b[-1], -1, N)
    while len(r) >= len(b) and r != [0]:
        shift = len(r) - len(b)
        q = r[-1] * lead_inv % N
        r = psub(r, [0]*shift + [q*v % N for v in b])
    return r


def pgcd(a, b):
    while b != [0]:
        a, b = b, pmod(a, b)
    inv = pow(a[-1], -1, N)
    return [v*inv % N for v in a]


def recover_window_key(sigs, pub):
    # k_i = (h_i + r_i*d) / s_i = A_i + B_i*d (mod N)
    kpolys = []
    for data, r, s in sigs:
        si = pow(s, -1, N)
        kpolys.append([h(data)*si % N, r*si % N])

    # k_{i+1} = a*k_i^2 + b*k_i + c (mod N)
    # Thus every 4x4 minor of [k_i^2,k_i,1,k_{i+1}] vanishes.
    rows = []
    for i in range(5):
        k = kpolys[i]
        rows.append([pmul(k, k), k, [1], kpolys[i+1]])

    f = det4(rows[:4])
    g = det4(rows[1:])
    common = pgcd(f, g)
    if len(common) != 2:
        raise RuntimeError(f"Unexpected GCD degree {len(common)-1}: {common}")
    d = -common[0] * pow(common[1], -1, N) % N
    if ec_mul(d) != pub:
        raise RuntimeError("Recovered window key does not match public key")
    return d


def check_signature(pub, data, r, s):
    """Check the actual quote signature, not just the guessed nonce model."""
    if not (0 < r < N and 0 < s < N):
        return False
    inv = pow(s, -1, N)
    pt = ec_add(ec_mul(h(data) * inv % N),
                ec_mul(r * inv % N, pub))
    return pt is not None and pt[0] % N == r


def reduce_lattice(rows):
    """Use fpylll if available; SymPy is the fallback."""
    try:
        from fpylll import IntegerMatrix, LLL
        A = IntegerMatrix.from_matrix(rows)
        LLL.reduction(A, delta=0.99)
        return [[int(A[i, j]) for j in range(A.ncols)] for i in range(A.nrows)]
    except ImportError:
        return Matrix(rows).lll(delta=0.90).tolist()



def recover_box_key(sigs, pub):
    """
    Automated attacks against several possible *weak* box-office nonce sources.
    Important: the box signer itself is NOT in the supplied challenge archive,
    so none of these nonce-source models is guaranteed for the real service.
    Every recovered private key is checked against the real public key.
    """
    if len(sigs) < 24:
        raise ValueError("Need at least 24 quote signatures")

    for data, r, s in sigs[:min(5, len(sigs))]:
        if not check_signature(pub, data, r, s):
            raise RuntimeError("A box-office signature did not verify")

    lows = sum(s <= N // 2 for _, _, s in sigs)
    unique_r = len({r for _, r, _ in sigs})
    print(f"[i] Verified quotes; unique r={unique_r}/{len(sigs)}; "
          f"low-S={lows}/{len(sigs)}", flush=True)

    # Stage A: repeated nonce (including opposite signs, same r).
    seen = {}
    for data, r, s in sigs:
        if r in seen:
            data0, s0 = seen[r]
            for sign in (1, -1):
                denom = (s0 - sign * s) % N
                if denom == 0:
                    continue
                k = ((h(data0) - h(data)) * pow(denom, -1, N)) % N
                candidate = ((s0*k - h(data0)) * pow(r, -1, N)) % N
                if ec_mul(candidate) == pub:
                    print("[+] Box key recovered from reused nonce!", flush=True)
                    return candidate
        else:
            seen[r] = (data, s)

    # Stage B: a polynomial nonce sequence over secp256k1's scalar field
    # would also be broken by the same attack as the public window signer.
    try:
        candidate = recover_window_key(sigs[:6], pub)
        print("[+] Box key recovered from quadratic nonce recurrence!", flush=True)
        return candidate
    except (ValueError, RuntimeError, ZeroDivisionError):
        pass

    # For ECDSA:
    # k_i = r_i * s_i^-1 * d + H(m_i)*s_i^-1 (mod N).
    # If k_i is small (or differs from a common unknown offset by a small
    # amount), a Hidden Number Problem lattice can recover d.
    t0 = []
    u0 = []
    idxs = []
    for data, r, s in sigs:
        inv = pow(s, -1, N)
        t0.append((r*inv) % N)
        u0.append((h(data)*inv) % N)
        m = re.fullmatch(rb"quote=([0-9]+)", data)
        idxs.append(int(m.group(1)) if m else 0)

    checked = set()

    def attempt_lattice(label, bits, shift=0, difference=False,
                        subtract_index=False, sizes=(24, 30, 36)):
        factor = pow(1 << shift, -1, N)
        t = [v*factor % N for v in t0]
        u = [((v - (idxs[i] if subtract_index else 0))*factor) % N
             for i, v in enumerate(u0)]

        if difference:
            # An unknown constant prefix/suffix cancels from k_i-k_anchor.
            # Useful e.g. for k_i = C*2**240 + random_240 or
            # k_i = random_240*2**16 + C with a constant 16-bit suffix.
            anchor = 0
            t = [(v-t[anchor])%N for v in t[anchor+1:]]
            u = [(v-u[anchor])%N for v in u[anchor+1:]]

        W = (N+(1 << bits)-1)//(1 << bits)
        for size in sizes:
            if size > len(t):
                continue
            # Run over consecutive blocks to avoid an unlucky first subset
            # or an initial signer warm-up nonce.
            starts = [0]
            if 30 <= size <= 40 and len(t) >= size+18:
                starts.append(18)
            for start in starts:
                a, b = t[start:start+size], u[start:start+size]
                D = size + 2
                rows = [[0]*D for _ in range(D)]
                for i in range(size):
                    rows[i][i] = N * W
                    rows[size][i] = a[i] * W
                    rows[size+1][i] = b[i] * W
                rows[size][size] = 1
                rows[size+1][size+1] = N
                print(f"[+] {label}: LLL {D}D (offset {start})", flush=True)
                try:
                    reduced = reduce_lattice(rows)
                except (ValueError, ArithmeticError) as ex:
                    print(f"[i] LLL skipped: {str(ex)[:120]}", flush=True)
                    continue
                for vec in reduced:
                    if abs(int(vec[-1])) != N:
                        continue
                    sign = 1 if int(vec[-1]) > 0 else -1
                    candidate = (sign * int(vec[-2])) % N
                    if candidate in checked:
                        continue
                    checked.add(candidate)
                    if ec_mul(candidate) == pub:
                        print(f"[+] Box private key recovered: {label}", flush=True)
                        return candidate
        return None

    # First sweep: cheap 26D tests across several distinct nonce models.
    # Only if these fail do we try expensive, higher-dimensional lattices.
    small_models = [
        ("short nonces (<2^240)", 240, 0, False, False, (24,)),
        ("240-bit interval, unknown prefix", 240, 0, True, False, (24,)),
        ("short nonce left-shifted 16", 240, 16, False, False, (24,)),
        ("240-bit shift16 + unknown suffix", 240, 16, True, False, (24,)),
        ("240-bit shift16 + quote counter", 240, 16, False, True, (24,)),
        ("240-bit shift8 + unknown suffix", 240, 8, True, False, (24,)),
        ("240-bit shift8", 240, 8, False, False, (24,)),
        ("240-bit shift4", 240, 4, False, False, (24,)),
        ("240-bit shift12", 240, 12, False, False, (24,)),
    ]
    deep_models = [
        ("short nonces (<2^240)", 240, 0, False, False, (30, 36)),
        ("240-bit interval, unknown prefix", 240, 0, True, False, (30, 36)),
        ("short nonce left-shifted 16", 240, 16, False, False, (30, 36)),
        ("240-bit shift16 + unknown suffix", 240, 16, True, False, (30, 36)),
        ("240-bit shift16 + quote counter", 240, 16, False, True, (30, 36)),
        ("short nonces (<2^242)", 242, 0, False, False, (28, 36, 44)),
        ("242-bit unknown prefix", 242, 0, True, False, (28, 36, 44)),
        ("short nonces (<2^244)", 244, 0, False, False, (36, 44, 52)),
        ("244-bit unknown prefix", 244, 0, True, False, (36, 44, 52)),
        ("short nonces (<2^248)", 248, 0, False, False, (56, 68, 78)),
    ]
    for spec in small_models + deep_models:
        key = attempt_lattice(*spec)
        if key is not None:
            return key

    raise RuntimeError(
        "Belum menemukan private key box office. Implementasi box_sign() "
        "memang tidak ada di arsip; nonce mungkin berbeda dari model yang "
        "bisa diturunkan. File will_call_capture.json tersimpan otomatis. "
        "Upload file itu ke chat untuk analisis data remote."
    )


def pack_pass(data, d):
    # For a single forgery ECDSA nonce k=1 works: r=x(G), s=h(data)+r*d.
    r = G[0] % N
    s = (h(data) + r*d) % N
    if s == 0:
        raise RuntimeError("Extremely unlucky s=0; use a different nonce")
    return (data.hex() + "." + format(r, "064x") + "." + format(s, "064x")).encode()


def split_pass(line, prefix):
    if not line.startswith(prefix):
        raise RuntimeError(f"Unexpected server response: {line!r}")
    try:
        hd, hr, hs = line[len(prefix):].decode().strip().split(".")
        return bytes.fromhex(hd), int(hr, 16), int(hs, 16)
    except ValueError as e:
        raise RuntimeError(f"Could not parse signature {line!r}") from e


def read_line(stream):
    line = stream.readline()
    if not line:
        raise EOFError("Server disconnected unexpectedly")
    return line.strip()


def req(stream, line):
    stream.write(line + b"\n")
    return read_line(stream)


def parse_pub(line):
    match = re.search(rb"([0-9a-fA-F]{64}),([0-9a-fA-F]{64})", line)
    if not match:
        raise ValueError(f"No public key in: {line!r}")
    return int(match.group(1), 16), int(match.group(2), 16)


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--capture":
        with open(sys.argv[2], "r") as fh:
            cap = json.load(fh)
        pub = tuple(int(v, 16) for v in cap["box_pub"])
        sigs = [(bytes.fromhex(data), int(r, 16), int(s, 16))
                for data, r, s in cap["quotes"]]
        result = recover_box_key(sigs, pub)
        print(f"[+] Captured session's box key: {result:064x}")
        print("[i] Offline captures are only useful for that exact session.")
        return

    host = sys.argv[1] if len(sys.argv) > 1 else "109.123.232.54"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1344
    with socket.create_connection((host, port), timeout=25) as sock:
        sock.settimeout(300)
        with sock.makefile("rwb", buffering=0) as stream:
            banner = [read_line(stream) for _ in range(6)]
            for line in banner:
                print(line.decode("utf-8", "replace"))
            window_pub = parse_pub(next(x for x in banner if x.startswith(b"Window public key:")))

            sigs = []
            for i in range(6):
                res = req(stream, b"ISSUE user" + str(i).encode())
                sigs.append(split_pass(res, b"pass: "))
            print("[+] 6 window signatures received", flush=True)
            dwin = recover_window_key(sigs, window_pub)
            print(f"[+] Window private key: {dwin:064x}", flush=True)

            staff = pack_pass(b"name=solver&tier=staff", dwin)
            staff_status = req(stream, b"ENTER " + staff)
            print("[+] " + staff_status.decode("utf-8", "replace"))
            if b"staff door opens" not in staff_status:
                raise RuntimeError("Staff door not opened")

            after_staff = [read_line(stream) for _ in range(3)]
            for line in after_staff:
                print(line.decode("utf-8", "replace"))
            box_pub = parse_pub(next(x for x in after_staff if x.startswith(b"Box office public key:")))

            quotes = []
            for i in range(1, 81):
                res = req(stream, b"QUOTE " + str(i).encode())
                quotes.append(split_pass(res, b"quote: "))
            print(f"[+] {len(quotes)} box-office signatures received", flush=True)
            # Preserve all signatures for offline debugging if lattice fails.
            capture = {
                "box_pub": [f"{v:064x}" for v in box_pub],
                "quotes": [[data.hex(), f"{r:064x}", f"{s:064x}"]
                           for data, r, s in quotes],
            }
            with open("will_call_capture.json", "w") as out:
                json.dump(capture, out, indent=2)
            print("[+] Saved quotes to will_call_capture.json", flush=True)
            dbox = recover_box_key(quotes, box_pub)
            print(f"[+] Box private key: {dbox:064x}", flush=True)

            backstage = pack_pass(b"name=solver&tier=allaccess", dbox)
            result = req(stream, b"ENTER " + backstage)
            decoded = result.decode("utf-8", "replace")
            if "backstage unlocked:" in decoded:
                print("[FLAG] " + decoded.split("backstage unlocked:", 1)[1].strip(), flush=True)
            else:
                print("[!] Backstage rejected the forged pass: " + decoded, flush=True)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, EOFError, OSError, ValueError) as exc:
        print(f"\\n[!] {exc}", file=sys.stderr)
        sys.exit(2)
