"""
ecdsa_min.py — A minimal, from-scratch ECDSA implementation over secp256k1.

Pure stdlib. No external crypto libraries. Implemented from the public SEC1
spec so that every step of signing and verification is visible and auditable.
This is deliberately NOT constant-time and NOT hardened — it exists to make
the math legible for security research, not to secure anything.

secp256k1 is the curve used by Bitcoin/Ethereum. The parameters are public.

Author: (portfolio research)
License: MIT
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# --- secp256k1 domain parameters (public constants) -------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # field prime
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


# --- elliptic curve arithmetic over the finite field ------------------------
Point = tuple[int, int] | None  # None represents the point at infinity


def inv_mod(x: int, m: int) -> int:
    """Modular inverse via Python's built-in (Fermat/extended-Euclid)."""
    return pow(x, -1, m)


def point_add(p: Point, q: Point) -> Point:
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None  # p + (-p) = infinity
    if p == q:
        # point doubling
        m = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        m = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k: int, p: Point) -> Point:
    """Double-and-add scalar multiplication: computes k*P."""
    result: Point = None
    addend = p
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


G: Point = (GX, GY)


# --- ECDSA ------------------------------------------------------------------
def hash_msg(msg: bytes) -> int:
    """Hash message to an integer mod N (SHA-256, truncated per spec)."""
    h = hashlib.sha256(msg).digest()
    return int.from_bytes(h, "big") % N


@dataclass
class Signature:
    r: int
    s: int


def keygen() -> tuple[int, Point]:
    """Return (private_key d, public_key Q = d*G)."""
    d = secrets.randbelow(N - 1) + 1
    Q = scalar_mul(d, G)
    return d, Q


def sign(d: int, msg: bytes, k: int | None = None) -> Signature:
    """Sign msg with private key d, using nonce k.

    If k is None a fresh random nonce is used (correct behavior).
    Passing a fixed/repeated k is the vulnerability we study — the caller
    controls it so the demo server can simulate a realistic PRNG bug.
    """
    z = hash_msg(msg)
    while True:
        if k is None:
            k_use = secrets.randbelow(N - 1) + 1
        else:
            k_use = k
        R = scalar_mul(k_use, G)
        r = R[0] % N
        if r == 0:
            if k is not None:
                raise ValueError("bad fixed nonce produced r=0")
            continue
        s = (inv_mod(k_use, N) * (z + r * d)) % N
        if s == 0:
            if k is not None:
                raise ValueError("bad fixed nonce produced s=0")
            continue
        return Signature(r, s)


def verify(Q: Point, msg: bytes, sig: Signature) -> bool:
    r, s = sig.r, sig.s
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = hash_msg(msg)
    w = inv_mod(s, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    X = point_add(scalar_mul(u1, G), scalar_mul(u2, Q))
    if X is None:
        return False
    return X[0] % N == r
