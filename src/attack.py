"""
attack.py — Recover an ECDSA private key from two signatures that reused a nonce.

This is the whole point of the project. The attacker is a PASSIVE OBSERVER:
it only sees (message, r, s) tuples. It has NO access to the signer's private
key, nonce, or internals. It detects nonce reuse by spotting two signatures
that share the same r value, then recovers the private key algebraically.

The math (all mod N, the curve order):

  A signature is:   s = k^-1 (z + r*d)   =>   s*k = z + r*d

  If two messages are signed with the SAME nonce k, they share the same r
  (because r = (k*G).x depends only on k). Then:

      s1*k = z1 + r*d
      s2*k = z2 + r*d

  Subtract:   (s1 - s2)*k = z1 - z2
  So:         k = (z1 - z2) / (s1 - s2)   mod N

  Once k is known, recover d from either signature:
              d = (s1*k - z1) / r         mod N

No key material is ever transmitted. The private key is reconstructed purely
from public signature values. That is the vulnerability.

Author: (portfolio research)
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass

from ecdsa_min import N, Signature, hash_msg, inv_mod, scalar_mul, G, verify, Point


@dataclass
class ObservedSig:
    msg: bytes
    sig: Signature


def find_nonce_reuse(observations: list[ObservedSig]) -> tuple[ObservedSig, ObservedSig] | None:
    """Detect two distinct messages whose signatures share an r value.

    Equal r with different messages is the tell-tale sign of nonce reuse.
    This is exactly what a passive network observer could compute.
    """
    by_r: dict[int, ObservedSig] = {}
    for obs in observations:
        prev = by_r.get(obs.sig.r)
        if prev is not None and prev.msg != obs.msg:
            return prev, obs
        by_r[obs.sig.r] = obs
    return None


def recover_nonce(a: ObservedSig, b: ObservedSig) -> int:
    """k = (z1 - z2) / (s1 - s2) mod N"""
    z1, z2 = hash_msg(a.msg), hash_msg(b.msg)
    s1, s2 = a.sig.s, b.sig.s
    return (z1 - z2) * inv_mod((s1 - s2) % N, N) % N


def recover_private_key(a: ObservedSig, k: int) -> int:
    """d = (s*k - z) / r mod N, from a single signature and the known nonce."""
    z = hash_msg(a.msg)
    r, s = a.sig.r, a.sig.s
    return (s * k - z) * inv_mod(r, N) % N


def attack(observations: list[ObservedSig]) -> dict | None:
    """Full chain: detect reuse -> recover nonce -> recover private key."""
    pair = find_nonce_reuse(observations)
    if pair is None:
        return None
    a, b = pair
    k = recover_nonce(a, b)
    d = recover_private_key(a, k)
    return {
        "reused_r": a.sig.r,
        "recovered_nonce_k": k,
        "recovered_private_key_d": d,
        "pair": (a, b),
    }
