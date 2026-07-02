"""
test_nonce_reuse.py — Self-tests for the ECDSA nonce-reuse recovery demo.

Runs with either `pytest` or plain `python3 tests/test_nonce_reuse.py`.
No external dependencies (uses only the from-scratch `ecdsa_min` module and
stdlib). Deterministic where it matters: signing uses caller-supplied nonces
so the reuse cases are reproducible rather than probabilistic.

Coverage:
  * curve/group invariants (generator on curve, order, doubling)
  * ECDSA round-trip sign/verify, and rejection of tampered signatures
  * nonce-reuse detection from public (message, r, s) tuples only
  * private-key recovery algebra: k = (z1-z2)/(s1-s2), d = (s*k-z)/r
  * end-to-end: recovered key regenerates Q and forges an accepted signature
  * both realistic bug models in vulnerable_signer (fork_reseed, counter_wrap)
  * negative case: healthy random nonces yield no detectable reuse
"""

from __future__ import annotations

import os
import sys

# Make `src/` importable whether run from the project root or tests/ dir.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
sys.path.insert(0, _SRC)

from ecdsa_min import (  # noqa: E402
    A,
    B,
    G,
    GX,
    GY,
    N,
    P,
    Signature,
    hash_msg,
    inv_mod,
    keygen,
    point_add,
    scalar_mul,
    sign,
    verify,
)
from attack import (  # noqa: E402
    ObservedSig,
    attack,
    find_nonce_reuse,
    recover_nonce,
    recover_private_key,
)
from vulnerable_signer import VulnerableSigner  # noqa: E402


# --- curve / group invariants ----------------------------------------------
def _on_curve(pt) -> bool:
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def test_generator_on_curve():
    assert G == (GX, GY)
    assert _on_curve(G)


def test_generator_has_group_order():
    # N * G must be the point at infinity for a valid group order.
    assert scalar_mul(N, G) is None


def test_point_doubling_matches_addition():
    two_g_dbl = point_add(G, G)
    two_g_mul = scalar_mul(2, G)
    assert two_g_dbl == two_g_mul
    assert _on_curve(two_g_mul)


def test_inv_mod_roundtrip():
    for x in (1, 2, 3, 123456789, N - 1):
        assert (x * inv_mod(x, N)) % N == 1


# --- ECDSA sign / verify ----------------------------------------------------
def test_sign_verify_roundtrip():
    d, Q = keygen()
    msg = b"hello ecdsa"
    sig = sign(d, msg)
    assert verify(Q, msg, sig)


def test_verify_rejects_wrong_message():
    d, Q = keygen()
    sig = sign(d, b"authorize payment")
    assert not verify(Q, b"authorize DIFFERENT payment", sig)


def test_verify_rejects_tampered_signature():
    d, Q = keygen()
    msg = b"transfer 1 to self"
    sig = sign(d, msg)
    assert not verify(Q, msg, Signature(sig.r, (sig.s + 1) % N))
    assert not verify(Q, msg, Signature((sig.r + 1) % N, sig.s))


def test_verify_rejects_out_of_range():
    d, Q = keygen()
    msg = b"x"
    sig = sign(d, msg)
    assert not verify(Q, msg, Signature(0, sig.s))
    assert not verify(Q, msg, Signature(sig.r, N))


def test_fixed_nonce_reproduces_same_r():
    d, _ = keygen()
    k = 0x1234567890ABCDEF
    r1 = sign(d, b"message one", k=k).r
    r2 = sign(d, b"message two", k=k).r
    assert r1 == r2  # r depends only on k -> reused nonce = reused r


# --- recovery algebra -------------------------------------------------------
def test_recover_nonce_and_key_from_reuse():
    d, Q = keygen()
    k = 0xDEADBEEFCAFE1234567890
    m1, m2 = b"pay alice 10", b"pay bob 25"
    a = ObservedSig(m1, sign(d, m1, k=k))
    b = ObservedSig(m2, sign(d, m2, k=k))

    rec_k = recover_nonce(a, b)
    assert rec_k == k

    rec_d = recover_private_key(a, rec_k)
    assert rec_d == d
    # independent check: recovered key regenerates the public key.
    assert scalar_mul(rec_d, G) == Q


def test_find_nonce_reuse_detects_shared_r():
    d, _ = keygen()
    k = 0xABCDEF
    obs = [
        ObservedSig(b"a", sign(d, b"a")),          # healthy random nonce
        ObservedSig(b"b", sign(d, b"b", k=k)),     # reused
        ObservedSig(b"c", sign(d, b"c", k=k)),     # reused
    ]
    pair = find_nonce_reuse(obs)
    assert pair is not None
    assert {pair[0].msg, pair[1].msg} == {b"b", b"c"}


def test_find_nonce_reuse_ignores_same_message_resign():
    # Same message signed twice with the same nonce is not an exploitable
    # cross-message reuse; detector must not flag it.
    d, _ = keygen()
    k = 0x777
    obs = [
        ObservedSig(b"same", sign(d, b"same", k=k)),
        ObservedSig(b"same", sign(d, b"same", k=k)),
    ]
    assert find_nonce_reuse(obs) is None


def test_no_reuse_with_healthy_nonces():
    d, _ = keygen()
    obs = [ObservedSig(f"m{i}".encode(), sign(d, f"m{i}".encode())) for i in range(8)]
    assert find_nonce_reuse(obs) is None
    assert attack(obs) is None


# --- end-to-end against the vulnerable signer -------------------------------
def test_fork_reseed_end_to_end():
    signer = VulnerableSigner(bug="fork_reseed")
    Q = signer.public_key()
    observed = [
        ObservedSig(b"transfer 10 to alice", signer.sign_message(b"transfer 10 to alice")),
        ObservedSig(b"transfer 25 to bob", signer.sign_message(b"transfer 25 to bob")),
    ]
    twin = signer.fork()  # inherits PRNG state -> next nonce collides
    observed.append(ObservedSig(b"transfer 5 to carol", signer.sign_message(b"transfer 5 to carol")))
    observed.append(ObservedSig(b"transfer 999 to dave", twin.sign_message(b"transfer 999 to dave")))

    result = attack(observed)
    assert result is not None
    rec_d = result["recovered_private_key_d"]
    assert rec_d == signer.d
    assert scalar_mul(rec_d, G) == Q

    # Weaponize: forge a brand-new authorization the signer never issued.
    forged = b"transfer 1000000 to attacker"
    assert verify(Q, forged, sign(rec_d, forged))


def test_counter_wrap_end_to_end():
    signer = VulnerableSigner(bug="counter_wrap")
    Q = signer.public_key()
    # 8-bit counter wraps after 256 signatures; message 1 and message 257
    # collide on the same nonce.
    observed = []
    for i in range(258):
        m = f"op #{i}".encode()
        observed.append(ObservedSig(m, signer.sign_message(m)))
    result = attack(observed)
    assert result is not None
    assert result["recovered_private_key_d"] == signer.d
    assert scalar_mul(result["recovered_private_key_d"], G) == Q


def test_hash_msg_in_range():
    for m in (b"", b"a", b"transfer 999 to dave", os.urandom(64)):
        z = hash_msg(m)
        assert 0 <= z < N


# --- allow running without pytest ------------------------------------------
if __name__ == "__main__":
    failures = 0
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failures += 1
            print(f"FAIL  {t.__name__}: {e or 'assertion failed'}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    sys.exit(1 if failures else 0)
