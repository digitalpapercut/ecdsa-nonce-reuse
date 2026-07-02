"""
demo.py — End-to-end: observe -> detect reuse -> recover key -> forge.

Runs entirely offline against a signer object you own. No network, no third
party. Demonstrates the full attack chain and, crucially, verifies that the
recovered private key EQUALS the real one and that a forged signature (made
with the recovered key, on a message the server never signed) is accepted by
the server's own verifier.

Run:  python3 src/demo.py
"""

from __future__ import annotations

from ecdsa_min import sign, verify, scalar_mul, G
from attack import ObservedSig, attack
from vulnerable_signer import VulnerableSigner


def banner(t: str) -> None:
    print("\n" + "=" * 68 + f"\n{t}\n" + "=" * 68)


def main() -> None:
    banner("1. A service you do NOT control signs messages for clients")
    signer = VulnerableSigner(bug="fork_reseed")
    Q = signer.public_key()
    print(f"   Server public key Q.x = {hex(Q[0])[:26]}...")
    print("   (The private key d lives inside the signer and is never sent.)")

    banner("2. As a passive observer, we collect (message, r, s) tuples")
    observed: list[ObservedSig] = []

    def record(m: bytes) -> None:
        sig = signer.sign_message(m)
        observed.append(ObservedSig(m, sig))
        print(f"   msg={m!r:32}  r={hex(sig.r)[:20]}...")

    # Parent process signs a couple of messages with healthy random nonces.
    record(b"transfer 10 to alice")
    record(b"transfer 25 to bob")
    # A fork / VM snapshot-restore happens here: the twin inherits PRNG state.
    twin = signer.fork()
    print("   -- process forked (twin inherits identical PRNG state) --")

    def record_from(s, m: bytes) -> None:
        sig = s.sign_message(m)
        observed.append(ObservedSig(m, sig))
        print(f"   msg={m!r:32}  r={hex(sig.r)[:20]}...")

    # Parent and twin each sign their next message; identical PRNG state means
    # identical nonce -> the same r on two DIFFERENT messages.
    record_from(signer, b"transfer 5 to carol")     # parent
    record_from(twin,   b"transfer 999 to dave")    # twin, SAME nonce

    banner("3. Detect nonce reuse and recover the private key from math alone")
    result = attack(observed)
    if not result:
        print("   No nonce reuse detected — nothing to recover.")
        return
    a, b = result["pair"]
    print(f"   Two messages share r  -> nonce reuse detected")
    print(f"     {a.msg!r}")
    print(f"     {b.msg!r}")
    print(f"   Recovered nonce  k = {hex(result['recovered_nonce_k'])[:26]}...")
    print(f"   Recovered key    d = {hex(result['recovered_private_key_d'])[:26]}...")

    banner("4. Proof: recovered key == real key")
    real_d = signer.d  # only used here to VERIFY the attack worked
    rec_d = result["recovered_private_key_d"]
    match = real_d == rec_d
    print(f"   real d      = {hex(real_d)[:26]}...")
    print(f"   recovered d = {hex(rec_d)[:26]}...")
    print(f"   EXACT MATCH: {match}")
    # independent check: recovered key regenerates the public key
    regen_Q = scalar_mul(rec_d, G)
    print(f"   recovered d * G == server public key Q : {regen_Q == Q}")

    banner("5. Weaponize (against our own target): forge a NEW authorization")
    forged_msg = b"transfer 1000000 to attacker"
    forged_sig = sign(rec_d, forged_msg)  # sign as if we were the server
    accepted = verify(Q, forged_msg, forged_sig)
    print(f"   Forged message : {forged_msg!r}")
    print(f"   Server's OWN verifier accepts the forgery: {accepted}")
    print("\n   The observer never saw the private key. It reconstructed it")
    print("   from two public signatures and can now impersonate the server.")


if __name__ == "__main__":
    main()
