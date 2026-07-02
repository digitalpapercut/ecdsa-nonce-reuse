# Recovering an ECDSA Private Key From Two Signatures

A self-contained, from-scratch demonstration that if an ECDSA signer ever
reuses a nonce across two different messages, anyone who observes the two
signatures can recover the private key with grade-school algebra — no
brute force, no side channel, no key material ever transmitted.

This is the bug class behind the 2010 Sony PS3 code-signing break and the
2013 Android `SecureRandom` Bitcoin wallet thefts. The math is old and
public; the value here is a clean, dependency-free repro that shows every
step and closes the loop with a working forgery.

## What it does

1. Implements ECDSA over secp256k1 from scratch (pure stdlib, no `ecdsa`
   or `cryptography` library) so every operation is auditable.
2. Stands up a vulnerable signer with a **realistic** nonce-reuse bug
   (a fork / VM-snapshot that copies PRNG state — not a hard-coded `k`).
3. Acts as a **passive observer** that only sees `(message, r, s)` tuples,
   detects the reused nonce by spotting a repeated `r`, and recovers the key.
4. Proves the recovered key equals the real one, then forges a brand-new
   authorization the signer's own verifier accepts.

## The math

A signature is `s = k^-1 (z + r*d) mod n`, where `z = H(m)`, `d` is the
private key, and `k` is the per-signature nonce. `r` depends only on `k`,
so reusing `k` produces the same `r` on two messages. Then:

```
s1*k = z1 + r*d
s2*k = z2 + r*d
--------------------------
(s1 - s2)*k = z1 - z2      =>   k = (z1 - z2) / (s1 - s2)  mod n
d = (s1*k - z1) / r        mod n
```

![The two signatures share a nonce, so the r·d term cancels on subtraction — revealing k and then the private key d.](docs/assets/nonce-reuse-algebra.png)

## Run it

```bash
python3 src/demo.py          # full observe -> recover -> forge chain
```

No dependencies. Python 3.10+. Runs offline in under a second.

![Terminal output of demo.py: the two forked signatures share an r, the recovered key matches the real one bit-for-bit (EXACT MATCH: True), and a forged authorization is accepted.](docs/assets/demo-terminal.png)

The optional live HTTP demo needs Flask:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 src/server.py        # then, in another terminal: python3 src/client_attack.py
```

### Interactive attacker console (forge your own message)

For a hands-on version, run the victim service and the browser-based attacker
console in two terminals:

```bash
python3 src/server.py        # victim signing service on :5000
python3 src/attack_web.py    # attacker console on :5001
```

Open <http://127.0.0.1:5001>: click once to observe signatures and recover the
key from the reused nonce, then type **any** message and forge it. The victim's
own `/verify` endpoint judges your forgery — and accepts a message it never
signed. The attacker console only ever calls the public endpoints; the private
key never leaves the victim process.

## Files

- `src/ecdsa_min.py` — from-scratch secp256k1 + ECDSA (sign/verify).
- `src/attack.py` — nonce-reuse detection and key recovery (the core).
- `src/vulnerable_signer.py` — two realistic nonce-reuse bug models.
- `src/demo.py` — end-to-end offline demonstration.
- `src/server.py` / `src/client_attack.py` — optional localhost HTTP version.
- `src/attack_web.py` — interactive browser console: recover the key, forge any message.
- `tests/test_nonce_reuse.py` — self-tests (curve math, recovery, forgery).
- `docs/writeup.md` — the full research report (background, threat model, results, defenses).

## Safety / ethics

- Everything targets a signer you instantiate locally. Nothing here scans,
  connects to, or attacks any third-party system.
- The `ecdsa_min.py` code is intentionally **not** constant-time or hardened.
  Do not use it to protect anything. It exists to make the math legible.
- The recovery technique is textbook public cryptanalysis (SEC1 + basic
  modular algebra). Publishing it does not create new capability; it makes
  an existing, still-recurring failure mode easy to understand and test for.
- If you find nonce reuse in real software, follow responsible disclosure.

## Why this is worth reading

Most write-ups show the algebra on two hand-picked signatures. This one
models a plausible root cause (inherited PRNG state across a fork), forces
the attacker to *discover* the reuse from public data, and demonstrates the
consequence end to end — recovered key, accepted forgery. It also serves as
a working reference for detecting nonce reuse defensively.
