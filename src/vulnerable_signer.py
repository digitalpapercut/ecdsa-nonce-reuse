"""
vulnerable_signer.py — A signer with a REALISTIC nonce-reuse bug.

The naive demo sets k=1234. Real incidents are subtler. Two authentic
historical patterns are modeled here (choose with `bug=`):

  "fork_reseed":
      The signer derives its nonce from a PRNG that is seeded at process
      start. When the process forks (or a container is snapshotted and
      restored), both copies inherit the same PRNG state and therefore
      produce the SAME nonce for their first signature. This is the class
      of bug behind several real embedded/VM key compromises.

  "counter_wrap":
      A "deterministic" signer keeps a counter and mixes it into the nonce.
      A narrow counter (here 8 bits, for demo speed) eventually wraps and
      collides, reusing a nonce across two different messages.

The server exposes ONLY (message, r, s). The private key and nonce never
leave. This mirrors what a real client/attacker actually observes.

Author: (portfolio research)
License: MIT
"""

from __future__ import annotations

import hashlib

from ecdsa_min import N, Signature, keygen, sign, Point


class VulnerableSigner:
    def __init__(self, bug: str = "fork_reseed", seed: bytes = b"process-start-entropy"):
        self.d, self.Q = keygen()        # private key stays inside the object
        self.bug = bug
        self._seed = seed
        self._counter = 0
        # Toy PRNG state, seeded at "process start".
        self._prng_state = seed

    def _prng_nonce(self) -> int:
        """Advance a toy PRNG and emit a nonce. NOT secure — models a buggy
        nonce source seeded once at process start."""
        self._prng_state = hashlib.sha256(self._prng_state).digest()
        return int.from_bytes(self._prng_state, "big") % (N - 1) + 1

    def _nonce_for(self, msg: bytes) -> int:
        if self.bug == "fork_reseed":
            # BUG: the nonce comes from a PRNG seeded once at process start.
            # This is fine WITHIN one process. It fails across a fork/snapshot
            # because two processes inherit identical PRNG state (see fork()).
            return self._prng_nonce()
        elif self.bug == "counter_wrap":
            # BUG: narrow counter mixed into nonce wraps and collides.
            self._counter = (self._counter + 1) & 0xFF  # 8-bit wrap
            mixed = hashlib.sha256(
                self._seed + self._counter.to_bytes(1, "big")
            ).digest()
            return int.from_bytes(mixed, "big") % (N - 1) + 1
        else:
            raise ValueError(f"unknown bug mode {self.bug}")

    def fork(self) -> "VulnerableSigner":
        """Simulate a process fork / VM snapshot-restore. Returns a TWIN
        signer that shares the parent's private key AND inherits the exact
        PRNG state. Because both processes now advance from identical state,
        their next signatures reuse the same nonce -> key recovery.

        This is the real-world bug: os.fork() copies memory, including PRNG
        state, and neither child reseeds. VM snapshot/restore does the same.
        """
        twin = VulnerableSigner.__new__(VulnerableSigner)
        twin.d = self.d              # same key: both are the same service
        twin.Q = self.Q
        twin.bug = self.bug
        twin._seed = self._seed
        twin._counter = self._counter
        twin._prng_state = self._prng_state   # INHERITED — the fatal copy
        return twin

    def sign_message(self, msg: bytes) -> Signature:
        k = self._nonce_for(msg)
        return sign(self.d, msg, k=k)

    def public_key(self) -> Point:
        return self.Q
