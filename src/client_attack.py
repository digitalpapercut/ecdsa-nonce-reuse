"""
client_attack.py — Passive-observer attack against the localhost server.

We are an ordinary client of the signing service. We request signatures,
trigger the (realistic) fork event, and recover the server's private key
purely from the (r, s) values it returns over HTTP. Then we forge a message
and confirm the recovered key produces a signature the server would accept.

Run server.py first, then this.
"""

from __future__ import annotations

import requests

from ecdsa_min import Signature, sign, verify
from attack import ObservedSig, attack

BASE = "http://127.0.0.1:5000"


def request_sig(message: str, process: str = "primary") -> ObservedSig:
    r = requests.post(f"{BASE}/sign",
                      json={"message": message, "process": process}).json()
    return ObservedSig(message.encode(), Signature(r["r"], r["s"]))


def main() -> None:
    Q = requests.get(f"{BASE}/pubkey").json()
    Qpt = (Q["qx"], Q["qy"])
    print(f"[*] Server public key qx = {hex(Qpt[0])[:24]}...")

    observed = []
    for m in ["pay 10 to alice", "pay 25 to bob"]:
        observed.append(request_sig(m))
        print(f"[*] observed sig for {m!r}")

    requests.post(f"{BASE}/fork")
    print("[*] triggered /fork (twin inherits PRNG state)")

    observed.append(request_sig("pay 5 to carol", process="primary"))
    observed.append(request_sig("pay 999 to dave", process="twin"))
    print("[*] collected post-fork signatures")

    res = attack(observed)
    if not res:
        print("[!] no nonce reuse observed")
        return
    d = res["recovered_private_key_d"]
    print(f"[+] recovered private key d = {hex(d)[:24]}...")

    forged = b"pay 1000000 to attacker"
    forged_sig = sign(d, forged)
    ok = verify(Qpt, forged, forged_sig)
    print(f"[+] forged {forged!r} accepted by server's verifier: {ok}")


if __name__ == "__main__":
    main()
