"""
server.py — Optional localhost HTTP version of the vulnerable signer.

A tiny "signing service" you run on 127.0.0.1. It exposes an endpoint that
signs client-supplied messages and returns ONLY (r, s) plus the public key.
The private key never leaves the process. A /fork endpoint simulates the
fork/snapshot event that triggers nonce reuse.

This exists so the attack can be demonstrated as a real client/server
exchange (nice for a screen recording). It binds to localhost only.

Run:  python3 src/server.py
Then: python3 src/client_attack.py
"""

from __future__ import annotations

from flask import Flask, request, jsonify

from vulnerable_signer import VulnerableSigner

app = Flask(__name__)

# One "primary" signer process. /fork produces a twin sharing PRNG state.
primary = VulnerableSigner(bug="fork_reseed")
twin: VulnerableSigner | None = None


@app.get("/pubkey")
def pubkey():
    Q = primary.public_key()
    return jsonify({"qx": Q[0], "qy": Q[1]})


@app.post("/sign")
def sign_endpoint():
    data = request.get_json(force=True)
    msg = data["message"].encode()
    who = data.get("process", "primary")
    signer = twin if (who == "twin" and twin is not None) else primary
    sig = signer.sign_message(msg)
    # Note what is (and is not) returned: no key, no nonce. Only r, s.
    return jsonify({"message": data["message"], "r": sig.r, "s": sig.s})


@app.post("/fork")
def fork_endpoint():
    global twin
    twin = primary.fork()
    return jsonify({"status": "forked", "note": "twin inherited PRNG state"})


if __name__ == "__main__":
    print("Vulnerable signing service on http://127.0.0.1:5000 (localhost only)")
    app.run(host="127.0.0.1", port=5000)
