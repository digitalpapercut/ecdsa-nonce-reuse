"""
attack_web.py — Interactive attacker console (browser front-end).

This is the ATTACKER, running as a separate party from the victim service in
`server.py`. It talks to the victim over HTTP using only the public endpoints
(/pubkey, /sign, /fork, /verify). It never has access to the private key, the
nonce, or the victim's memory — exactly like a real passive observer.

What the page lets you do:
  1. Observe a handful of signatures, trigger the (realistic) fork event, and
     recover the victim's private key from the two signatures that reused a
     nonce — all from public (r, s) values.
  2. Type ANY message and forge a signature with the recovered key, then send
     it to the victim's own /verify endpoint and watch the victim accept a
     message it never signed.

Run (two terminals):
    python3 src/server.py         # victim, on :5000
    python3 src/attack_web.py     # this console, on :5001
Then open http://127.0.0.1:5001
"""

from __future__ import annotations

import requests
from flask import Flask, jsonify, render_template_string, request

from ecdsa_min import Signature, sign
from attack import ObservedSig, attack

VICTIM = "http://127.0.0.1:5000"

app = Flask(__name__)

# The only thing the attacker "keeps" between requests: what it recovered from
# public data. Never the victim's real key object.
state: dict = {"recovered_d": None, "pubkey": None}


def _request_sig(message: str, process: str = "primary") -> dict:
    return requests.post(
        f"{VICTIM}/sign", json={"message": message, "process": process}, timeout=5
    ).json()


@app.post("/api/run")
def api_run():
    """Observe signatures, force the fork, and recover the key — public data only."""
    try:
        Q = requests.get(f"{VICTIM}/pubkey", timeout=5).json()
    except requests.RequestException:
        return jsonify({"error": "Victim server not reachable on :5000. "
                                 "Start it with  python3 src/server.py"}), 502

    Qpt = (Q["qx"], Q["qy"])
    state["pubkey"] = Qpt

    steps = []
    observed: list[ObservedSig] = []

    def observe(msg: str, process: str, note: str) -> None:
        s = _request_sig(msg, process)
        observed.append(ObservedSig(msg.encode(), Signature(s["r"], s["s"])))
        steps.append({"msg": msg, "r": s["r"], "note": note})

    observe("pay 10 to alice", "primary", "primary process, healthy nonce")
    observe("pay 25 to bob", "primary", "primary process, healthy nonce")
    requests.post(f"{VICTIM}/fork", timeout=5)
    steps.append({"fork": True})
    observe("pay 5 to carol", "primary", "primary, first nonce after fork")
    observe("pay 999 to dave", "twin", "TWIN — inherited PRNG state, same nonce")

    res = attack(observed)
    if not res:
        return jsonify({"error": "No nonce reuse observed."}), 500

    d = res["recovered_private_key_d"]
    state["recovered_d"] = d
    reused_r = res["reused_r"]
    a, b = res["pair"]

    return jsonify({
        "pubkey_qx": hex(Qpt[0]),
        "steps": steps,
        "reused_r": hex(reused_r),
        "pair": [a.msg.decode(), b.msg.decode()],
        "recovered_k": hex(res["recovered_nonce_k"]),
        "recovered_d": hex(d),
    })


@app.post("/api/forge")
def api_forge():
    """Sign a user-supplied message with the recovered key and ask the victim
    to verify it. Acceptance means the forgery is indistinguishable from a
    genuine signature by the service."""
    if state["recovered_d"] is None:
        return jsonify({"error": "Recover the key first."}), 400

    message = (request.get_json(force=True).get("message") or "").strip()
    if not message:
        return jsonify({"error": "Type a message to forge."}), 400

    d = state["recovered_d"]
    forged = sign(d, message.encode())  # signed as if we were the server
    verdict = requests.post(
        f"{VICTIM}/verify",
        json={"message": message, "r": forged.r, "s": forged.s}, timeout=5,
    ).json()

    return jsonify({
        "message": message,
        "r": hex(forged.r),
        "s": hex(forged.s),
        "accepted": bool(verdict.get("accepted")),
    })


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ECDSA Nonce-Reuse — Attacker Console</title>
<style>
  :root {
    --bg:#0f1420; --card:#161c2c; --line:#2a3550; --ink:#e8edf7; --sub:#8a97b3;
    --dim:#6b7894; --k:#7ef0c8; --d:#ff9db1; --hi:#7cc4ff; --ok:#7ef0c8;
    --bad:#ff6b81; --accent:#7cc4ff;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:820px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:24px; margin:0 0 4px; }
  .sub { color:var(--sub); margin:0 0 24px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:20px; margin:16px 0; }
  .step-label { font-size:13px; color:var(--dim); text-transform:uppercase;
    letter-spacing:.06em; margin:0 0 12px; }
  button { background:var(--accent); color:#08121f; border:0; border-radius:8px;
    font-weight:600; font-size:15px; padding:11px 18px; cursor:pointer; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  button.ghost { background:transparent; color:var(--accent);
    border:1px solid var(--line); }
  code, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  table { width:100%; border-collapse:collapse; margin-top:12px; font-size:13.5px; }
  td { padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
  td.msg { color:var(--ink); }
  td.r { color:var(--dim); font-family:ui-monospace,Menlo,monospace; }
  tr.reuse td.r { color:var(--hi); font-weight:600; }
  tr.fork td { color:var(--dim); font-style:italic; text-align:center; }
  .keyline { font-family:ui-monospace,Menlo,monospace; font-size:13.5px; margin:4px 0; }
  .keyline .lbl { color:var(--dim); }
  .keyline .d { color:var(--d); }
  .keyline .k { color:var(--k); }
  input[type=text] { width:100%; background:#0b0f17; border:1px solid var(--line);
    color:var(--ink); border-radius:8px; padding:11px 12px; font-size:15px;
    font-family:ui-monospace,Menlo,monospace; margin-bottom:12px; }
  .verdict { font-size:20px; font-weight:700; margin-top:14px; }
  .verdict.ok { color:var(--ok); }
  .verdict.bad { color:var(--bad); }
  .fine { color:var(--dim); font-size:13px; margin-top:8px; }
  .muted { color:var(--sub); }
  .hidden { display:none; }
  .sigline { font-family:ui-monospace,Menlo,monospace; font-size:12.5px;
    color:var(--dim); word-break:break-all; margin-top:10px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>ECDSA Nonce-Reuse — Attacker Console</h1>
  <p class="sub">You are a passive observer. You only ever see
    <code>(message, r, s)</code> from the service on :5000 — never its key.</p>

  <div class="card">
    <p class="step-label">Step 1 — Observe &amp; recover the private key</p>
    <button id="runBtn">Observe signatures &amp; recover key</button>
    <div id="runOut" class="hidden">
      <table id="sigTable"></table>
      <div id="keyBox" style="margin-top:16px;"></div>
    </div>
  </div>

  <div class="card" id="forgeCard" style="opacity:.45;">
    <p class="step-label">Step 2 — Forge any message as the server</p>
    <input type="text" id="msg" placeholder="e.g. transfer 1000000 to attacker" disabled/>
    <button id="forgeBtn" disabled>Forge &amp; send to server's verifier</button>
    <div id="forgeOut"></div>
    <p class="fine">The signature is made with the recovered key and checked by the
      victim's own <code>/verify</code>. Acceptance = you are now the signer.</p>
  </div>
</div>

<script>
const $ = s => document.querySelector(s);

function short(hex){ return hex.length > 22 ? hex.slice(0,22) + "…" : hex; }

$("#runBtn").addEventListener("click", async () => {
  const btn = $("#runBtn");
  btn.disabled = true; btn.textContent = "Observing…";
  try {
    const res = await fetch("/api/run", {method:"POST"});
    const data = await res.json();
    if (!res.ok) { alert(data.error || "Failed"); btn.disabled = false;
      btn.textContent = "Observe signatures & recover key"; return; }

    const rows = data.steps.map(s => {
      if (s.fork) return `<tr class="fork"><td colspan="2">— process forked: twin inherits identical PRNG state —</td></tr>`;
      const isReuse = data.pair.includes(s.msg);
      return `<tr class="${isReuse ? 'reuse':''}">
        <td class="msg">${s.msg}</td>
        <td class="r">r = ${short(s.r)}</td></tr>`;
    }).join("");
    $("#sigTable").innerHTML = rows;

    $("#keyBox").innerHTML = `
      <div class="muted" style="margin-bottom:8px;">Two messages
        (<code>${data.pair[0]}</code>, <code>${data.pair[1]}</code>)
        share <span class="mono" style="color:var(--hi)">r = ${short(data.reused_r)}</span>
        → nonce reuse detected.</div>
      <div class="keyline"><span class="lbl">recovered nonce  k = </span><span class="k">${short(data.recovered_k)}</span></div>
      <div class="keyline"><span class="lbl">recovered key    d = </span><span class="d">${short(data.recovered_d)}</span></div>`;

    $("#runOut").classList.remove("hidden");
    btn.textContent = "Key recovered ✓";

    // unlock step 2
    $("#forgeCard").style.opacity = "1";
    $("#msg").disabled = false; $("#forgeBtn").disabled = false;
    $("#msg").focus();
  } catch (e) {
    alert("Could not reach the console backend."); btn.disabled = false;
    btn.textContent = "Observe signatures & recover key";
  }
});

async function doForge(){
  const message = $("#msg").value.trim();
  if (!message) return;
  const btn = $("#forgeBtn");
  btn.disabled = true; const old = btn.textContent; btn.textContent = "Forging…";
  try {
    const res = await fetch("/api/forge", {method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({message})});
    const data = await res.json();
    if (!res.ok) { alert(data.error || "Failed"); return; }
    const cls = data.accepted ? "ok" : "bad";
    const word = data.accepted ? "ACCEPTED" : "REJECTED";
    $("#forgeOut").innerHTML = `
      <div class="sigline">forged signature&nbsp; r = ${short(data.r)}&nbsp; s = ${short(data.s)}</div>
      <div class="verdict ${cls}">Server's own verifier: ${word}</div>
      <div class="fine">You signed “${data.message}” — a message the server never issued.</div>`;
  } finally {
    btn.disabled = false; btn.textContent = old;
  }
}
$("#forgeBtn").addEventListener("click", doForge);
$("#msg").addEventListener("keydown", e => { if (e.key === "Enter") doForge(); });
</script>
</body>
</html>"""


@app.get("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    print("Attacker console on http://127.0.0.1:5001  (victim must be on :5000)")
    app.run(host="127.0.0.1", port=5001)
