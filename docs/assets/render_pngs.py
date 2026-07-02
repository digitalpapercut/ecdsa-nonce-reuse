"""
render_pngs.py — Render the two project visuals to pixel-exact PNGs.

Uses Pillow with the DejaVu fonts (bundled on most Linux boxes). Text is drawn
directly, so hex values and equations are reproduced exactly — no SVG-engine
tspan quirks, no image-model hallucination. Run:

    python3 render_pngs.py

Outputs (next to this script):
    nonce-reuse-algebra.png
    demo-terminal.png
"""

from __future__ import annotations

import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
SCALE = 2  # supersample then downscale for crisp edges

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

# palette (matches the SVGs)
BG = "#0f1420"
CARD = "#161c2c"
CARD_LINE = "#2a3550"
TITLE = "#e8edf7"
SUB = "#8a97b3"
FAINT = "#5f6b85"
OP = "#6f7d9c"
S = "#7cc4ff"   # signatures
Z = "#ffd479"   # hashes
K = "#7ef0c8"   # nonce
D = "#ff9db1"   # private key
R = "#c9a3ff"   # r value
CANCEL = "#ff6b81"
RES_FILL, RES_LINE = "#10281f", "#2f6f52"
RES2_FILL, RES2_LINE = "#2a1220", "#7a3049"

# terminal palette
WIN_BG, WIN_LINE, BAR = "#0b0f17", "#23293a", "#1b2130"
T_FG, T_DIM, T_RULE = "#c8d2e6", "#6b7894", "#4a5a7e"
T_HEAD, T_OK, T_KEY, T_HI, T_PROMPT, T_CMD = "#ffd479", "#7ef0c8", "#ff9db1", "#7cc4ff", "#7ef0c8", "#e8edf7"
T_TT = "#7b8aa8"


def font(path, size):
    return ImageFont.truetype(path, size * SCALE)


def S_(v):  # scale a coordinate/length
    return v * SCALE


def rrect(d, xy, radius, fill=None, outline=None, width=1):
    d.rounded_rectangle(
        [S_(xy[0]), S_(xy[1]), S_(xy[2]), S_(xy[3])],
        radius=S_(radius), fill=fill, outline=outline, width=max(1, width * SCALE),
    )


def segs(d, x, baseline, parts, f):
    """Draw colored inline segments left-to-right. parts = [(text, color), ...].
    baseline is the text baseline (SVG-style); PIL anchor 'ls' uses baseline."""
    cx = S_(x)
    for text, color in parts:
        d.text((cx, S_(baseline)), text, font=f, fill=color, anchor="ls")
        cx += d.textlength(text, font=f)


def finish(img, name):
    out = img.resize(
        (img.width // SCALE, img.height // SCALE), Image.LANCZOS
    )
    path = os.path.join(HERE, name)
    out.save(path)
    print("wrote", path, out.size)


# --------------------------------------------------------------------------
def render_algebra():
    W, H = 920, 600
    img = Image.new("RGB", (S_(W), S_(H)), BG)
    d = ImageDraw.Draw(img)

    f_title = font(SANS_B, 24)
    f_sub = font(SANS, 14)
    f_sub13 = font(SANS, 13)
    f_sub12 = font(SANS, 12)
    f_eq = font(MONO, 25)
    f_eq2 = font(MONO, 26)
    f_res_h = font(SANS_B, 14)
    f_res = font(MONO, 23)
    f_leg = font(SANS, 13)
    f_note = font(SANS, 14)

    d.text((S_(40), S_(52)), "Recovering the private key with grade-school algebra",
           font=f_title, fill=TITLE, anchor="ls")
    d.text((S_(40), S_(78)), "One reused nonce k across two messages leaks everything. "
           "All arithmetic is mod n (the curve order).", font=f_sub, fill=SUB, anchor="ls")

    rrect(d, (40, 100, 540, 250), 10, fill=CARD, outline=CARD_LINE, width=1)
    d.text((S_(60), S_(128)), "Two signatures made with the SAME nonce k (so the same r):",
           font=f_sub13, fill=SUB, anchor="ls")

    eq = [("s₁", S), ("·", OP), ("k", K), (" = ", OP), ("z₁", Z),
          (" + ", OP), ("r", R), ("·", OP), ("d", D)]
    eq_b = [("s₂", S), ("·", OP), ("k", K), (" = ", OP), ("z₂", Z),
            (" + ", OP), ("r", R), ("·", OP), ("d", D)]
    segs(d, 80, 172, eq, f_eq2)
    segs(d, 80, 214, eq_b, f_eq2)

    # cancel strikes through the r·d of each equation.
    # measure x of "r·d" start: width of "s₁·k = z₁ + " in f_eq2
    pre = d.textlength("s₁·k = z₁ + ", font=f_eq2)
    rd = d.textlength("r·d", font=f_eq2)
    x0 = S_(80) + pre
    for by in (172, 214):
        d.line([x0 - S_(3), S_(by - 8), x0 + rd + S_(3), S_(by - 8)],
               fill=CANCEL, width=max(1, 2 * SCALE))

    legend = [("s = signature scalar", S, 128), ("z = H(message)", Z, 150),
              ("k = nonce (secret, reused)", K, 172), ("r = x-coord of k·G", R, 194),
              ("d = private key (the prize)", D, 216)]
    for text, color, y in legend:
        d.text((S_(580), S_(y)), text, font=f_leg, fill=color, anchor="ls")

    # subtraction line
    d.text((S_(52), S_(300)), "Subtract the two equations — the",
           font=f_sub, fill=OP, anchor="ls")
    f_sub_b = font(SANS_B, 14)
    xrd = S_(52) + d.textlength("Subtract the two equations — the ", font=f_sub)
    d.text((xrd, S_(300)), "r·d", font=f_sub_b, fill=R, anchor="ls")
    xrd2 = xrd + d.textlength("r·d", font=f_sub_b)
    d.text((xrd2, S_(300)), " term is identical, so it cancels:", font=f_sub, fill=OP, anchor="ls")

    d.line([S_(80), S_(322), S_(470), S_(322)], fill=T_RULE, width=max(1, 1 * SCALE))

    sub_eq = [("(", OP), ("s₁", S), (" − ", OP), ("s₂", S), (")", OP),
              ("·", OP), ("k", K), (" = ", OP), ("z₁", Z), (" − ", OP), ("z₂", Z)]
    segs(d, 80, 366, sub_eq, f_eq2)

    # result cards
    rrect(d, (40, 410, 440, 490), 10, fill=RES_FILL, outline=RES_LINE, width=1)
    d.text((S_(60), S_(440)), "Solve for the nonce k", font=f_res_h, fill=K, anchor="ls")
    segs(d, 60, 475, [("k", K), (" = ", OP), ("(z₁ − z₂)", Z),
                      (" / ", OP), ("(s₁ − s₂)", S)], f_res)

    # arrow
    ay = 450
    d.line([S_(450), S_(ay), S_(496), S_(ay)], fill=OP, width=max(1, 1 * SCALE))
    d.polygon([(S_(496), S_(ay - 5)), (S_(506), S_(ay)), (S_(496), S_(ay + 5))], fill=OP)

    rrect(d, (510, 410, 880, 490), 10, fill=RES2_FILL, outline=RES2_LINE, width=1)
    d.text((S_(530), S_(440)), "Back-substitute for the private key d",
           font=f_res_h, fill=D, anchor="ls")
    segs(d, 530, 475, [("d", D), (" = ", OP), ("(", OP), ("s₁", S), ("·", OP),
                       ("k", K), (" − ", OP), ("z₁", Z), (")", OP), (" / ", OP), ("r", R)], f_res)

    d.text((S_(40), S_(534)), "The attacker only ever observes public (message, r, s) tuples.",
           font=f_note, fill=SUB, anchor="ls")
    d.text((S_(40), S_(555)), "No key material is transmitted — d is reconstructed from arithmetic alone.",
           font=f_note, fill=SUB, anchor="ls")
    d.text((S_(40), S_(580)), "Same bug class as the 2010 Sony PS3 signing break and the "
           "2013 Android SecureRandom Bitcoin thefts.", font=f_sub12, fill=FAINT, anchor="ls")

    finish(img, "nonce-reuse-algebra.png")


# --------------------------------------------------------------------------
def render_terminal():
    W, H = 940, 820
    img = Image.new("RGB", (S_(W), S_(H)), BG)
    d = ImageDraw.Draw(img)
    f = font(MONO, 13)
    f_tt = font(MONO, 12)

    rrect(d, (10, 10, 930, 810), 12, fill=WIN_BG, outline=WIN_LINE, width=1)
    # title bar
    rrect(d, (10, 10, 930, 44), 12, fill=BAR)
    d.rectangle([S_(10), S_(28), S_(930), S_(44)], fill=BAR)
    for cx, col in ((34, "#ff5f56"), (54, "#ffbd2e"), (74, "#27c93f")):
        d.ellipse([S_(cx - 6), S_(21), S_(cx + 6), S_(33)], fill=col)
    d.text((S_(470), S_(31)), "ecdsa-nonce-reuse — python3 src/demo.py",
           font=f_tt, fill=T_TT, anchor="ms")

    ox, oy = 28, 70
    lh = 18

    def line(y, parts):
        cx = S_(ox)
        for text, color in parts:
            d.text((cx, S_(oy + y)), text, font=f, fill=color, anchor="ls")
            cx += d.textlength(text, font=f)

    RULE = "=" * 68
    line(0, [("$ ", T_PROMPT), ("python3 src/demo.py", T_CMD)])

    line(34, [(RULE, T_RULE)])
    line(52, [("1. A service you do NOT control signs messages for clients", T_HEAD)])
    line(70, [(RULE, T_RULE)])
    line(90, [("   Server public key Q.x = ", T_DIM), ("0xb7c3cdec69e06f157a564618...", T_FG)])
    line(108, [("   (The private key d lives inside the signer and is never sent.)", T_DIM)])

    line(142, [(RULE, T_RULE)])
    line(160, [("2. As a passive observer, we collect (message, r, s) tuples", T_HEAD)])
    line(178, [(RULE, T_RULE)])
    line(198, [("   msg=", T_DIM), ("b'transfer 10 to alice'", T_FG), ("      r=", T_DIM), ("0x1fbea9a12ad0adc88a...", T_FG)])
    line(216, [("   msg=", T_DIM), ("b'transfer 25 to bob'", T_FG), ("        r=", T_DIM), ("0x1ab923ae1f9b9deeea...", T_FG)])
    line(234, [("   -- process forked (twin inherits identical PRNG state) --", T_DIM)])
    line(252, [("   msg=", T_DIM), ("b'transfer 5 to carol'", T_FG), ("       r=", T_DIM), ("0x468e2e8154bcad98bb...", T_HI)])
    line(270, [("   msg=", T_DIM), ("b'transfer 999 to dave'", T_FG), ("      r=", T_DIM), ("0x468e2e8154bcad98bb...", T_HI)])

    line(304, [(RULE, T_RULE)])
    line(322, [("3. Detect nonce reuse and recover the private key from math alone", T_HEAD)])
    line(340, [(RULE, T_RULE)])
    line(360, [("   Two messages share r  -> nonce reuse detected", T_FG)])
    line(378, [("     b'transfer 5 to carol'", T_DIM)])
    line(396, [("     b'transfer 999 to dave'", T_DIM)])
    line(414, [("   Recovered nonce  k = ", T_DIM), ("0x8aa3a6248280f7fe95a9cd87...", T_FG)])
    line(432, [("   Recovered key    d = ", T_DIM), ("0xe416f395e764254661766330...", T_KEY)])

    line(466, [(RULE, T_RULE)])
    line(484, [("4. Proof: recovered key == real key", T_HEAD)])
    line(502, [(RULE, T_RULE)])
    line(522, [("   real d      = ", T_DIM), ("0xe416f395e764254661766330...", T_KEY)])
    line(540, [("   recovered d = ", T_DIM), ("0xe416f395e764254661766330...", T_KEY)])
    line(558, [("   EXACT MATCH: ", T_DIM), ("True", T_OK)])
    line(576, [("   recovered d * G == server public key Q : ", T_DIM), ("True", T_OK)])

    line(610, [(RULE, T_RULE)])
    line(628, [("5. Weaponize (against our own target): forge a NEW authorization", T_HEAD)])
    line(646, [(RULE, T_RULE)])
    line(666, [("   Forged message : ", T_DIM), ("b'transfer 1000000 to attacker'", T_FG)])
    line(684, [("   Server's OWN verifier accepts the forgery: ", T_DIM), ("True", T_OK)])
    line(710, [("   The observer never saw the private key. It reconstructed it", T_DIM)])
    line(728, [("   from two public signatures and can now impersonate the server.", T_DIM)])

    finish(img, "demo-terminal.png")


if __name__ == "__main__":
    render_algebra()
    render_terminal()
