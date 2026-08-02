#!/usr/bin/env python3
"""Render clean terminal-style animated GIFs for the Kagebox README (no recorder needed)."""
from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONOB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FS = 15
font = ImageFont.truetype(MONO, FS)
fontb = ImageFont.truetype(MONOB, FS)
CW = font.getlength("M")
LH = FS + 9
PAD = 20
TOPBAR = 36

BG = (13, 17, 23); BAR = (22, 27, 34); FG = (201, 209, 217); DIM = (139, 148, 158)
GREEN = (63, 185, 80); YEL = (210, 153, 34); RED = (248, 81, 73); CYAN = (88, 166, 255)


def ok(text):     return [("  ", FG), ("[ok]", GREEN), ("   " + text, FG)]
def arrow(text):  return [("==>", CYAN), (" " + text, FG)]


def render(scene, n_lines, typed, cursor):
    lines = scene["lines"]
    maxc = max([len(scene["command"]) + 4] + [sum(len(t) for t, _ in ln) for ln in lines])
    W = int(PAD * 2 + (maxc + 2) * CW)
    H = int(TOPBAR + PAD + (len(lines) + 2) * LH + PAD)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # window chrome
    d.rectangle([0, 0, W, TOPBAR], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([PAD + i * 22, 13, PAD + i * 22 + 11, 24], fill=c)
    d.text((W / 2, TOPBAR / 2), scene["title"], font=font, fill=DIM, anchor="mm")
    # prompt + command
    y = TOPBAR + PAD
    d.text((PAD, y), "$", font=fontb, fill=GREEN)
    x = PAD + 2 * CW
    d.text((x, y), typed, font=font, fill=FG)
    if cursor:
        cx = x + len(typed) * CW
        d.rectangle([cx, y + 1, cx + CW - 1, y + FS + 2], fill=DIM)
    # output lines
    for ln in lines[:n_lines]:
        y += LH
        x = PAD
        for text, col in ln:
            d.text((x, y), text, font=font, fill=col)
            x += len(text) * CW
    return img


def build(scene, out):
    cmd = scene["command"]
    frames, durs = [], []
    # type the command
    for i in range(0, len(cmd) + 1, 2):
        frames.append(render(scene, 0, cmd[:i], True)); durs.append(45)
    frames.append(render(scene, 0, cmd, True)); durs.append(450)
    # reveal output lines
    for k in range(1, len(scene["lines"]) + 1):
        frames.append(render(scene, k, cmd, False)); durs.append(150)
    # hold
    frames.append(render(scene, len(scene["lines"]), cmd, False)); durs.append(2800)
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durs, loop=0, optimize=True)
    print("wrote", out, f"({len(frames)} frames, {frames[0].size})")


doctor = {"title": "kagebox", "command": "./kagebox doctor", "lines": [
    [("Preflight — Kagebox host checks:", FG)],
    ok("KVM: /dev/kvm present"),
    ok("multipass: multipass   1.16.3"),
    ok("python3 present (bridge dependency)"),
    ok("Ollama reachable on 127.0.0.1:11434"),
    ok("disk: 243 GB free"),
    ok("VM 'hermes': Running"),
    ok("bridge service active"),
    ok("memory backup present (2026-08-02T13:40:02Z)"),
    [],
    [("Summary: ", FG), ("8 ok", GREEN), (" · ", DIM), ("0 warn", DIM), (" · ", DIM), ("0 fail", DIM)],
]}

setup = {"title": "kagebox", "command": "./kagebox setup", "lines": [
    arrow("model 'hermes-ctx' ready"),
    arrow("Launching sandbox VM 'hermes' (4 cpu / 4G / 20G)..."),
    arrow("bridge listening on 10.85.206.1:18080"),
    [("   bridge OK  ", FG), ("✓", GREEN)],
    arrow("Installing Hermes Agent (Python 3.11 + Node + browser)..."),
    arrow("Verifying sandbox → bridge → Ollama..."),
    [("   {\"version\":\"0.32.5\"}  ", DIM), ("← Ollama reachable from sandbox", FG)],
    [("✓ Sandbox ready.", GREEN)],
    [("  Enter it:  ", FG), ("./kagebox shell", CYAN), ("   (then type: hermes)", DIM)],
]}

build(doctor, "docs/doctor.gif")
build(setup, "docs/setup.gif")
