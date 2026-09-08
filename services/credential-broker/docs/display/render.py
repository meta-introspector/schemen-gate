"""Render editable SVG diagrams and matching PNG previews; requires Pillow."""

from html import escape
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).parent
BG, PANEL, INK, MUTED = "#0c1422", "#152237", "#f0f5ff", "#a9b9d0"
TEAL, GOLD, BLUE, RED = "#52dec2", "#ffd184", "#8cb8ff", "#ff9b9b"
FONT = "/System/Library/Fonts/Supplemental/Arial.ttf"
BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"


class Board:
    def __init__(self, title, sub, number):
        self.im = Image.new("RGB", (1600, 1120), BG)
        self.d = ImageDraw.Draw(self.im)
        self.svg = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="1120" viewBox="0 0 1600 1120"><rect width="1600" height="1120" fill="{BG}"/>'
        ]
        self.text(60, 35, "SCHEMEN GATE  /  DELEGATED AUTHORIZATION", 19, TEAL, True)
        self.text(60, 80, title, 43, INK, True)
        self.text(60, 140, sub, 21, MUTED)
        self.text(
            60,
            1070,
            "BROKER 0.3.0  •  IMPLEMENTATION + ADOPTION GUIDE  •  NO SUBSTRATE REQUIRED",
            16,
            MUTED,
        )
        self.text(1490, 1070, number, 20, TEAL, True)

    def text(self, x, y, s, size=20, color=INK, bold=False):
        font = ImageFont.truetype(BOLD if bold else FONT, size)
        self.d.text((x, y), s, font=font, fill=color)
        self.svg.append(
            f'<text x="{x}" y="{y + size}" fill="{color}" font-family="Arial, sans-serif" font-size="{size}" font-weight="{700 if bold else 400}">{escape(s)}</text>'
        )

    def box(self, x, y, w, h, fill=PANEL, stroke=None):
        self.d.rounded_rectangle(
            (x, y, x + w, y + h), radius=12, fill=fill, outline=stroke, width=2
        )
        self.svg.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke or fill}" stroke-width="2"/>'
        )

    def line(self, x, y, xx, yy, color=MUTED, arrow=False):
        self.d.line((x, y, xx, yy), fill=color, width=2)
        self.svg.append(f'<path d="M{x} {y} L{xx} {yy}" stroke="{color}" stroke-width="2"/>')
        if arrow:
            sign = 1 if xx >= x else -1
            pts = [(xx, yy), (xx - sign * 10, yy - 5), (xx - sign * 10, yy + 5)]
            self.d.polygon(pts, fill=color)
            self.svg.append(
                '<polygon points="' + " ".join(f"{a},{b}" for a, b in pts) + f'" fill="{color}"/>'
            )

    def save(self, name):
        (OUT / f"{name}.svg").write_text("\n".join(self.svg + ["</svg>"]))
        self.im.save(OUT / f"{name}.png")


b = Board(
    "One request. A verifiable pause. One authorized call.",
    "Authenticated bindings from the original caller through approval, execution and result.",
    "01",
)
xs = [185, 490, 795, 1100, 1405]
labels = [
    ("CALLER", "Human or software"),
    ("AUTHORIZATION SERVICE", "Pinned service key"),
    ("APPROVER", "Owner or delegate"),
    ("GATE + CUSTODY", "Broker execution boundary"),
    ("GOOGLE CALENDAR", "Existing OAuth API"),
]
for x, (a, c) in zip(xs, labels, strict=True):
    b.box(x - 135, 200, 270, 72)
    b.text(x - 122, 213, a, 17, TEAL, True)
    b.text(x - 122, 241, c, 16, MUTED)
    b.line(x, 285, x, 970, "#2b3e58")


def msg(i, j, y, label, color=BLUE):
    b.text(min(xs[i], xs[j]) + 12, y - 31, label, 18, color)
    b.line(xs[i], y, xs[j], y, color, True)


msg(0, 1, 325, "1  Sign exact proposal")
b.box(370, 352, 540, 56, "#3a3024")
b.text(390, 367, "PAUSED  •  No provider credential acquired", 20, GOLD, True)
msg(1, 2, 450, "2  Signed request for review")
msg(2, 1, 515, "3  Signed, scoped decision")
msg(1, 0, 580, "4  Caller verifies signed callback")
msg(0, 1, 645, "5  Token exchange + client proof")
msg(1, 0, 710, "6  Key-bound operation grant")
msg(0, 3, 775, "7  Exact call + DPoP; Gate checks arguments")
b.box(970, 797, 285, 65, "#153e38")
b.text(986, 808, "CONSUME ATOMICALLY", 18, TEAL, True)
b.text(986, 835, "Then acquire per-call credential", 16, INK)
msg(3, 4, 905, "8  OAuth API request", TEAL)
msg(3, 0, 970, "9  Signed result after dispatch; owned custody discarded", TEAL)
b.text(
    60,
    1015,
    "Google enforces its OAuth grant. The broker enforces the exact delegated operation.",
    22,
    GOLD,
)
b.save("01-authenticated-swimlanes")

b = Board(
    "Authority is explicit at every handoff.",
    "A key proves who signed. A validated delegation determines what that signer may approve.",
    "02",
)
for x, title, lines in [
    (60, "RESOURCE OWNER", ["Configured authority root", "Bound to account + resource"]),
    (570, "DELEGATE", ["Parent commitment + child key", "Same request; shorter lifetime"]),
    (1080, "FINAL APPROVER", ["Signs approve / deny", "Human or software interface"]),
]:
    b.box(x, 235, 460, 170)
    b.text(x + 25, 260, title, 25, TEAL, True)
    for j, line in enumerate(lines):
        b.text(x + 25, 310 + j * 34, line, 22)
b.line(520, 320, 565, 320, TEAL, True)
b.line(1030, 320, 1075, 320, TEAL, True)
b.box(60, 455, 1480, 155)
b.text(90, 477, "THE COMMITMENT TRAVELS WITH THE REQUEST", 21, BLUE, True)
b.text(90, 522, "Caller key  ·  Tenant + connection  ·  Resource  ·  Operation + arguments", 26)
b.text(90, 561, "Return channel  ·  Nonce  ·  Expiry  ·  Parent chain  ·  One-use limit", 26)
for x, title, lines, col in [
    (
        60,
        "VALIDATE EACH LINK",
        [
            "Trusted root and final signer",
            "Parent hash and permitted action",
            "No scope or lifetime expansion",
            "Bounded depth; cycles rejected",
        ],
        TEAL,
    ),
    (
        820,
        "REJECT BEFORE DISPATCH",
        [
            "Substituted caller or connection",
            "Changed callback or arguments",
            "Expired or replayed proof",
            "Untrusted signer or broken parent",
        ],
        RED,
    ),
]:
    b.box(x, 655, 720, 235)
    b.text(x + 25, 680, title, 24, col, True)
    for j, line in enumerate(lines):
        b.text(x + 25, 730 + j * 35, line, 22)
b.text(
    60,
    936,
    "Implemented: a bounded linear approval chain. A human signing UI is an integration piece.",
    23,
    MUTED,
)
b.text(
    60,
    979,
    "TLS CA trust authenticates transport; resource authority needs its own scoped key binding.",
    23,
    GOLD,
)
b.save("02-delegation-and-bindings")

b = Board(
    "Enforce where the capability lives.",
    "Today: broker enforcement. Adoption proposal: native operation authorization at the resource API.",
    "03",
)
b.box(60, 220, 720, 355)
b.box(820, 220, 720, 355)
b.text(85, 246, "TODAY  /  IMPLEMENTED BROKER", 24, TEAL, True)
b.text(845, 246, "PROPOSAL  /  RESOURCE-NATIVE", 24, BLUE, True)
for x, lines in [
    (
        85,
        [
            "Caller → signed approval flow",
            "Gate → exact operation check",
            "Consume → acquire credential → Google",
            "Google checks its ordinary OAuth token",
        ],
    ),
    (
        845,
        [
            "Caller → resource authorization endpoint",
            "Owner / delegate → signed decision",
            "Resource API → verify operation grant",
            "Consume → execute inside resource boundary",
        ],
    ),
]:
    for j, s in enumerate(lines):
        b.text(x, 310 + j * 52, s, 23)
b.text(85, 532, "Protects credentials held by this broker.", 20, MUTED)
b.text(845, 532, "No broad provider token sent to the caller.", 20, MUTED)
b.text(60, 625, "ONE-USE LIFECYCLE", 23, GOLD, True)
for x, title in [(60, "PENDING"), (365, "APPROVED"), (670, "ISSUED"), (975, "CONSUMED")]:
    b.box(x, 680, 260, 65)
    b.text(x + 22, 699, title, 24, INK, True)
    if x < 975:
        b.line(x + 260, 712, x + 297, 712, TEAL, True)
b.text(1260, 698, "Dispatch", 24, TEAL, True)
b.line(1235, 712, 1252, 712, TEAL, True)
b.box(60, 785, 1480, 140)
b.text(85, 806, "CONSUMED IS TERMINAL FOR EXECUTION", 23, TEAL, True)
b.text(
    85,
    850,
    "Confirmed or uncertain result → signed receipt. Restart or retry cannot reopen the grant.",
    23,
)
b.text(
    85,
    885,
    "Owned per-call custody is discarded; this does not prove upstream token revocation.",
    21,
    MUTED,
)
b.text(
    60,
    962,
    "Local protocol tests pass. Live Google access is pending account configuration.",
    24,
    GOLD,
)
b.text(
    60,
    1002,
    "The native resource integration above is a proposal, not a claim of Google support.",
    22,
    MUTED,
)
b.save("03-resource-boundary")
