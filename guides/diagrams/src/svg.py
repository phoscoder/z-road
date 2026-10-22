"""Tiny helpers for drawing the guide diagrams as clean, consistent SVG.

Run `python3 make_diagrams.py` to regenerate every diagram in ../ from the code.
"""
from xml.sax.saxutils import escape

GREEN, GREEN_DK = "#1F7A4D", "#14593A"
GREEN_BG, GREEN_BD = "#EAF4EE", "#C9DDD0"
GOLD_BG, GOLD_BD, GOLD_TX = "#FFF3C4", "#E6B800", "#6B5200"
BLUE_BG, BLUE_BD, BLUE_TX = "#E3EAFB", "#9DB2E8", "#2B4A9B"
RED_BG, RED_BD, RED_TX = "#FDE8E8", "#F0A8A8", "#9B1C1C"
INK, MUTED, LINE = "#0F172A", "#64748B", "#94A3B8"
PAPER, PAPER_BD = "#FBFCFA", "#DDE5DF"
FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"


class Svg:
    def __init__(self, w, h, title, desc, heading=None, sub=None):
        self.w, self.h, self.title, self.desc = w, h, title, desc
        self.parts = []
        self.heading = heading
        self.sub = sub

    # -- primitives -----------------------------------------------------
    def add(self, s):
        self.parts.append(s)

    def rect(self, x, y, w, h, fill="#fff", stroke=GREEN_BD, r=12, sw=1.2, shadow=False, dash=None, op=None):
        extra = f' stroke-dasharray="{dash}"' if dash else ""
        extra += f' fill-opacity="{op}"' if op is not None else ""
        f = ' filter="url(#sh)"' if shadow else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{extra}{f}/>')

    def text(self, x, y, s, size=13, weight=400, fill=INK, anchor="start", italic=False, spacing=None):
        st = ' font-style="italic"' if italic else ""
        sp = f' letter-spacing="{spacing}"' if spacing else ""
        self.add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{st}{sp}>{escape(s)}</text>')

    def lines(self, x, y, items, size=12.5, gap=18, fill=INK, anchor="start", weight=400):
        for i, s in enumerate(items):
            self.text(x, y + i * gap, s, size=size, fill=fill, anchor=anchor, weight=weight)

    def line(self, x1, y1, x2, y2, color=LINE, w=1.6, dash=None, arrow=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        m = ""
        if arrow in ("end", "both"):
            m += f' marker-end="url(#a-{self._mk(color)})"'
        if arrow in ("start", "both"):
            m += f' marker-start="url(#a-{self._mk(color)})"'
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{w}"{d}{m}/>')

    def path(self, d, color=LINE, w=1.6, dash=None, arrow=None, fill="none"):
        dd = f' stroke-dasharray="{dash}"' if dash else ""
        m = ""
        if arrow in ("end", "both"):
            m += f' marker-end="url(#a-{self._mk(color)})"'
        if arrow in ("start", "both"):
            m += f' marker-start="url(#a-{self._mk(color)})"'
        self.add(f'<path d="{d}" fill="{fill}" stroke="{color}" stroke-width="{w}"{dd}{m}/>')

    def circle(self, cx, cy, r, fill=GREEN, stroke="none", sw=0):
        self.add(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')

    def badge(self, cx, cy, n, fill=GREEN, tx="#fff", r=13):
        self.circle(cx, cy, r, fill)
        self.text(cx, cy + 4.5, str(n), size=13, weight=700, fill=tx, anchor="middle")

    def chip(self, x, y, label, bg=GREEN_BG, tx=GREEN, w=None, h=22, size=11):
        w = w or int(len(label) * size * 0.62 + 18)
        self.rect(x, y, w, h, bg, "none", r=h / 2, sw=0)
        self.text(x + w / 2, y + h / 2 + 4, label, size=size, weight=700, fill=tx, anchor="middle")
        return w

    def card(self, x, y, w, h, title, sub=None, kind="white", sub2=None):
        fills = {
            "white": ("#FFFFFF", "#C9D3CC", INK, MUTED),
            "green": (GREEN, GREEN, "#fff", "#CFE9DA"),
            "gold": (GOLD_BG, GOLD_BD, GOLD_TX, "#8A6D00"),
            "blue": (BLUE_BG, BLUE_BD, BLUE_TX, "#5A74B8"),
            "red": (RED_BG, RED_BD, RED_TX, "#B45454"),
            "soft": (GREEN_BG, GREEN_BD, GREEN_DK, "#4C7A62"),
        }
        bg, bd, t1, t2 = fills[kind]
        self.rect(x, y, w, h, bg, bd, shadow=True)
        cy = y + h / 2
        if sub is None and sub2 is None:
            self.text(x + w / 2, cy + 5, title, 14, 600, t1, "middle")
        elif sub2 is None:
            self.text(x + w / 2, cy - 2, title, 14, 600, t1, "middle")
            self.text(x + w / 2, cy + 16, sub, 11.5, 400, t2, "middle")
        else:
            self.text(x + w / 2, cy - 10, title, 14, 600, t1, "middle")
            self.text(x + w / 2, cy + 8, sub, 11.5, 400, t2, "middle")
            self.text(x + w / 2, cy + 24, sub2, 11.5, 400, t2, "middle")

    def zone(self, x, y, w, h, label, kind="soft", dash=None):
        bg, bd, tx = {
            "soft": (GREEN_BG, GREEN_BD, GREEN),
            "gold": ("#FFFAE6", GOLD_BD, "#9A7B00"),
            "blue": ("#F1F5FD", BLUE_BD, BLUE_TX),
            "red": ("#FEF3F3", RED_BD, RED_TX),
            "grey": ("#F4F6F5", "#CBD5D0", MUTED),
        }[kind]
        self.rect(x, y, w, h, bg, bd, r=16, dash=dash, op=0.85)
        self.text(x + 18, y + 25, label.upper(), 10.5, 700, tx, spacing="1.2")

    # -- output ---------------------------------------------------------
    def _mk(self, color):
        return color.lstrip("#")

    def render(self):
        colors = {GREEN, LINE, MUTED, GOLD_BD, BLUE_TX, RED_TX, INK, "#B42318"}
        markers = "".join(
            f'<marker id="a-{self._mk(c)}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
            for c in colors
        )
        head = ""
        if self.heading:
            head += f'<text x="40" y="44" font-size="22" font-weight="700" fill="{INK}">{escape(self.heading)}</text>'
        if self.sub:
            head += f'<text x="40" y="66" font-size="13" fill="{MUTED}">{escape(self.sub)}</text>'
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" font-family="{FONT}">\n'
            f"<title>{escape(self.title)}</title><desc>{escape(self.desc)}</desc>\n"
            f'<defs>{markers}<filter id="sh" x="-10%" y="-10%" width="120%" height="140%"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#0F172A" flood-opacity="0.12"/></filter></defs>\n'
            f'<rect x="0.5" y="0.5" width="{self.w - 1}" height="{self.h - 1}" rx="18" fill="{PAPER}" stroke="{PAPER_BD}"/>\n'
            f'<rect x="0.5" y="0.5" width="{self.w - 1}" height="6" rx="3" fill="{GREEN}"/>\n'
            + head
            + "\n"
            + "\n".join(self.parts)
            + "\n</svg>\n"
        )
