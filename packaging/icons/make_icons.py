"""Draw the OffsecHub app icon and write it in every format the installers need.

    python packaging/icons/make_icons.py

Writes offsechub.png (1024 px), offsechub.ico (Windows), offsechub.icns (macOS),
offsechub.svg and offsechub-<size>.png (Linux) next to this script. The mark is the
shield from the app's header (frontend/src/components/ui.tsx), on a dark tile.
Needs Pillow.
"""

from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
SIZE = 1024
SS = 4  # supersampling factor for smooth edges
ACCENT = (45, 212, 191, 255)  # --accent
TOP, BOTTOM = (22, 34, 56), (10, 15, 26)  # tile gradient, ends at --bg
INSET, RADIUS = 64, 200  # tile margin and corner radius at 1024 px
LINUX_SIZES = (48, 128, 256, 512)  # hicolor theme sizes shipped in the .deb

# The logo's 32x32 viewBox, as drawn in the app.
SHIELD_SVG_PATH = "M16 4 6 8.5v6.7c0 6.5 4.2 11.3 10 13 5.8-1.7 10-6.5 10-13V8.5z"
STROKE, DOT = 2.2, 3.4
SCALE = 24.0  # viewBox units -> px at 1024
CENTER = (16.0, 16.1)  # middle of the shield's bounding box


def cubic(p0, p1, p2, p3, steps=48):
    for i in range(1, steps + 1):
        t = i / steps
        u = 1 - t
        yield (u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0],
               u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1])


def shield_outline():
    """The path above, with its two curves flattened (in viewBox units)."""
    pts = [(16, 4), (6, 8.5), (6, 15.2)]
    pts += cubic((6, 15.2), (6, 21.7), (10.2, 26.5), (16, 28.2))
    pts += cubic((16, 28.2), (21.8, 26.5), (26, 21.7), (26, 15.2))
    pts += [(26, 8.5), (16, 4)]
    return pts


def to_px(pt, k):
    return ((pt[0] - CENTER[0]) * SCALE * k + SIZE * k / 2, (pt[1] - CENTER[1]) * SCALE * k + SIZE * k / 2)


def draw() -> Image.Image:
    k = SS
    big = SIZE * k
    tile = Image.new("RGBA", (big, big))
    grad = ImageDraw.Draw(tile)
    for y in range(big):
        f = y / (big - 1)
        grad.line([(0, y), (big, y)], fill=tuple(round(a + (b - a) * f) for a, b in zip(TOP, BOTTOM)) + (255,))
    mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(mask).rounded_rectangle([INSET * k, INSET * k, big - INSET * k, big - INSET * k],
                                           RADIUS * k, fill=255)
    icon = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    icon.paste(tile, mask=mask)

    d = ImageDraw.Draw(icon)
    width = round(STROKE * SCALE * k)
    outline = [to_px(p, k) for p in shield_outline()]
    d.line(outline, fill=ACCENT, width=width, joint="curve")
    for x, y in (outline[0], outline[1], outline[-2]):  # round the corners the joints leave square
        d.ellipse([x - width / 2, y - width / 2, x + width / 2, y + width / 2], fill=ACCENT)
    cx, cy = to_px((16, 15), k)
    r = DOT * SCALE * k
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=ACCENT)
    return icon.resize((SIZE, SIZE), Image.LANCZOS)


def svg() -> str:
    tx, ty = SIZE / 2 - CENTER[0] * SCALE, SIZE / 2 - CENTER[1] * SCALE
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SIZE} {SIZE}">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="rgb{TOP}"/>
      <stop offset="1" stop-color="rgb{BOTTOM}"/>
    </linearGradient>
  </defs>
  <rect x="{INSET}" y="{INSET}" width="{SIZE - 2 * INSET}" height="{SIZE - 2 * INSET}" rx="{RADIUS}" fill="url(#g)"/>
  <g transform="translate({tx:g} {ty:g}) scale({SCALE:g})" fill="none" stroke="#2dd4bf">
    <path d="{SHIELD_SVG_PATH}" stroke-width="{STROKE}" stroke-linejoin="round"/>
    <circle cx="16" cy="15" r="{DOT}" fill="#2dd4bf" stroke="none"/>
  </g>
</svg>
"""


def main() -> None:
    icon = draw()
    icon.save(HERE / "offsechub.png")
    icon.save(HERE / "offsechub.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    icon.save(HERE / "offsechub.icns")
    (HERE / "offsechub.svg").write_text(svg())
    for size in LINUX_SIZES:
        icon.resize((size, size), Image.LANCZOS).save(HERE / f"offsechub-{size}.png")
    print("wrote", ", ".join(p.name for p in sorted(HERE.glob("offsechub.*"))))


if __name__ == "__main__":
    main()
