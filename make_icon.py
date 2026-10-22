#!/usr/bin/env python3
"""make_icon.py - draw the app icon and write every format we need.

Design: a certificate page with a key bit, on a dark rounded square.  Pure
Pillow, no external assets.  Outputs:

  assets/icon.png        512x512 master
  assets/icon.ico        multi-size Windows icon (16..256)
  assets/icon_16.png     tray/taskbar previews
  assets/icon_32.png
  assets/icon_48.png
  assets/icon_256.png
"""

from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

HERE = pathlib.Path(__file__).resolve().parent
ASSETS = HERE / "assets"

# palette
BG_TOP = (18, 26, 38)
BG_BOT = (10, 15, 24)
PAGE = (247, 250, 253)
PAGE_EDGE = (200, 212, 226)
ACCENT = (58, 190, 140)
ACCENT_DARK = (32, 140, 102)
RIBBON = (232, 88, 96)
KEY = (255, 198, 66)
LINE = (176, 192, 210)


def rounded(draw: ImageDraw.ImageDraw, box, radius, fill) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def draw_small_icon(size: int) -> Image.Image:
    """Simplified mark for 16/24/32 px.

    The detailed 512 design turns to mush when shrunk: at 16 px a page with
    five lines and a ribbon is four grey pixels.  Small sizes get their own
    drawing - a white page with one accent bar and a single accent dot in the
    corner - so the silhouette still reads in a taskbar.
    """
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # rounded dark plate
    d.rounded_rectangle(
        [0, 0, s - 1, s - 1], radius=max(2, round(s * 0.22)), fill=BG_TOP
    )

    # page block, offset up-right to leave room for the dot
    inset = max(2, round(s * 0.14))
    pw = s - inset * 2 - max(1, round(s * 0.10))
    ph = s - inset * 2 - max(1, round(s * 0.10))
    px, py = inset, inset
    d.rounded_rectangle(
        [px, py, px + pw, py + ph], radius=max(1, round(s * 0.06)), fill=PAGE
    )

    # one accent bar + one grey bar; at 16 px two bars is the max that reads
    bar_h = max(1, round(s * 0.13))
    x0 = px + max(1, round(pw * 0.20))
    x1 = px + pw - max(1, round(pw * 0.20))
    y = py + max(1, round(ph * 0.28))
    d.rectangle([x0, y, x1, y + bar_h - 1], fill=ACCENT_DARK)
    if s >= 24:
        y2 = y + bar_h + max(1, round(ph * 0.16))
        d.rectangle(
            [x0, y2, x0 + max(1, round((x1 - x0) * 0.60)), y2 + bar_h - 1],
            fill=LINE,
        )

    # accent dot, bottom-left corner of the plate
    dr = max(3, round(s * 0.17))
    dcx = max(dr, round(s * 0.23))
    dcy = s - max(dr, round(s * 0.23))
    d.ellipse([dcx - dr, dcy - dr, dcx + dr, dcy + dr], fill=ACCENT)
    # punch a hole at every size so it reads as a key ring, not a blob
    hr = max(1, round(dr * 0.36))
    d.ellipse([dcx - hr, dcy - hr, dcx + hr, dcy + hr], fill=BG_TOP)
    return img


def draw_icon(size: int = 512) -> Image.Image:
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # background: vertical gradient inside a rounded square
    bg = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    bd = ImageDraw.Draw(bg)
    for y in range(s):
        t = y / max(1, s - 1)
        r = int(BG_TOP[0] + (BG_BOT[0] - BG_TOP[0]) * t)
        g = int(BG_TOP[1] + (BG_BOT[1] - BG_TOP[1]) * t)
        b = int(BG_TOP[2] + (BG_BOT[2] - BG_TOP[2]) * t)
        bd.line([(0, y), (s, y)], fill=(r, g, b, 255))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, s - 1, s - 1], radius=int(s * 0.22), fill=255
    )
    img.paste(bg, (0, 0), mask)

    # subtle accent glow at the bottom-left
    glow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse(
        [-int(s * 0.25), int(s * 0.55), int(s * 0.55), int(s * 1.25)],
        fill=(ACCENT[0], ACCENT[1], ACCENT[2], 46),
    )
    img = Image.alpha_composite(img, glow)
    d = ImageDraw.Draw(img)

    # ---- certificate page ------------------------------------------------
    pw, ph = int(s * 0.56), int(s * 0.66)
    px = (s - pw) // 2
    py = int(s * 0.17)
    # page shadow
    d.rounded_rectangle(
        [px + int(s * 0.018), py + int(s * 0.018), px + pw + int(s * 0.018),
         py + ph + int(s * 0.018)],
        radius=int(s * 0.05),
        fill=(0, 0, 0, 90),
    )
    d.rounded_rectangle(
        [px, py, px + pw, py + ph], radius=int(s * 0.05), fill=PAGE,
        outline=PAGE_EDGE, width=max(1, int(s * 0.008)),
    )

    # text lines on the page
    lx0 = px + int(pw * 0.12)
    lx1 = px + int(pw * 0.88)
    ly = py + int(ph * 0.16)
    widths = (0.76, 0.62, 0.82, 0.52)
    for i, w in enumerate(widths):
        yy = ly + i * int(ph * 0.135)
        d.rounded_rectangle(
            [lx0, yy, lx0 + int((lx1 - lx0) * w), yy + int(s * 0.026)],
            radius=int(s * 0.013),
            fill=LINE if i else ACCENT_DARK,
        )

    # seal / ribbon
    cx = px + int(pw * 0.72)
    cy = py + int(ph * 0.80)
    r = int(s * 0.085)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=RIBBON)
    d.ellipse(
        [cx - int(r * 0.52), cy - int(r * 0.52), cx + int(r * 0.52), cy + int(r * 0.52)],
        fill=PAGE,
    )
    # ribbon tails
    d.polygon(
        [
            (cx - int(r * 0.55), cy + int(r * 0.55)),
            (cx - int(r * 0.18), cy + int(r * 0.95)),
            (cx - int(r * 0.55), cy + int(r * 1.55)),
            (cx - int(r * 1.02), cy + int(r * 1.25)),
        ],
        fill=RIBBON,
    )
    d.polygon(
        [
            (cx + int(r * 0.55), cy + int(r * 0.55)),
            (cx + int(r * 0.18), cy + int(r * 0.95)),
            (cx + int(r * 0.55), cy + int(r * 1.55)),
            (cx + int(r * 1.02), cy + int(r * 1.25)),
        ],
        fill=RIBBON,
    )

    # ---- key badge, bottom-left -----------------------------------------
    kx = int(s * 0.20)
    ky = int(s * 0.72)
    kr = int(s * 0.105)
    # badge disc
    d.ellipse(
        [kx - kr - int(s * 0.018), ky - kr - int(s * 0.018),
         kx + kr + int(s * 0.018), ky + kr + int(s * 0.018)],
        fill=ACCENT,
    )
    # key ring
    ring_r = int(kr * 0.52)
    ring_w = max(2, int(s * 0.020))
    d.ellipse(
        [kx - ring_r, ky - ring_r, kx + ring_r, ky + ring_r],
        outline=PAGE, width=ring_w,
    )
    # key shaft going down-right
    sx0, sy0 = kx + int(ring_r * 0.55), ky + int(ring_r * 0.55)
    sx1, sy1 = kx + int(kr * 1.30), ky + int(kr * 1.30)
    d.line([(sx0, sy0), (sx1, sy1)], fill=PAGE, width=ring_w)
    # key teeth
    t = int(s * 0.030)
    d.line([(sx1, sy1), (sx1 - t, sy1 + t)], fill=PAGE, width=ring_w)
    d.line(
        [(sx1 - int(t * 0.35), sy1 - int(t * 0.35)),
         (sx1 - int(t * 1.35), sy1 + int(t * 0.65))],
        fill=PAGE, width=ring_w,
    )

    return img


def icon_for(size: int) -> Image.Image:
    """Pick the right drawing for a size, then hand back an RGBA image."""
    if size <= 32:
        return draw_small_icon(size)
    return draw_icon(size)


def main() -> int:
    ASSETS.mkdir(exist_ok=True)
    master = draw_icon(512)
    master.save(ASSETS / "icon.png")
    print(f"wrote {ASSETS / 'icon.png'} ({master.width}x{master.height})")

    sizes = (16, 24, 32, 48, 64, 128, 256)
    frames: dict[int, Image.Image] = {}
    for size in sizes:
        img = icon_for(size)
        img.save(ASSETS / f"icon_{size}.png")
        frames[size] = img
        print(f"wrote {ASSETS / f'icon_{size}.png'}")

    # Windows picks the closest size from the .ico.  Hand it per-size
    # drawings, not one bitmap downscaled seven times, so 16 and 24 px stay
    # legible in the taskbar and the window title bar.
    ico_path = ASSETS / "icon.ico"
    base = frames[256].convert("RGBA")
    base.save(ico_path, sizes=[(256, 256), (128, 128), (64, 64), (48, 48)])
    # Pillow cannot append custom frames to an .ico, so rebuild it by hand
    _write_ico(ico_path, [frames[s] for s in sizes])
    print(f"wrote {ico_path} sizes={list(sizes)}")

    # a small preview sheet so the icon can be eyeballed at every size
    sheet = Image.new("RGBA", (760, 200), (250, 251, 253, 255))
    x = 12
    for size in (16, 24, 32, 48, 64, 128):
        img = frames[size]
        sheet.paste(img, (x, 24), img)
        x += size + 26
    sheet.save(ASSETS / "icon_preview.png")
    print(f"wrote {ASSETS / 'icon_preview.png'}")
    return 0


def _write_ico(path: pathlib.Path, images: list[Image.Image]) -> None:
    """Write a multi-image .ico with one independent bitmap per size."""
    import struct

    images = sorted(images, key=lambda im: im.width)
    header = struct.pack("<HHH", 0, 1, len(images))
    entries = b""
    payload = b""
    offset = 6 + 16 * len(images)
    for im in images:
        im = im.convert("RGBA")
        w, h = im.size
        # ICO stores BGRA, bottom-up
        raw = im.tobytes("raw", "BGRA")
        rows = [raw[y * w * 4:(y + 1) * w * 4] for y in range(h)]
        flipped = b"".join(reversed(rows))
        mask_row = ((w + 31) // 32) * 4
        mask = b"\x00" * (mask_row * h)
        bitmap = (
            struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, len(flipped) + len(mask), 0, 0, 0, 0)
            + flipped
            + mask
        )
        dim = 0 if w >= 256 else w
        entries += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(bitmap), offset
        )
        payload += bitmap
        offset += len(bitmap)
    path.write_bytes(header + entries + payload)


if __name__ == "__main__":
    raise SystemExit(main())

