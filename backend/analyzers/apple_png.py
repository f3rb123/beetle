"""
Apple PNG utilities — shared by every iOS surface that renders an image.

EVERY PNG in a shipped iOS bundle is "CgBI-crushed": Xcode rewrites it into an
Apple-private variant that is NOT a standard PNG — the IDAT stream is raw deflate with
no zlib header, the channels are byte-swapped to BGRA, and the alpha is premultiplied.
Pillow refuses it ("broken data stream") and so does every browser, so a CgBI PNG passed
through to the UI renders as a BROKEN IMAGE even though the bytes are "there".

:func:`decode_cgbi_png` reverses exactly what pngcrush did; :func:`renderable_image_bytes`
is the one gate every image path should call before shipping bytes to a report — it passes
standard PNG/JPEG through, converts CgBI, and returns None for anything undecodable so the
caller can pick another candidate instead of emitting a broken image.

Extracted from ios_analyzer (RUN 5) so the app-icon path is not the only consumer:
Property Lists (RUN 12) and any future image-rendering path hit the identical bug.
"""
from __future__ import annotations

import io
import struct
import zlib

# PNG magic + IEND terminator, for carving embedded renditions out of a compiled
# Assets.car asset catalog (Apple BOM/CAR format) without actool.
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_END = b"IEND\xaeB\x60\x82"


def iter_carved_pngs(blob: bytes):
    """Yield each complete embedded PNG byte-stream found in ``blob``."""
    start = blob.find(PNG_SIG)
    while start != -1:
        end = blob.find(PNG_END, start)
        if end == -1:
            break
        png = blob[start:end + len(PNG_END)]
        yield png
        start = blob.find(PNG_SIG, end + len(PNG_END))


def iter_png_chunks(png: bytes):
    """Yield (type, data) for each PNG chunk."""
    off = 8
    while off + 8 <= len(png):
        try:
            length = struct.unpack(">I", png[off:off + 4])[0]
        except struct.error:
            return
        ctype = png[off + 4:off + 8]
        data = png[off + 8:off + 8 + length]
        yield ctype, data
        if ctype == b"IEND":
            return
        off += 12 + length


def is_cgbi_png(png: bytes) -> bool:
    """Apple's 'crushed' PNG: a CgBI chunk precedes IHDR. Xcode rewrites every PNG in a
    shipped bundle this way. It is NOT a standard PNG — the IDAT stream is raw deflate
    with no zlib header, the channels are byte-swapped to BGRA, and alpha is
    premultiplied. Browsers and Pillow both refuse it, which is why an icon extracted
    verbatim from an IPA renders as a broken image."""
    return png[:8] == PNG_SIG and png[12:16] == b"CgBI"


def _unfilter_scanlines(raw: bytes, width: int, height: int, bpp: int) -> bytearray | None:
    """Undo the per-scanline PNG filters (RFC 2083 §6). Returns raw pixel bytes."""
    stride = width * bpp
    out = bytearray(stride * height)
    pos = 0
    for y in range(height):
        if pos >= len(raw):
            return None
        ft = raw[pos]; pos += 1
        line = bytearray(raw[pos:pos + stride]); pos += stride
        if len(line) < stride:
            return None
        prev = out[(y - 1) * stride:y * stride] if y else bytes(stride)
        if ft == 1:      # Sub
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ft == 2:    # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:    # Average
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ft == 4:    # Paeth
            for i in range(stride):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        elif ft != 0:
            return None
        out[y * stride:(y + 1) * stride] = line
    return out


def decode_cgbi_png(png: bytes) -> bytes | None:
    """Convert an Apple CgBI PNG into a standard, browser-renderable PNG.

    Reverses exactly what Xcode's pngcrush does: raw-deflate IDAT (no zlib wrapper),
    BGRA channel order, premultiplied alpha. Returns None if the PNG is not the 8-bit
    RGBA shape Apple emits, so the caller falls through to another candidate rather
    than emitting something unrenderable.
    """
    try:
        from PIL import Image
    except Exception:
        return None
    ihdr = idat = None
    parts = []
    for ctype, data in iter_png_chunks(png):
        if ctype == b"IHDR":
            ihdr = data
        elif ctype == b"IDAT":
            parts.append(data)
    if not ihdr or len(ihdr) < 13 or not parts:
        return None
    idat = b"".join(parts)
    width, height, depth, ctype_n = struct.unpack(">IIBB", ihdr[:10])
    if depth != 8 or ctype_n != 6 or not (0 < width <= 2048 and 0 < height <= 2048):
        return None    # only the 8-bit RGBA form Apple ships
    try:
        # Raw deflate — CgBI strips the zlib header, so negative wbits.
        raw = zlib.decompressobj(-zlib.MAX_WBITS).decompress(idat)
    except zlib.error:
        return None
    pixels = _unfilter_scanlines(raw, width, height, 4)
    if pixels is None:
        return None
    # BGRA premultiplied -> RGBA straight.
    for i in range(0, len(pixels), 4):
        b, g, r, a = pixels[i], pixels[i + 1], pixels[i + 2], pixels[i + 3]
        if a and a != 255:
            r = min(255, (r * 255 + a // 2) // a)
            g = min(255, (g * 255 + a // 2) // a)
            b = min(255, (b * 255 + a // 2) // a)
        pixels[i], pixels[i + 1], pixels[i + 2], pixels[i + 3] = r, g, b, a
    try:
        img = Image.frombytes("RGBA", (width, height), bytes(pixels))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return None


def renderable_image_bytes(raw: bytes) -> bytes | None:
    """The bytes to actually ship to the UI, or None if this candidate is unusable.

    Validates by CONTENT: a standard PNG/JPEG passes through; an Apple CgBI PNG is
    converted; anything else is rejected rather than emitted as a broken image.
    """
    if not raw or len(raw) > 4_000_000:
        return None
    if raw[:3] == b"\xff\xd8\xff":                 # JPEG
        return raw
    if raw[:8] != PNG_SIG:
        return None
    if is_cgbi_png(raw):
        return decode_cgbi_png(raw)
    return raw


def png_dimensions(png: bytes):
    """(width, height) from a PNG's IHDR, or None."""
    i = png.find(b"IHDR")
    if i == -1 or i + 12 > len(png):
        return None
    try:
        w, h = struct.unpack(">II", png[i + 4:i + 12])
        return w, h
    except struct.error:
        return None


def best_icon_png_from_assets_car(blob: bytes) -> bytes | None:
    """Pick the largest SQUARE PNG (an app icon is square) carved from Assets.car,
    preferring a plausible icon size and capping at the emit ceiling."""
    best = None
    best_area = 0
    for png in iter_carved_pngs(blob):
        if len(png) > 4_000_000:
            continue
        dims = png_dimensions(png)
        if not dims:
            continue
        w, h = dims
        # App icons are square; ignore non-square renditions (launch images, etc.).
        if w != h or w < 20 or w > 1024:
            continue
        area = w * h
        if area > best_area:
            best_area = area
            best = png
    return best
