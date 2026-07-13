"""apple_png — CgBI (Apple-crushed) PNG handling.

Every PNG in a shipped iOS bundle is CgBI: raw-deflate IDAT (no zlib header), BGRA
channel order, premultiplied alpha. It is not a standard PNG, so it must be converted
before it reaches any renderer — otherwise the UI shows a broken image.
"""
import io
import struct
import zlib

from analyzers import apple_png


def _crush(width: int, height: int, rgba: bytes) -> bytes:
    """Build a CgBI PNG the way Xcode's pngcrush does: CgBI chunk, BGRA channel order,
    premultiplied alpha, and a RAW-DEFLATE IDAT with no zlib wrapper."""
    def chunk(ctype: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + ctype + data
                + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))

    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)                       # filter type 0 (None)
        row = rgba[y * width * 4:(y + 1) * width * 4]
        for i in range(0, len(row), 4):
            r, g, b, a = row[i], row[i + 1], row[i + 2], row[i + 3]
            # premultiply, then swap to BGRA — exactly what Apple stores
            pr, pg, pb = (r * a) // 255, (g * a) // 255, (b * a) // 255
            scanlines += bytes((pb, pg, pr, a))

    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)   # raw deflate
    idat = co.compress(bytes(scanlines)) + co.flush()
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (apple_png.PNG_SIG + chunk(b"CgBI", b"\x50\x00\x20\x06")
            + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b""))


def test_cgbi_png_is_detected():
    png = _crush(2, 2, bytes([255, 0, 0, 255] * 4))
    assert apple_png.is_cgbi_png(png)


def test_cgbi_decodes_to_a_standard_png_with_correct_colors():
    # Opaque teal — the real app icon's colour. A missed BGRA swap turns it orange,
    # which still DECODES, so asserting the pixel is what actually proves correctness.
    teal = bytes([0, 179, 179, 255] * 4)
    out = apple_png.decode_cgbi_png(_crush(2, 2, teal))
    assert out and not apple_png.is_cgbi_png(out)
    assert apple_png.png_dimensions(out) == (2, 2)

    from PIL import Image
    img = Image.open(io.BytesIO(out))       # a browser/Pillow must be able to decode it
    img.load()
    assert img.mode == "RGBA"
    assert img.getpixel((0, 0)) == (0, 179, 179, 255)   # R,G,B not swapped


def test_renderable_image_bytes_converts_cgbi_and_passes_standard_png_through():
    cgbi = _crush(2, 2, bytes([10, 20, 30, 255] * 4))
    converted = apple_png.renderable_image_bytes(cgbi)
    assert converted and not apple_png.is_cgbi_png(converted)

    # A standard PNG is returned untouched.
    assert apple_png.renderable_image_bytes(converted) == converted


def test_renderable_image_bytes_rejects_junk_instead_of_emitting_a_broken_image():
    assert apple_png.renderable_image_bytes(b"") is None
    assert apple_png.renderable_image_bytes(b"not an image at all") is None
    # Truncated/corrupt CgBI: must return None so the caller tries another candidate.
    broken = _crush(2, 2, bytes([1, 2, 3, 255] * 4))[:40]
    assert apple_png.renderable_image_bytes(broken) is None
