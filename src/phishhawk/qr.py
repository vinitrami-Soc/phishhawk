"""QR codes in email: quishing moves the link off the desktop, where the
mail gateway and the link checks are, onto a personal phone.

Codes are found where attackers put them:

* image attachments and inline images, including nameless inline parts;
* images embedded in the HTML as data: URIs, which never show up as an
  attachment at all;
* images inside PDF attachments (JPEG, and Flate-compressed pixel data with
  or without PNG predictors);
* codes drawn with HTML table cells or with Unicode block characters
  (█ ▀ ▄), which contain no image for a scanner to look at.

Decoding needs the optional extra: ``pip install 'phishhawk[qr]'``
(zxing-cpp and Pillow). Without it everything else still works and the
QR-code lure wording is still flagged.

Every input is attacker-controlled, so pixel counts, image counts and PDF
decompression are capped, and any decoder error means "no code found".
"""

from __future__ import annotations

import io
import re
import zlib
from collections.abc import Iterator

MAX_PYTHON_PREDICTOR = 1_000_000  # bytes; larger predictor images need the Pillow path
MAX_PIXELS = 25_000_000       # refuse larger images: decompression-bomb guard
MAX_SIDE = 2500               # larger images are scaled down before decoding
MAX_IMAGES_PER_PDF = 30
MAX_PDF_STREAMS = 2000  # stream dictionaries examined per PDF, images or not
PDF_INFLATE_BUDGET = 20 * 1024 * 1024
MAX_GRID_CELLS = 40_000       # 200 x 200 modules is far beyond any QR code
MIN_GRID = 21                 # the smallest QR code is 21 x 21 modules

_BLOCK_BITS = {"█": (1, 1), "▀": (1, 0), "▄": (0, 1),
               "▓": (1, 1), "■": (1, 1)}
_BLOCK_LINE_RE = re.compile(r"^[▀▄█▓■  \t]{10,400}$")


def _libraries():
    try:
        import zxingcpp  # noqa: PLC0415 - optional dependency
        from PIL import Image  # noqa: PLC0415
    except ImportError:
        return None, None
    return zxingcpp, Image


def available() -> bool:
    return _libraries()[0] is not None


def versions() -> dict[str, str]:
    if not available():
        return {}
    from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415
    found = {}
    for name in ("zxing-cpp", "Pillow"):
        try:
            found[name] = version(name)
        except PackageNotFoundError:
            found[name] = "installed"
    return found


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------

def _decode_pil(img) -> list[str]:
    zxingcpp, image = _libraries()
    if zxingcpp is None:
        return []
    try:
        if img.width * img.height > MAX_PIXELS or img.width < 1 or img.height < 1:
            return []
        if img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info):
            # A transparent background would turn black and hide the code.
            rgba = img.convert("RGBA")
            canvas = image.new("RGBA", rgba.size, "white")
            canvas.alpha_composite(rgba)
            img = canvas
        gray = img.convert("L")
        if max(gray.size) > MAX_SIDE:
            gray.thumbnail((MAX_SIDE, MAX_SIDE))
        if min(gray.size) < 120:  # tiny codes decode better enlarged
            factor = max(2, 240 // max(1, min(gray.size)))
            gray = gray.resize((gray.width * factor, gray.height * factor), image.NEAREST)
        low, high = gray.getextrema()
        if high - low < 64 and high > low:  # palette indices read as grey: stretch them
            gray = gray.point(lambda v, lo=low, hi=high: 255 * (v - lo) // (hi - lo))
        found = zxingcpp.read_barcodes(gray, formats=zxingcpp.BarcodeFormat.QRCode)
    except Exception:  # corrupt or hostile image data
        return []
    texts: list[str] = []
    for result in found:
        text = (result.text or "").strip()
        if text and text not in texts:
            texts.append(text)
    return texts


def decode_image(data: bytes) -> list[str]:
    """QR payloads in an image file (PNG, JPEG, GIF, BMP, WebP...)."""
    _, image = _libraries()
    if image is None or not data:
        return []
    try:
        img = image.open(io.BytesIO(data))
        if img.width * img.height > MAX_PIXELS:  # the header is read, the pixels are not
            return []
        img.seek(0)
        return _decode_pil(img)
    except Exception:
        return []


def _grid_image(rows: list[list[int]]):
    """Render a module grid (1 = dark) as an image with a quiet zone."""
    _, image = _libraries()
    width = max(len(row) for row in rows)
    img = image.new("L", (width + 8, len(rows) + 8), 255)
    pixels = img.load()
    for y, row in enumerate(rows):
        for x, dark in enumerate(row):
            if dark:
                pixels[x + 4, y + 4] = 0
    return img.resize((img.width * 8, img.height * 8), image.NEAREST)


def decode_grid(rows: list[list[int]]) -> list[str]:
    """A QR code drawn as a table of dark and light cells."""
    if not available() or len(rows) < MIN_GRID or sum(len(r) for r in rows) > MAX_GRID_CELLS:
        return []
    if min(len(r) for r in rows) < MIN_GRID or not any(any(r) for r in rows):
        return []
    try:
        return _decode_pil(_grid_image(rows))
    except Exception:
        return []


def decode_text_blocks(text: str) -> list[str]:
    """QR codes drawn with block characters ("ASCII QR"): each character is
    one module wide; ▀ and ▄ fill its top or bottom half."""
    if not available() or "█" not in text and "▀" not in text and "▄" not in text:
        return []
    found: list[str] = []
    group: list[str] = []
    for line in text.splitlines() + [""]:
        if _BLOCK_LINE_RE.match(line.rstrip()) and any(ch in _BLOCK_BITS for ch in line):
            group.append(line.rstrip())
            continue
        if len(group) >= 10:
            rows: list[list[int]] = []
            for row in group:
                bits = [_BLOCK_BITS.get(ch, (0, 0)) for ch in row]
                rows.append([top for top, _ in bits])
                rows.append([bottom for _, bottom in bits])
            try:
                for text_found in _decode_pil(_grid_image(rows)):
                    if text_found not in found:
                        found.append(text_found)
            except Exception:
                pass
        group = []
    return found


# ---------------------------------------------------------------------------
# Images inside PDFs
# ---------------------------------------------------------------------------

_STREAM_START_RE = re.compile(rb">>\s*stream\r?\n")
_NAME_RE = re.compile(rb"/([A-Za-z0-9]+)")
_FILTER_RE = re.compile(rb"/Filter\s*(\[[^\]]{0,200}\]|/[^\s/<>\[\]()]{1,40})")


def _dictionary_before(data: bytes, end: int) -> bytes:
    """The << ... >> dictionary that ends at data[end], nested ones included."""
    depth, i, floor = 0, end, max(0, end - 8192)
    while i > floor:
        pair = data[i - 2:i]
        if pair == b">>":
            depth += 1
            i -= 2
        elif pair == b"<<":
            depth -= 1
            i -= 2
            if depth == 0:
                return data[i:end]
        else:
            i -= 1
    return b""


def _int(dictionary: bytes, key: bytes, default: int = 0) -> int:
    match = re.search(rb"/" + key + rb"\s+(\d{1,6})(?!\s+\d+\s+R)", dictionary)
    return int(match.group(1)) if match else default


def _png(compressed: bytes, width: int, height: int, colors: int, bpc: int):
    """A Flate stream with PNG predictors is exactly a PNG's IDAT data, so it
    is wrapped as a PNG and decoded by Pillow in C, not a pixel at a time."""
    import struct  # noqa: PLC0415

    _, image = _libraries()
    color_type = {1: 0, 3: 2, 4: 6}.get(colors)
    if color_type is None or bpc not in (1, 8):
        raise ValueError("unsupported predictor image")

    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, height, bpc, color_type, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", compressed) + chunk(b"IEND", b"")
    img = image.open(io.BytesIO(png))
    img.load()
    return img


def _filters(dictionary: bytes) -> list[bytes]:
    """The names in /Filter only: /FlateDecode, or [/A /B]. Reading on past
    it took /DecodeParms and /Predictor for filters, so ordinary predictor
    images missed the fast path and were decoded a byte at a time (4 s)."""
    match = _FILTER_RE.search(dictionary)
    return _NAME_RE.findall(match.group(1)) if match else []


def _undo_png_predictor(raw: bytes, columns: int, colors: int, bpc: int) -> bytes:
    stride = max(1, (columns * colors * bpc + 7) // 8)
    step = max(1, (colors * bpc + 7) // 8)
    out = bytearray()
    previous = bytearray(stride)
    for start in range(0, len(raw) - stride, stride + 1):
        kind, row = raw[start], bytearray(raw[start + 1:start + 1 + stride])
        for i in range(len(row)):
            left = row[i - step] if i >= step else 0
            up = previous[i]
            if kind == 1:
                row[i] = (row[i] + left) & 0xFF
            elif kind == 2:
                row[i] = (row[i] + up) & 0xFF
            elif kind == 3:
                row[i] = (row[i] + ((left + up) >> 1)) & 0xFF
            elif kind == 4:
                upper_left = previous[i - step] if i >= step else 0
                p = left + up - upper_left
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - upper_left)
                predictor = left if pa <= pb and pa <= pc else up if pb <= pc else upper_left
                row[i] = (row[i] + predictor) & 0xFF
        out += row
        previous = row
    return bytes(out)


def _ccitt_image(stream: bytes, width: int, height: int, dictionary: bytes):
    """CCITT fax data (what scanners and 1-bit PDF writers use), decoded by
    wrapping it in a one-strip TIFF for Pillow's libtiff."""
    import struct  # noqa: PLC0415

    _, image = _libraries()
    k = re.search(rb"/K\s+(-?\d+)", dictionary)
    group4 = k is not None and int(k.group(1)) < 0
    black_is_one = b"/BlackIs1 true" in dictionary
    entries = [(256, 4, width), (257, 4, height), (258, 3, 1), (259, 3, 4 if group4 else 3),
               (262, 3, 0 if black_is_one else 1), (273, 4, 0), (277, 3, 1), (278, 4, height),
               (279, 4, len(stream))]
    if not group4:
        entries.append((292, 4, 0))
    offset = 8 + 2 + 12 * len(entries) + 4
    ifd = struct.pack("<H", len(entries))
    for tag, kind, value in entries:
        value = offset if tag == 273 else value
        ifd += struct.pack("<HHI", tag, kind, 1) + (struct.pack("<HH", value, 0) if kind == 3 else
                                                    struct.pack("<I", value))
    tiff = b"II*\x00" + struct.pack("<I", 8) + ifd + struct.pack("<I", 0) + stream
    img = image.open(io.BytesIO(tiff))
    img.load()
    return img


def _pdf_images(data: bytes) -> Iterator[object]:
    _, image = _libraries()
    budget = PDF_INFLATE_BUDGET
    count = 0
    for examined, match in enumerate(_STREAM_START_RE.finditer(data)):
        if count >= MAX_IMAGES_PER_PDF or budget <= 0 or examined >= MAX_PDF_STREAMS:
            return
        if b"/Image" not in data[max(0, match.start() - 8192):match.start()]:
            continue  # cheap test before walking back through the dictionary
        dictionary = _dictionary_before(data, match.start() + 2)
        if b"/Image" not in dictionary or b"/Subtype" not in dictionary:
            continue
        start = match.end()
        length = _int(dictionary, b"Length")
        end = start + length if length and data[start + length:start + length + 12].lstrip().startswith(
            b"endstream") else data.find(b"endstream", start)
        if end < 0:
            continue
        stream = data[start:end]
        filters = _filters(dictionary)
        width, height = _int(dictionary, b"Width"), _int(dictionary, b"Height")
        if not width or not height or width * height > MAX_PIXELS:
            continue
        count += 1
        try:
            predictor = _int(dictionary, b"Predictor", 1)
            if filters == [b"FlateDecode"] and predictor >= 10:
                bpc = 1 if b"/ImageMask true" in dictionary else _int(dictionary, b"BitsPerComponent", 8)
                columns, colors = _int(dictionary, b"Columns", width), _int(dictionary, b"Colors", 1)
                yield _png(stream, columns, height, colors, bpc)
                continue
            if b"FlateDecode" in filters:
                inflated = zlib.decompressobj().decompress(stream, budget)
                budget -= len(inflated)
                stream = inflated
            if b"DCTDecode" in filters or b"JPXDecode" in filters:
                yield image.open(io.BytesIO(stream))
                continue
            if b"CCITTFaxDecode" in filters:
                yield _ccitt_image(stream, width, height, dictionary)
                continue
            if filters and b"FlateDecode" not in filters:
                continue  # JBIG2, LZW, RunLength: not decoded here
            bpc = 1 if b"/ImageMask true" in dictionary else _int(dictionary, b"BitsPerComponent", 8)
            colors = 1 if bpc == 1 else max(1, len(stream) // (width * height)) if predictor < 10 else \
                _int(dictionary, b"Colors", 1)
            if predictor >= 10:
                if len(stream) > MAX_PYTHON_PREDICTOR:  # a byte at a time in Python: only for small images
                    continue
                stream = _undo_png_predictor(stream, _int(dictionary, b"Columns", width), colors, bpc)
            if bpc == 1:
                yield image.frombytes("1", (width, height), stream[:((width + 7) // 8) * height])
            elif bpc == 8 and colors in (1, 3, 4):
                mode = {1: "L", 3: "RGB", 4: "CMYK"}[colors]
                yield image.frombytes(mode, (width, height), stream[:width * height * colors])
        except Exception:
            continue


def decode_pdf(data: bytes) -> list[str]:
    """QR payloads in the images a PDF carries."""
    if not available() or not data:
        return []
    found: list[str] = []
    for img in _pdf_images(data):
        for text in _decode_pil(img):
            if text not in found:
                found.append(text)
    return found
