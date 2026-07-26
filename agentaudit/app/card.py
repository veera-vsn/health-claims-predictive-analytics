"""Render an audit result as a shareable PNG.

This is the distribution mechanic, not decoration: the card is the thing that
gets pasted into a PR, a Slack channel, or a tweet, and every copy carries the
URL. It renders server-side with Pillow so it works headlessly and costs
nothing per scan.

Output is 1200x630 -- the Open Graph size, so link unfurls use it directly.
"""

from __future__ import annotations

import io
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

from .scoring import AuditResult

WIDTH, HEIGHT = 1200, 630
PAD = 64

BG = (11, 15, 20)
PANEL = (17, 23, 30)
GRID = (23, 31, 40)
TEXT = (230, 237, 243)
MUTED = (125, 141, 158)
DIM = (72, 85, 99)
TRACK = (33, 43, 54)

#: score floor -> accent colour, worst last.
ACCENTS: tuple[tuple[int, tuple[int, int, int]], ...] = (
    (90, (63, 185, 80)),
    (80, (126, 231, 135)),
    (70, (210, 153, 34)),
    (60, (240, 136, 62)),
    (0, (248, 81, 73)),
)

FONT_CANDIDATES = {
    "mono": (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ),
    "mono_bold": (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf",
    ),
    "sans": (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ),
    "sans_bold": (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ),
}


@lru_cache(maxsize=64)
def _font(kind: str, size: int) -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES.get(kind, ()):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    # Bitmap fallback keeps the endpoint alive on a box with no fonts at all.
    return ImageFont.load_default()


def accent_for(score: int) -> tuple[int, int, int]:
    for floor, colour in ACCENTS:
        if score >= floor:
            return colour
    return ACCENTS[-1][1]


def _text_width(draw: ImageDraw.ImageDraw, text: str, font) -> float:
    return draw.textlength(text, font=font)


def _wrap(draw: ImageDraw.ImageDraw, text: str, font, max_width: int, max_lines: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if _text_width(draw, candidate, font) <= max_width:
            current = candidate
            continue
        if current:
            lines.append(current)
        current = word
        if len(lines) == max_lines:
            break
    if current and len(lines) < max_lines:
        lines.append(current)

    if len(lines) == max_lines and words:
        # Ellipsise if we ran out of room mid-sentence.
        consumed = len(" ".join(lines).split())
        if consumed < len(words):
            last = lines[-1]
            while last and _text_width(draw, last + " …", font) > max_width:
                last = last.rsplit(" ", 1)[0] if " " in last else last[:-1]
            lines[-1] = last + " …"
    return lines


def _letterspace(draw: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, font, fill, spacing: int = 3) -> None:
    x, y = xy
    for char in text:
        draw.text((x, y), char, font=font, fill=fill)
        x += _text_width(draw, char, font) + spacing


def render_card(result: AuditResult, host: str = "agentaudit.dev") -> bytes:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    accent = accent_for(result.score)

    # --- backdrop ---------------------------------------------------------
    for x in range(0, WIDTH, 40):
        draw.line([(x, 0), (x, HEIGHT)], fill=GRID, width=1)
    for y in range(0, HEIGHT, 40):
        draw.line([(0, y), (WIDTH, y)], fill=GRID, width=1)
    draw.rectangle([(0, 0), (WIDTH, 6)], fill=accent)

    # --- header -----------------------------------------------------------
    _letterspace(draw, (PAD, PAD - 8), "AGENT SECURITY SCORE", _font("mono", 20), MUTED, spacing=4)
    host_font = _font("mono", 20)
    draw.text(
        (WIDTH - PAD - _text_width(draw, host, host_font), PAD - 8),
        host,
        font=host_font,
        fill=DIM,
    )

    # --- score block (left) ----------------------------------------------
    score_font = _font("sans_bold", 168)
    score_text = str(result.score)
    score_y = PAD + 40
    draw.text((PAD, score_y), score_text, font=score_font, fill=accent)
    score_w = _text_width(draw, score_text, score_font)

    out_of_font = _font("sans_bold", 48)
    draw.text((PAD + score_w + 12, score_y + 104), "/100", font=out_of_font, fill=DIM)

    # Grade badge sits under the number.
    badge_y = score_y + 190
    grade_font = _font("mono_bold", 26)
    grade_text = f" {result.grade} · {result.verdict.upper()} "
    grade_w = _text_width(draw, grade_text, grade_font)
    draw.rectangle([(PAD, badge_y), (PAD + grade_w + 16, badge_y + 44)], fill=accent)
    draw.text((PAD + 8, badge_y + 9), grade_text, font=grade_font, fill=BG)

    # Injection headline.
    probe_font = _font("sans", 24)
    n = result.unmitigated_probe_count
    probe_line = (
        "No unmitigated injection classes"
        if n == 0
        else f"{n} unmitigated injection class{'es' if n != 1 else ''}"
    )
    draw.text((PAD, badge_y + 68), probe_line, font=probe_font, fill=MUTED)

    counts = result.severity_counts
    detail = (
        f"{counts.get('critical', 0)} critical · {counts.get('high', 0)} high · {result.tool_count_label}"
    )
    draw.text((PAD, badge_y + 102), detail, font=_font("sans", 22), fill=DIM)

    # --- axis bars (right) ------------------------------------------------
    col_x = 560
    col_w = WIDTH - PAD - col_x
    row_y = PAD + 46
    label_font = _font("mono", 21)
    value_font = _font("mono_bold", 21)

    for axis in result.axes:
        draw.text((col_x, row_y), axis.label, font=label_font, fill=TEXT)
        value = str(axis.score)
        draw.text(
            (col_x + col_w - _text_width(draw, value, value_font), row_y),
            value,
            font=value_font,
            fill=accent_for(axis.score),
        )
        bar_y = row_y + 32
        draw.rounded_rectangle([(col_x, bar_y), (col_x + col_w, bar_y + 10)], radius=5, fill=TRACK)
        filled = int(col_w * axis.score / 100)
        if filled > 0:
            draw.rounded_rectangle(
                [(col_x, bar_y), (col_x + max(filled, 10), bar_y + 10)],
                radius=5,
                fill=accent_for(axis.score),
            )
        row_y += 62

    # --- top risk callout -------------------------------------------------
    box_top = HEIGHT - PAD - 106
    draw.rounded_rectangle([(PAD, box_top), (WIDTH - PAD, box_top + 82)], radius=10, fill=PANEL)
    draw.rectangle([(PAD, box_top + 8), (PAD + 5, box_top + 74)], fill=accent)

    top = result.top_risk
    if top:
        _letterspace(draw, (PAD + 24, box_top + 14), "TOP RISK", _font("mono_bold", 16), accent, spacing=3)
        risk_font = _font("sans", 25)
        lines = _wrap(draw, top.title, risk_font, WIDTH - 2 * PAD - 48, max_lines=2)
        y = box_top + 40
        for line in lines:
            draw.text((PAD + 24, y), line, font=risk_font, fill=TEXT)
            y += 30
    else:
        _letterspace(draw, (PAD + 24, box_top + 14), "NO FINDINGS", _font("mono_bold", 16), accent, spacing=3)
        draw.text(
            (PAD + 24, box_top + 40),
            "Every control this scanner checks for is present.",
            font=_font("sans", 25),
            fill=TEXT,
        )

    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()
