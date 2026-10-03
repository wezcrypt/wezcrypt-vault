"""Render the application icon (assets/icon.png + assets/icon.ico) with Qt.

Run: python tools/make_icon.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QRectF, Qt  # noqa: E402
from PySide6.QtGui import QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPainterPath, QPen  # noqa: E402

ASSETS = Path(__file__).resolve().parents[1] / "assets"


def render(size: int) -> QImage:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 256
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0, QColor("#1f6feb"))
    grad.setColorAt(1, QColor("#0b2a5b"))
    p.setBrush(grad)
    p.setPen(Qt.NoPen)
    p.drawRoundedRect(QRectF(8 * s, 8 * s, 240 * s, 240 * s), 52 * s, 52 * s)
    # shackle
    pen = QPen(QColor("#e8f0ff"), 22 * s, Qt.SolidLine, Qt.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    shackle = QPainterPath()
    shackle.moveTo(86 * s, 118 * s)
    shackle.lineTo(86 * s, 92 * s)
    shackle.arcTo(QRectF(86 * s, 50 * s, 84 * s, 84 * s), 180, -180)
    shackle.lineTo(170 * s, 118 * s)
    p.drawPath(shackle)
    # body
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#e8f0ff"))
    p.drawRoundedRect(QRectF(62 * s, 112 * s, 132 * s, 100 * s), 18 * s, 18 * s)
    # keyhole
    p.setBrush(QColor("#0b2a5b"))
    p.drawEllipse(QRectF(115 * s, 138 * s, 26 * s, 26 * s))
    p.drawRoundedRect(QRectF(122 * s, 156 * s, 12 * s, 34 * s), 4 * s, 4 * s)
    p.end()
    return img


def main() -> int:
    _keepalive = [QGuiApplication.instance() or QGuiApplication(sys.argv)]  # Qt app must exist before QPainter
    assert _keepalive
    ASSETS.mkdir(exist_ok=True)
    if not render(256).save(str(ASSETS / "icon.png"), "PNG"):
        print("failed to write icon.png", file=sys.stderr)
        return 1
    if not render(256).save(str(ASSETS / "icon.ico"), "ICO"):
        print("failed to write icon.ico", file=sys.stderr)
        return 1
    print(f"wrote {ASSETS / 'icon.png'} and {ASSETS / 'icon.ico'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
