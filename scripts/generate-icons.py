"""Генерация иконок приложения FousBrowser.

Иконка рисуется кодом, а не хранится бинарным исходником: так палитра
меняется одной правкой, а результат воспроизводим в CI.

Стиль: терминальная эстетика — тёмный фон, циановый и зелёный акценты,
только прямые углы, без градиентов и скруглений. Форма повторяет
исходный знак лаунчера: два симметричных шеврона.

Запуск из корня репозитория:

    python scripts/generate-icons.py

Скрипт перезаписывает `launcher/src-tauri/icons/*` и
`launcher/static/favicon.png`. Требуется Pillow.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw

# --- палитра: те же токены, что в launcher/src/app.css -------------------

BG = (10, 12, 10, 255)  # --bg
CYAN = (34, 211, 238, 255)  # --accent
GREEN = (52, 211, 153, 255)  # --ok
DIM = (22, 78, 87, 255)  # --accent-dim

# Рисуем крупно и уменьшаем: на 16 и 32 пикселях линии остаются чистыми.
MASTER = 1024

REPO_ROOT = Path(__file__).resolve().parent.parent
ICONS_DIR = REPO_ROOT / "launcher" / "src-tauri" / "icons"
STATIC_DIR = REPO_ROOT / "launcher" / "static"

# Размеры, которых ждёт tauri.conf.json и установщик Windows.
PNG_TARGETS = {
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "icon.png": 512,
}

# Плитки Windows Store (значения из шаблона Tauri).
SQUARE_TARGETS = {
    "Square30x30Logo.png": 30,
    "Square44x44Logo.png": 44,
    "Square71x71Logo.png": 71,
    "Square89x89Logo.png": 89,
    "Square107x107Logo.png": 107,
    "Square142x142Logo.png": 142,
    "Square150x150Logo.png": 150,
    "Square284x284Logo.png": 284,
    "Square310x310Logo.png": 310,
    "StoreLogo.png": 50,
}

ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def draw_master() -> Image.Image:
    """Мастер-изображение 1024×1024."""
    image = Image.new("RGBA", (MASTER, MASTER), BG)
    draw = ImageDraw.Draw(image)

    inset = 64
    draw.rectangle(
        [inset, inset, MASTER - inset, MASTER - inset], outline=DIM, width=16
    )

    stroke = 46
    top = [
        (MASTER * 0.30, MASTER * 0.435),
        (MASTER * 0.50, MASTER * 0.245),
        (MASTER * 0.70, MASTER * 0.435),
    ]
    bottom = [
        (MASTER * 0.30, MASTER * 0.565),
        (MASTER * 0.50, MASTER * 0.755),
        (MASTER * 0.70, MASTER * 0.565),
    ]
    draw.line(top, fill=CYAN, width=stroke, joint="curve")
    draw.line(bottom, fill=GREEN, width=stroke, joint="curve")

    return image


def resize(master: Image.Image, size: int) -> Image.Image:
    return master.resize((size, size), Image.LANCZOS)


def main() -> int:
    if not ICONS_DIR.is_dir():
        print(f"нет каталога иконок: {ICONS_DIR}", file=sys.stderr)
        return 1

    master = draw_master()
    written: list[str] = []

    for name, size in {**PNG_TARGETS, **SQUARE_TARGETS}.items():
        resize(master, size).save(ICONS_DIR / name)
        written.append(name)

    # ICO с несколькими разрешениями — им пользуется Проводник Windows.
    master.save(ICONS_DIR / "icon.ico", sizes=ICO_SIZES)
    written.append("icon.ico")

    # favicon для самого интерфейса (отдаётся SvelteKit из static/).
    resize(master, 64).save(STATIC_DIR / "favicon.png")
    written.append("static/favicon.png")

    # icon.icns (macOS) намеренно не трогаем: Pillow не умеет ICNS.
    # Файл остаётся от шаблона и в сборках Windows/Linux не используется.

    print(f"готово: {len(written)} файлов")
    for name in written:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
