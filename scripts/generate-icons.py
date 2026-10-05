"""Генерация иконок приложения FousBrowser.

Иконка рисуется кодом, а не хранится бинарным исходником: так палитра
меняется одной правкой, а результат воспроизводим в CI.

Знак: фиолетовая монограмма F, коралловая орбита, тёмный диск.
Геометрия SVG и растра хранится в brand.py.

Запуск из корня репозитория:

    python scripts/generate-icons.py

Скрипт перезаписывает `launcher/src-tauri/icons/*`,
`launcher/static/favicon.png` и значки интерфейса в `launcher/static/`.
Требуется Pillow.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

TRANSPARENT = (0, 0, 0, 0)

REPO_ROOT = Path(__file__).resolve().parent.parent
ICONS_DIR = REPO_ROOT / "launcher" / "src-tauri" / "icons"
STATIC_DIR = REPO_ROOT / "launcher" / "static"
START_DIR = REPO_ROOT / "launcher" / "src-tauri" / "resources" / "start"

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

# Значки самого интерфейса: шапка лаунчера и favicon страницы.
UI_TARGETS = {
    "fousbrowser-32.png": 32,
    "fousbrowser-128.png": 128,
    "favicon.png": 64,
}


from brand import draw_master, write_svg


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

    # Значки интерфейса отдаются SvelteKit из static/.
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    for name, size in UI_TARGETS.items():
        resize(master, size).save(STATIC_DIR / name)
        written.append(f"static/{name}")

    # Резкий знак для интерфейса: растр в шапке размывался при уменьшении.
    write_svg(STATIC_DIR / "fousbrowser.svg")
    written.append("static/fousbrowser.svg")

    # Тот же знак нужен стартовой странице профиля: она лежит в ресурсах
    # приложения, и её содержимое встраивается в исполняемый файл.
    START_DIR.mkdir(parents=True, exist_ok=True)
    write_svg(START_DIR / "logo.svg")
    written.append("src-tauri/resources/start/logo.svg")

    # icon.icns (macOS) не создаётся: сборки для macOS не выпускаются,
    # а Pillow не умеет ICNS. Файл шаблона удалён, чтобы в репозитории
    # не оставалось чужих значков.

    print(f"готово: {len(written)} файлов")
    for name in written:
        print(f"  {name}")

    # Проверка читаемости: на 16 px знак не должен превращаться в пятно.
    small = resize(master, 16)
    colors = {
        color
        for _count, color in small.getcolors(maxcolors=4096) or []
        if color[3] > 200
    }
    print(f"проверка: непрозрачных цветов на 16 px — {len(colors)}")
    if len(colors) < 3:
        print("предупреждение: значок на 16 px выглядит однородным", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
