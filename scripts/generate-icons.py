"""Генерация иконок приложения FousBrowser.

Иконка рисуется кодом, а не хранится бинарным исходником: так палитра
меняется одной правкой, а результат воспроизводим в CI.

Стиль: терминальная эстетика — тёмный фон, циановый и зелёный акценты,
прямые углы в интерфейсе. Форма знака — как у браузеров: **круглый** диск
с тонким ободом, внутри два симметричных шеврона (вверх — циан, вниз —
зелёный). Круг выбран осознанно: так выглядят значки браузеров, и в панели
задач иконка читается как «браузер», а не как «служебная утилита».

Запуск из корня репозитория:

    python scripts/generate-icons.py

Скрипт перезаписывает `launcher/src-tauri/icons/*`,
`launcher/static/favicon.png` и значки интерфейса в `launcher/static/`.
Требуется Pillow.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path

from PIL import Image, ImageDraw

# --- палитра: те же токены, что в launcher/src/app.css -------------------

BG = (10, 12, 10, 255)  # --bg: основной тёмный фон
PANEL = (13, 17, 16, 255)  # --bg-panel: чуть светлее, даёт глубину диску
CYAN = (34, 211, 238, 255)  # --accent
GREEN = (52, 211, 153, 255)  # --ok
DIM = (14, 116, 144, 255)  # --accent-soft: обод
FAINT = (22, 78, 87, 255)  # --accent-dim

# Рисуем крупно и уменьшаем: на 16 и 32 пикселях линии остаются чистыми.
SUPERSAMPLE = 2048
MASTER = 1024
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


def draw_master() -> Image.Image:
    """Мастер-изображение: круглый диск со шевронами внутри."""
    size = SUPERSAMPLE
    center = size / 2
    # Небольшой внешний отступ: круг не касается краёв кадра.
    radius = center - size * 0.035
    ring = size * 0.028

    image = Image.new("RGBA", (size, size), TRANSPARENT)
    draw = ImageDraw.Draw(image)

    # 1. Основной диск.
    draw.ellipse(
        [center - radius, center - radius, center + radius, center + radius],
        fill=BG,
    )

    # 2. Внутренний диск чуть светлее: даёт ощущение глубины без градиента.
    inner = radius - ring * 1.6
    draw.ellipse(
        [center - inner, center - inner, center + inner, center + inner],
        fill=PANEL,
    )

    # 3. Обод: циановый контур и приглушённая линия внутри него.
    draw.ellipse(
        [center - radius, center - radius, center + radius, center + radius],
        outline=CYAN,
        width=int(ring),
    )
    rim = radius - ring * 1.15
    draw.ellipse(
        [center - rim, center - rim, center + rim, center + rim],
        outline=FAINT,
        width=int(ring * 0.7),
    )

    # 4. Блик сверху слева и мягкий отблеск снизу справа. Полупрозрачные
    #    мазки наносятся через отдельный слой: иначе PIL заменил бы пиксели
    #    вместе с их прозрачностью.
    gloss = Image.new("RGBA", (size, size), TRANSPARENT)
    gloss_draw = ImageDraw.Draw(gloss)
    gloss_radius = radius - ring * 1.9
    gloss_box = [
        center - gloss_radius,
        center - gloss_radius,
        center + gloss_radius,
        center + gloss_radius,
    ]
    gloss_draw.arc(gloss_box, start=194, end=252, fill=(34, 211, 238, 70), width=int(ring * 0.9))
    gloss_draw.arc(gloss_box, start=26, end=72, fill=(52, 211, 153, 55), width=int(ring * 0.8))
    image = Image.alpha_composite(image, gloss)
    draw = ImageDraw.Draw(image)

    # 5. Шевроны: верхний — циан, нижний — зелёный. Концы скруглены
    #    кружками радиуса полуштиха — так знак выглядит аккуратно и на 16 px.
    stroke = int(size * 0.058)
    half = stroke / 2
    span = 0.225
    top_y, top_apex = 0.432, 0.243
    bottom_y, bottom_apex = 0.568, 0.757

    def chevron(color: tuple[int, int, int, int], y: float, apex: float) -> None:
        left = (center - size * span, size * y)
        middle = (center, size * apex)
        right = (center + size * span, size * y)
        draw.line([left, middle, right], fill=color, width=stroke, joint="curve")
        for point in (left, right, middle):
            draw.ellipse(
                [point[0] - half, point[1] - half, point[0] + half, point[1] + half],
                fill=color,
            )

    chevron(CYAN, top_y, top_apex)
    chevron(GREEN, bottom_y, bottom_apex)

    # 6. Центральная ось: тонкая линия между шевронами, чтобы знак читался
    #    как единая фигура, а не как две случайные галочки.
    axis = Image.new("RGBA", (size, size), TRANSPARENT)
    axis_draw = ImageDraw.Draw(axis)
    axis_draw.line(
        [(center, size * 0.470), (center, size * 0.530)],
        fill=(34, 211, 238, 110),
        width=int(stroke * 0.34),
    )
    image = Image.alpha_composite(image, axis)

    return image.resize((MASTER, MASTER), Image.LANCZOS)


def write_svg(path: Path) -> None:
    """Векторная версия знака для интерфейса.

    Растровая иконка, уменьшенная до 18–20 px, размывается: браузер
    пересчитывает пиксели. SVG строится из тех же чисел, что и мастер, и
    остаётся резким при любом размере и на любом экране с высокой плотностью.
    """
    s = MASTER
    center = s / 2
    radius = center - s * 0.035
    ring = s * 0.028
    inner = radius - ring * 1.6
    rim = radius - ring * 1.15
    gloss = radius - ring * 1.9
    stroke = s * 0.058
    span = s * 0.225

    def point(angle_deg: float, r: float) -> tuple[float, float]:
        angle = math.radians(angle_deg)
        return (center + r * math.cos(angle), center + r * math.sin(angle))

    def arc(start: float, end: float, r: float, color: str, width: float) -> str:
        x1, y1 = point(start, r)
        x2, y2 = point(end, r)
        return (
            f'  <path d="M {x1:.1f} {y1:.1f} A {r:.1f} {r:.1f} 0 0 1 {x2:.1f} {y2:.1f}" '
            f'fill="none" stroke="{color}" stroke-width="{width:.1f}" stroke-linecap="round" />'
        )

    top_y = s * 0.432
    top_apex = s * 0.243
    bottom_y = s * 0.568
    bottom_apex = s * 0.757
    left = center - span
    right = center + span

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {s} {s}" width="{s}" height="{s}" role="img" aria-label="FousBrowser">',
        f'  <circle cx="{center}" cy="{center}" r="{radius:.1f}" fill="#0a0c0a" />',
        f'  <circle cx="{center}" cy="{center}" r="{inner:.1f}" fill="#0d1110" />',
        f'  <circle cx="{center}" cy="{center}" r="{radius:.1f}" fill="none" stroke="#22d3ee" stroke-width="{ring:.1f}" />',
        f'  <circle cx="{center}" cy="{center}" r="{rim:.1f}" fill="none" stroke="#164e57" stroke-width="{ring * 0.7:.1f}" />',
        arc(194, 252, gloss, "#22d3ee", ring * 0.9).replace('stroke="#22d3ee"', 'stroke="#22d3ee" opacity="0.28"'),
        arc(26, 72, gloss, "#34d399", ring * 0.8).replace('stroke="#34d399"', 'stroke="#34d399" opacity="0.22"'),
        (
            f'  <path d="M {left:.1f} {top_y:.1f} L {center} {top_apex:.1f} L {right:.1f} {top_y:.1f}" '
            f'fill="none" stroke="#22d3ee" stroke-width="{stroke:.1f}" stroke-linecap="round" stroke-linejoin="round" />'
        ),
        (
            f'  <path d="M {left:.1f} {bottom_y:.1f} L {center} {bottom_apex:.1f} L {right:.1f} {bottom_y:.1f}" '
            f'fill="none" stroke="#34d399" stroke-width="{stroke:.1f}" stroke-linecap="round" stroke-linejoin="round" />'
        ),
        (
            f'  <line x1="{center}" y1="{s * 0.470:.1f}" x2="{center}" y2="{s * 0.530:.1f}" '
            f'stroke="#22d3ee" stroke-width="{stroke * 0.34:.1f}" opacity="0.45" stroke-linecap="round" />'
        ),
        "</svg>",
        "",
    ]
    path.write_text("\n".join(parts), encoding="utf-8")


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
