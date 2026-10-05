"""FousBrowser's vector-first violet/coral orbit and F monogram."""
from pathlib import Path
from PIL import Image, ImageDraw

VIOLET = '#b79aff'
CORAL = '#ff927c'
INK = '#121019'
GLYPH = [(39, 29), (72, 29), (65, 41), (48, 41), (44, 49),
         (61, 49), (54, 61), (39, 61), (32, 75), (20, 75)]

def draw_master():
    scale = 20
    image = Image.new('RGBA', (100 * scale, 100 * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((3*scale, 3*scale, 97*scale, 97*scale), fill=INK)
    draw.arc((8*scale, 8*scale, 92*scale, 92*scale), 115, 310,
             fill=VIOLET, width=5*scale)
    draw.arc((8*scale, 8*scale, 92*scale, 92*scale), 325, 95,
             fill=CORAL, width=5*scale)
    draw.polygon([(x*scale, y*scale) for x, y in GLYPH], fill=VIOLET)
    draw.polygon([(64*scale, 65*scale), (77*scale, 65*scale),
                  (70*scale, 77*scale), (57*scale, 77*scale)], fill=CORAL)
    return image.resize((1024, 1024), Image.Resampling.LANCZOS)

def write_svg(path: Path):
    import math
    def arc(start, end, color):
        x1, y1 = 50 + 42*math.cos(math.radians(start)), 50 + 42*math.sin(math.radians(start))
        x2, y2 = 50 + 42*math.cos(math.radians(end)), 50 + 42*math.sin(math.radians(end))
        large = int((end-start) % 360 > 180)
        return f'<path d="M{x1:.4f},{y1:.4f} A42,42 0 {large} 1 {x2:.4f},{y2:.4f}" fill="none" stroke="{color}" stroke-width="5"/>'
    points = ' '.join(f'{x},{y}' for x, y in GLYPH)
    path.write_text(f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" role="img" aria-label="FousBrowser">
<circle cx="50" cy="50" r="47" fill="{INK}"/>
{arc(115,310,VIOLET)}{arc(325,95,CORAL)}
<polygon points="{points}" fill="{VIOLET}"/>
<polygon points="64,65 77,65 70,77 57,77" fill="{CORAL}"/>
</svg>''', encoding='utf-8')
