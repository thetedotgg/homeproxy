# /// script
# requires-python = ">=3.11"
# dependencies = ["fonttools[woff]==4.60.1"]
# ///
"""Subset Inter Variable (OFL-1.1) for the HomeProxy website.

Dev-time step; the generated WOFF2 files are committed in website/src/fonts/.
Run: uv run website/scripts/subset-fonts.py <fontsource-inter-files-dir>
The source directory is @fontsource-variable/inter/files (5.3.0).
"""
import sys
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

OUT = Path(__file__).resolve().parent.parent / "src" / "fonts"

# Basic Latin, Latin-1, typographic punctuation and arrows used by the copy.
LATIN = [*range(0x20, 0x7F), *range(0xA0, 0x100), 0x2009, 0x2011, 0x2013, 0x2014,
         0x2018, 0x2019, 0x201A, 0x201C, 0x201D, 0x201E, 0x2022, 0x2026, 0x202F,
         0x2190, 0x2191, 0x2192, 0x2193, 0x2212]
# Czech and Slovak letters outside Latin-1.
CZECH = [0x10C, 0x10D, 0x10E, 0x10F, 0x11A, 0x11B, 0x139, 0x13A, 0x13D, 0x13E, 0x147,
         0x148, 0x154, 0x155, 0x158, 0x159, 0x160, 0x161, 0x164, 0x165, 0x16E, 0x16F,
         0x17D, 0x17E]
FEATURES = ["kern", "liga", "calt", "ccmp", "locl", "mark", "mkmk", "tnum", "case"]


def build(source: Path, unicodes: list[int], target: str) -> None:
    font = TTFont(source, lazy=False)
    font.flavor = None
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = FEATURES
    options.name_IDs = ["*"]
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=unicodes)
    subsetter.subset(font)
    font = instancer.instantiateVariableFont(font, {"wght": (400, 700)})
    path = OUT / target
    font.flavor = "woff2"
    font.save(path)
    print(f"{path.name}: {path.stat().st_size} B")


def main() -> None:
    files = Path(sys.argv[1])
    OUT.mkdir(parents=True, exist_ok=True)
    build(files / "inter-latin-wght-normal.woff2", LATIN, "inter-latin.woff2")
    build(files / "inter-latin-ext-wght-normal.woff2", CZECH, "inter-czech.woff2")


if __name__ == "__main__":
    main()
