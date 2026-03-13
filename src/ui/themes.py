from __future__ import annotations

from textual.theme import Theme


ELFEXPLORER_THEMES = (
    Theme(
        name="elfexplorer-cinder",
        primary="#ff8a3d",
        secondary="#ffb566",
        warning="#ffd166",
        error="#ff5d5d",
        success="#7bd389",
        accent="#f4a261",
        foreground="#f7f3ea",
        background="#171311",
        surface="#221b18",
        panel="#2c2320",
        boost="#3a2d29",
        dark=True,
    ),
    Theme(
        name="elfexplorer-oceanic",
        primary="#3fbac2",
        secondary="#7be0d6",
        warning="#ffd166",
        error="#ff6b6b",
        success="#80ed99",
        accent="#64dfdf",
        foreground="#edf6f9",
        background="#08141b",
        surface="#0f222c",
        panel="#14303d",
        boost="#1c4252",
        dark=True,
    ),
    Theme(
        name="elfexplorer-forge",
        primary="#d4a373",
        secondary="#e9c46a",
        warning="#f4d35e",
        error="#e76f51",
        success="#7bd389",
        accent="#f2cc8f",
        foreground="#f8f5f0",
        background="#15120f",
        surface="#211b17",
        panel="#2c241f",
        boost="#3a3028",
        dark=True,
    ),
    Theme(
        name="elfexplorer-verdant",
        primary="#52b788",
        secondary="#95d5b2",
        warning="#ffe066",
        error="#ef476f",
        success="#80ed99",
        accent="#74c69d",
        foreground="#edfdf6",
        background="#071510",
        surface="#0e2119",
        panel="#143026",
        boost="#1c4133",
        dark=True,
    ),
)


def register_elfexplorer_themes(app) -> None:
    for theme in ELFEXPLORER_THEMES:
        if theme.name not in app.available_themes:
            app.register_theme(theme)
