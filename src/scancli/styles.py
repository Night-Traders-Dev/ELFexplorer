import os
import sys

STYLE_RESET = "\033[0m"
STYLE_BOLD = "\033[1m"
STYLE_DIM = "\033[2m"
FG_CYAN = "\033[36m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_MAGENTA = "\033[35m"
FG_BLUE = "\033[34m"


def color_enabled(stream=None):
    if os.getenv("NO_COLOR"):
        return False
    target = stream if stream is not None else sys.stdout
    try:
        return target.isatty()
    except Exception:
        return False


def styled(text, *codes):
    if not color_enabled():
        return text
    return "".join(codes) + text + STYLE_RESET


def rule(title, color=FG_CYAN):
    label = styled(f" {title} ", STYLE_BOLD, color)
    line = "-" * 20
    return f"{line}{label}{line}"


def print_key_value(key, value, color=FG_BLUE):
    key_text = styled(f"{key:<18}", STYLE_BOLD, color)
    print(f"{key_text} {value}")

