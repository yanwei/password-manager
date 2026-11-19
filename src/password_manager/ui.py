"""终端输出工具 —— 零依赖的表格渲染、配色、剪贴板。

刻意不引 rich/textual：一个密码管理器的 CLI 不值得为表格多背一个依赖树，
而且我们要精确控制密文打码的行为，自己画更可控。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

#: 剪贴板自动清空时，子进程回读剪贴板比对的标识
_CLEAR_SNIPPET = """
import hashlib, os, subprocess, sys, time
time.sleep(float(sys.argv[1]))
raw = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout
if hashlib.sha256(raw.encode()).hexdigest() == sys.argv[2]:
    subprocess.run(["pbcopy"], input=b"")
"""


# ── 配色 ─────────────────────────────────────────────────────────────────────


class Style:
    """ANSI 配色。非 TTY 或 NO_COLOR 时自动关闭，保证管道里拿到干净文本。"""

    CODES = {
        "reset": "\x1b[0m",
        "bold": "\x1b[1m",
        "dim": "\x1b[2m",
        "red": "\x1b[31m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "blue": "\x1b[34m",
        "magenta": "\x1b[35m",
        "cyan": "\x1b[36m",
        "gray": "\x1b[90m",
    }

    def __init__(self, enabled: bool | None = None):
        if enabled is None:
            enabled = (
                sys.stdout.isatty()
                and os.environ.get("NO_COLOR") is None
                and os.environ.get("TERM") != "dumb"
            )
        self.enabled = bool(enabled)

    def __call__(self, text: object, *styles: str) -> str:
        text = str(text)
        if not self.enabled or not styles:
            return text
        prefix = "".join(self.CODES.get(s, "") for s in styles)
        return f"{prefix}{text}{self.CODES['reset']}"

    # 语义化快捷方式
    def ok(self, text: object) -> str:
        return self(text, "green")

    def warn(self, text: object) -> str:
        return self(text, "yellow")

    def bad(self, text: object) -> str:
        return self(text, "red")

    def muted(self, text: object) -> str:
        return self(text, "gray")

    def head(self, text: object) -> str:
        return self(text, "bold", "cyan")

    def strong(self, text: object) -> str:
        return self(text, "bold")

    # 直接按色名调用，如 style.cyan("▇")
    def red(self, text: object) -> str:
        return self(text, "red")

    def green(self, text: object) -> str:
        return self(text, "green")

    def yellow(self, text: object) -> str:
        return self(text, "yellow")

    def blue(self, text: object) -> str:
        return self(text, "blue")

    def magenta(self, text: object) -> str:
        return self(text, "magenta")

    def cyan(self, text: object) -> str:
        return self(text, "cyan")

    def bold(self, text: object) -> str:
        return self(text, "bold")

    def dim(self, text: object) -> str:
        return self(text, "dim")


STYLE = Style()


def visible_len(text: str) -> int:
    """按终端显示宽度算长度（中文按 2 列）。"""
    plain = _ANSI_RE.sub("", text)
    width = 0
    for char in plain:
        width += 2 if _is_wide(char) else 1
    return width


def _is_wide(char: str) -> bool:
    code = ord(char)
    return (
        0x1100 <= code <= 0x115F
        or 0x2E80 <= code <= 0xA4CF
        or 0xAC00 <= code <= 0xD7A3
        or 0xF900 <= code <= 0xFAFF
        or 0xFE30 <= code <= 0xFE6F
        or 0xFF00 <= code <= 0xFF60
        or 0xFFE0 <= code <= 0xFFE6
        or 0x1F300 <= code <= 0x1FAFF
    )


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - visible_len(text))


# ── 表格 ─────────────────────────────────────────────────────────────────────


@dataclass
class Column:
    """一列的定义。"""

    header: str
    align: str = "left"  # left | right
    max_width: int = 0  # 0 表示不截断


def render_table(
    columns: list[Column],
    rows: list[list[str]],
    *,
    style: Style | None = None,
) -> str:
    """渲染一张带对齐的表格。单元格内容可含 ANSI 颜色，宽度按可见长度计算。"""
    style = style or STYLE
    grid: list[list[str]] = []
    for row in rows:
        cells = []
        for index, column in enumerate(columns):
            text = str(row[index]) if index < len(row) else ""
            if column.max_width:
                text = truncate(text, column.max_width)
            cells.append(text)
        grid.append(cells)

    widths = []
    for index, column in enumerate(columns):
        width = visible_len(column.header)
        for cells in grid:
            width = max(width, visible_len(cells[index]))
        widths.append(min(width, column.max_width) if column.max_width else width)

    lines: list[str] = []
    header = "  ".join(
        _pad(style.head(column.header), widths[index]) for index, column in enumerate(columns)
    )
    lines.append(header.rstrip())
    lines.append(style.muted("─" * min(visible_len(header), 200)))

    for cells in grid:
        parts = []
        for index, column in enumerate(columns):
            cell = _pad(cells[index], widths[index])
            if column.align == "right":
                padding = " " * max(0, widths[index] - visible_len(cells[index]))
                cell = padding + cells[index]
            parts.append(cell)
        lines.append("  ".join(parts).rstrip())
    return "\n".join(lines)


def truncate(text: str, limit: int) -> str:
    """按显示宽度截断，超出部分用省略号。"""
    if visible_len(text) <= limit:
        return text
    out = ""
    width = 0
    for char in text:
        step = 2 if _is_wide(char) else 1
        if width + step > limit - 1:
            break
        out += char
        width += step
    return out + "…"


# ── 文本块 ───────────────────────────────────────────────────────────────────


def heading(text: str, *, style: Style | None = None) -> str:
    style = style or STYLE
    return f"\n{style.head(text)}"


def kv_block(pairs: list[tuple[str, str]], *, indent: str = "  ", label_width: int = 0) -> str:
    """键值对齐输出。"""
    if not pairs:
        return ""
    width = label_width or max(visible_len(label) for label, _ in pairs)
    lines = []
    for label, value in pairs:
        lines.append(f"{indent}{_pad(label, width)}  {value}")
    return "\n".join(lines)


def bullet(text: str, *, indent: str = "  ") -> str:
    return f"{indent}· {text}"


# ── 密文打码 ─────────────────────────────────────────────────────────────────


def mask_secret(value: str) -> str:
    """密文打码：保留首尾各一个字符，中间用圆点。

    短于 4 位的直接全遮——露出首尾就等于泄露大半。
    """
    if not value:
        return ""
    if len(value) <= 4:
        return "•" * len(value)
    return f"{value[0]}{'•' * min(len(value) - 2, 12)}{value[-1]}"


# ── 剪贴板 ───────────────────────────────────────────────────────────────────


def clipboard_available() -> bool:
    return sys.platform == "darwin" and shutil.which("pbcopy") is not None


def copy_to_clipboard(text: str, *, clear_after: int = 0) -> bool:
    """写入剪贴板；clear_after > 0 时启动一个脱离父进程的子进程定时清空。

    定时器必须脱离父进程——CLI 命令执行完就退出了，父进程内的 Timer 线程
    会一起被带走，剪贴板就永远不会被清空。
    """
    if not clipboard_available():
        return False
    try:
        subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
    except (subprocess.SubprocessError, OSError):
        return False
    if clear_after > 0:
        import hashlib

        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        try:
            subprocess.Popen(
                [sys.executable, "-c", _CLEAR_SNIPPET, str(clear_after), digest],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            pass
    return True


def read_clipboard() -> str:
    if not clipboard_available():
        return ""
    try:
        return subprocess.run(["pbpaste"], capture_output=True, text=True, check=True).stdout
    except (subprocess.SubprocessError, OSError):
        return ""


# ── 密码生成 ─────────────────────────────────────────────────────────────────


AMBIGUOUS = "Il1O0o"


def generate_password(
    length: int = 20,
    *,
    symbols: bool = True,
    digits: bool = True,
    upper: bool = True,
    lower: bool = True,
    avoid_ambiguous: bool = False,
    exclude: str = "",
) -> str:
    """用 `secrets` 生成密码，保证每个启用的字符类至少出现一次。"""
    import secrets

    pools: list[str] = []
    if lower:
        pools.append("abcdefghijklmnopqrstuvwxyz")
    if upper:
        pools.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if digits:
        pools.append("0123456789")
    if symbols:
        pools.append("!#$%&*+-=?@^_~.:;")
    if not pools:
        pools = ["abcdefghijklmnopqrstuvwxyz"]

    if avoid_ambiguous:
        banned = set(AMBIGUOUS)
        pools = ["".join(c for c in pool if c not in banned) or pool for pool in pools]
    if exclude:
        banned = set(exclude)
        pools = ["".join(c for c in pool if c not in banned) or pool for pool in pools]

    length = max(length, len(pools))
    alphabet = "".join(pools)
    while True:
        chars = [secrets.choice(pool) for pool in pools]
        chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        candidate = "".join(chars)
        # 抽出的成品若恰好触发结构性告警（比如全是数字），重抽一次
        from .audit import evaluate

        if evaluate(candidate).score >= 3:
            return candidate
