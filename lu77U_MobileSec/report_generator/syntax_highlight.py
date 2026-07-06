"""Line-oriented syntax highlighting for code blocks in reports."""

import html as _html
from typing import List

try:
    from pygments import lex
    from pygments.lexers import get_lexer_for_filename
    from pygments.token import Comment, Keyword, Name, Number, Operator, Punctuation, String
    from pygments.util import ClassNotFound
    PYGMENTS_AVAILABLE = True
except Exception:
    PYGMENTS_AVAILABLE = False

def _token_css_class(ttype) -> str:
    if ttype in Keyword:
        return "tok-kw"
    if ttype in Comment:
        return "tok-cm"
    if ttype in Number:
        return "tok-num"
    if ttype in String:
        return "tok-str"
    if ttype in Name.Function or ttype in Name.Class:
        return "tok-fn"
    if ttype in Name.Builtin or ttype in Name.Decorator or ttype in Name.Attribute:
        return "tok-fn"
    if ttype in Operator or ttype in Punctuation:
        return "tok-op"
    return ""

def _lexer_for(filename: str):
    if not filename or not PYGMENTS_AVAILABLE:
        return None
    try:
        return get_lexer_for_filename(filename, stripnl=False, stripall=False)
    except ClassNotFound:
        return None
    except Exception:
        return None

def highlight_lines(lines: List[str], filename: str = "") -> List[str]:
    """Return one HTML-safe (escaped + colorized) string per input line.

    Falls back to plain HTML-escaped lines if Pygments or a matching lexer
    isn't available, so callers never need a separate no-highlight path.
    """
    if not lines:
        return []

    lexer = _lexer_for(filename)
    if lexer is None:
        return [_html.escape(line) for line in lines]

    code = "\n".join(lines)
    try:
        tokens = list(lex(code, lexer))
    except Exception:
        return [_html.escape(line) for line in lines]

    out_lines: List[str] = []
    current: List[str] = []
    for ttype, value in tokens:
        css_class = _token_css_class(ttype)
        parts = value.split("\n")
        for i, part in enumerate(parts):
            if part:
                escaped = _html.escape(part)
                current.append(f'<span class="{css_class}">{escaped}</span>' if css_class else escaped)
            if i < len(parts) - 1:
                out_lines.append("".join(current))
                current = []
    out_lines.append("".join(current))

    if len(out_lines) == len(lines) + 1 and out_lines[-1] == "":
        out_lines.pop()

    if len(out_lines) != len(lines):
        return [_html.escape(line) for line in lines]

    return out_lines

SYNTAX_CSS = """
        .tok-kw  { color: #8250DF; font-weight: 600; }
        .tok-str { color: #3D9A6E; }
        .tok-cm  { color: #9099A8; font-style: italic; }
        .tok-num { color: #B3671B; }
        .tok-fn  { color: #1B6FB3; }
        .tok-op  { color: #6A7280; }
"""