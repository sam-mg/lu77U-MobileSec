#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.report_generator.syntax_highlight

Purpose:
    Render code excerpts in reports with syntax highlighting, so a reader can see the vulnerable construct rather than a wall of monospace text.

Responsibilities:
    Map lexer token types to stylesheet classes, pick a lexer from a filename, and highlight a block of lines.

Dependencies:
    Pygments when installed.

Implementation notes:
    Pygments is optional. Without it, lines are HTML-escaped and returned unhighlighted, which is plainer but entirely correct -- highlighting is presentation, and a report must not depend on it. Tokens are mapped to a small set of stylesheet classes rather than inline colours, so the report's own theme controls the appearance and the PDF and HTML renderings agree.

Security considerations:
    The code being highlighted comes from a decompiled untrusted app. Every path escapes its output -- the fallback explicitly, and the Pygments path through its own HTML formatting -- because this text goes straight into a report page.
"""

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
    """
    Purpose:
        Map a lexer token type to a stylesheet class.

    Parameters:
        ttype: The Pygments token type.

    Returns:
        The class name.

    Implementation notes:
        Token types are tested by membership rather than equality, so a subtype such as a documentation comment still maps through its parent. The set of classes is deliberately small: a report needs code to be readable, not to look like an editor.
    """
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
    """
    Purpose:
        Choose a lexer from a filename.

    Parameters:
        filename: The source filename.

    Returns:
        A lexer, or None when one cannot be determined.

    Implementation notes:
        Newline and whitespace stripping are disabled, because the lines being highlighted are numbered and aligned against a reported line number -- losing or adding one would point the reader at the wrong line. An unrecognised filename returns None rather than falling back to a guessed lexer, since highlighting a file as the wrong language is more confusing than not highlighting it.
    """
    if not filename or not PYGMENTS_AVAILABLE:
        return None
    try:
        return get_lexer_for_filename(filename, stripnl=False, stripall=False)
    except ClassNotFound:
        return None
    except Exception:
        return None

def highlight_lines(lines: List[str], filename: str = "") -> List[str]:
    """
    Purpose:
        Highlight a block of source lines for inclusion in a report.

    Parameters:
        lines: The source lines.
        filename: Filename used to select a lexer.

    Returns:
        One HTML-safe string per input line.

    Postconditions:
        The output has exactly as many entries as the input, so line numbering stays aligned on every path.

    Complexity:
        O(n) in the total length of the lines.

    Implementation notes:
        The lines are joined and lexed as one block rather than line by line, because a lexer needs surrounding context -- a multi-line string or comment highlighted per line would be mis-tokenised at every boundary.

    Security considerations:
        Both paths produce escaped output. The unhighlighted fallback escapes explicitly; nothing reaches the report as raw decompiled text.
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
