#!/usr/bin/env python3
"""
Module: check_comment_style

Purpose:
    Enforce the project's commenting standard mechanically, so that the rules in CONTRIBUTING.md are checked by a program rather than by review attention.

Responsibilities:
    Walk the target paths, apply every rule to every module, class and function, and report each violation with a file, a symbol and a reason.

Dependencies:
    Standard library only, so the checker runs in a bare environment and in a git hook before any project dependency is installed.

Usage:
    python scripts/check_comment_style.py
    python scripts/check_comment_style.py lu77U_MobileSec scripts
    python scripts/check_comment_style.py --json

Examples:
    A clean run prints a one-line summary and exits 0. A failing run prints one line per violation, grouped by file, and exits 1.

Implementation notes:
    The checker is self-hosting: it satisfies its own rules, and a test asserts that. A checker that cannot pass its own standard is not a standard anyone should be asked to follow. Parsing is done with ast and tokenize rather than regular expressions over raw text, so a rule cannot be fooled by a docstring, a string literal or a comment-looking fragment inside code.

Security considerations:
    Files are parsed, never imported or executed, so running this over an untrusted checkout cannot run that checkout's code.
"""

import argparse
import ast
import io
import json
import re
import sys
import tokenize
from pathlib import Path

SHEBANG = "#!/usr/bin/env python3"
SINGLE_TRIPLE = "'" * 3

DEFAULT_TARGETS = ("lu77U_MobileSec", "scripts", "tests")

VENDORED_DIRS = ("__pycache__", "node_modules", "static", "dist", "build", ".venv",
                 ".git", ".pytest_cache", "demo-dist", "brag-output",
                 "lu77U_MobileSec.egg-info")

ALLOWED_SECTIONS = frozenset({
    "Module", "Purpose", "Responsibilities", "Dependencies",
    "Attributes", "Invariants", "Thread-safety",
    "Parameters", "Returns", "Raises", "Preconditions", "Postconditions",
    "Complexity", "Side effects", "Security considerations",
    "Usage", "Examples", "Compatibility", "Deprecation",
    "Implementation notes", "Known limitations",
})

ENTRY_SECTIONS = frozenset({"Parameters", "Raises", "Attributes"})

LITERAL_SECTIONS = frozenset({"Usage", "Examples"})

HEADING_PATTERN = r"^([A-Z][A-Za-z/ -]*):\s*$"
LEAD_PATTERN = r"^(Module|Purpose|Returns):\s+\S"
ENTRY_PATTERN = (r"^(\*{0,2}[A-Za-z_][A-Za-z0-9_.]*"
                 r"(?:\s*,\s*\*{0,2}[A-Za-z_][A-Za-z0-9_.]*)*|\.\.\.)\s*:\s")
SECRET_PATTERN = (r"(?i)\b(?:api[-_]?key|secret|password|token)\b"
                  r"\s*[:=]\s*[\"']?[A-Za-z0-9/+_-]{12,}")

HEADING_RE = re.compile(HEADING_PATTERN)
LEAD_RE = re.compile(LEAD_PATTERN)
ENTRY_RE = re.compile(ENTRY_PATTERN)
SECRET_RE = re.compile(SECRET_PATTERN)


class Violation:
    """
    Purpose:
        One rule failure, carrying enough context for a contributor to find and fix it without rerunning the checker.

    Attributes:
        path: The file the failure is in, relative to the working directory.
        symbol: The module, class or function the failure belongs to.
        rule: Short identifier for the rule that failed.
        detail: Human-readable explanation of what is wrong.

    Thread-safety:
        Immutable in practice; instances are created and never mutated.
    """

    __slots__ = ("path", "symbol", "rule", "detail")

    def __init__(self, path, symbol, rule, detail):
        """
        Purpose:
            Record one rule failure.

        Parameters:
            path: The file the failure is in.
            symbol: The module, class or function the failure belongs to.
            rule: Short identifier for the rule that failed.
            detail: Human-readable explanation.
        """
        self.path = str(path)
        self.symbol = symbol
        self.rule = rule
        self.detail = detail

    def as_dict(self):
        """
        Purpose:
            Render the violation as plain data, for the machine-readable output mode.

        Returns:
            A dict of the four fields.
        """
        return {"path": self.path, "symbol": self.symbol,
                "rule": self.rule, "detail": self.detail}

    def __str__(self):
        """
        Purpose:
            Render the violation as the single line printed in the default output mode.

        Returns:
            The formatted line.
        """
        return "%s: %s [%s] %s" % (self.path, self.symbol, self.rule, self.detail)


def iter_python_files(targets):
    """
    Purpose:
        Collect the Python files to check, skipping vendored and generated trees.

    Parameters:
        targets: Files or directories to search.

    Returns:
        The matching paths, sorted so output order is stable between runs.

    Implementation notes:
        Vendored directories are skipped by name rather than by ignore file, so the checker behaves identically whether or not the working tree is clean.
    """
    found = set()
    for target in targets:
        path = Path(target)
        if path.is_file() and path.suffix == ".py":
            found.add(path)
            continue
        for candidate in path.rglob("*.py"):
            if any(part in VENDORED_DIRS for part in candidate.parts):
                continue
            found.add(candidate)
    return sorted(found)


def expected_module_name(path):
    """
    Purpose:
        Work out the dotted name a file's Module line should declare.

    Parameters:
        path: The file.

    Returns:
        The expected dotted module name.

    Implementation notes:
        Derived by walking up while each parent is a package, which gives the real importable name rather than a guess from the path. A file outside any package is named by its stem alone. A package initialiser is named for its package rather than carrying a trailing initialiser segment, since that is how the module is actually imported.
    """
    path = path.resolve()
    parts = [path.stem]
    parent = path.parent
    while (parent / "__init__.py").is_file():
        parts.append(parent.name)
        parent = parent.parent
    parts.reverse()
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or path.stem


def docstring_expr(node):
    """
    Purpose:
        Return the docstring expression of a node, if it has one.

    Parameters:
        node: A module, class or function node.

    Returns:
        A pair of the docstring text and its expression node, or a pair of Nones.
    """
    body = getattr(node, "body", None)
    if not body:
        return None, None
    first = body[0]
    if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)):
        return first.value.value, first
    return None, None


def stacked_docstring(node):
    """
    Purpose:
        Report whether a second bare string literal sits directly under a node's docstring.

    Parameters:
        node: A module, class or function node whose first statement is its docstring.

    Returns:
        True when the statement after the docstring is another bare string.

    Implementation notes:
        Only the first string counts as the docstring, so a second one is an expression evaluated and discarded, which is what a docstring inserted over an existing one leaves behind. It renders as a duplicated comment block and nothing else reports it, since every rule here reads only the first statement.
    """
    body = getattr(node, "body", None) or []
    if len(body) < 2:
        return False
    second = body[1]
    return (isinstance(second, ast.Expr) and isinstance(second.value, ast.Constant)
            and isinstance(second.value.value, str))


def dedent_doc(doc):
    """
    Purpose:
        Remove the common leading indent from a docstring, so the same section rules apply to a module docstring and to one nested inside a class or function.

    Parameters:
        doc: The docstring text.

    Returns:
        The docstring with its base indent removed and its relative structure intact.

    Implementation notes:
        Without this, a heading inside a function docstring sits at a deeper indent than the same heading in a module docstring, and a rule written for one silently stops firing for the other.
    """
    lines = doc.split("\n")
    indents = [len(ln) - len(ln.lstrip()) for ln in lines if ln.strip()]
    base = min(indents) if indents else 0
    return "\n".join(ln[base:] if len(ln) >= base else ln.lstrip() for ln in lines)


def parse_sections(doc):
    """
    Purpose:
        Split a docstring into its sections.

    Parameters:
        doc: The docstring text.

    Returns:
        A pair of the section bodies keyed by heading, and the headings in the order they appeared.

    Implementation notes:
        The order is returned alongside the mapping so that a repeated heading can be detected, which the mapping alone would hide.
    """
    bodies = {}
    order = []
    current = None
    for raw in dedent_doc(doc).split("\n"):
        stripped = raw.strip()
        if not stripped:
            continue
        heading = HEADING_RE.match(stripped)
        if heading:
            current = heading.group(1)
            order.append(current)
            bodies.setdefault(current, [])
            continue
        lead = LEAD_RE.match(stripped)
        if lead and raw == raw.lstrip():
            current = lead.group(1)
            order.append(current)
            bodies.setdefault(current, []).append(stripped.split(":", 1)[1].strip())
            continue
        if current is not None:
            bodies[current].append(raw)
    return bodies, order


def own_nodes(function):
    """
    Purpose:
        Yield the nodes belonging to a function itself, excluding anything nested inside it.

    Parameters:
        function: The function node.

    Returns:
        The nodes that are part of this function's own body.

    Implementation notes:
        A plain walk would let a nested helper's return statement count as the enclosing function's, which would demand a Returns section on a function that returns nothing.
    """
    stack = list(ast.iter_child_nodes(function))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.Lambda, ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def declared_parameters(function, is_method):
    """
    Purpose:
        List the parameters a function's docstring is expected to document.

    Parameters:
        function: The function node.
        is_method: Whether the function is defined directly inside a class body.

    Returns:
        The parameter names, excluding the implicit instance or class argument.

    Implementation notes:
        The receiver is dropped only from a method, only from its leading positional argument, and only when that argument is named self or cls. Dropping every argument with one of those names would exempt a real parameter that happens to be called cls, which parametrized tests over analyzer classes do have; dropping it from a plain function would exempt the first argument of a helper that builds a class descriptor. A static method takes no receiver at all, so its leading argument is a real parameter whatever it is called.
    """
    args = function.args
    positional = [*args.posonlyargs, *args.args]
    names = [a.arg for a in (*positional, *args.kwonlyargs)]
    if args.vararg:
        names.append(args.vararg.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    if (is_method and not is_static_method(function)
            and positional and positional[0].arg in ("self", "cls")):
        names = names[1:]
    return names


def is_static_method(function):
    """
    Purpose:
        Report whether a function carries the decorator that removes its receiver.

    Parameters:
        function: The function node.

    Returns:
        True when the decorator is present.

    Implementation notes:
        Matched by name rather than by resolving the decorator, because the checker never imports the code it reads, and the decorator is a builtin that nothing in this project shadows.
    """
    for decorator in function.decorator_list:
        name = getattr(decorator, "id", None) or getattr(decorator, "attr", None)
        if name == "staticmethod":
            return True
    return False


def produces_value(function):
    """
    Purpose:
        Decide whether a function hands a value back to its caller.

    Parameters:
        function: The function node.

    Returns:
        True when the function returns a value or yields.

    Implementation notes:
        A bare return and a return of None are both treated as returning nothing, since neither gives the caller a value to document.
    """
    for node in own_nodes(function):
        if isinstance(node, ast.Return) and node.value is not None:
            constant_none = (isinstance(node.value, ast.Constant)
                             and node.value.value is None)
            if not constant_none:
                return True
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
    return False


def has_wrapped_prose(doc):
    """
    Purpose:
        Detect prose that has been hard-wrapped across several lines.

    Parameters:
        doc: The docstring text.

    Returns:
        True when a paragraph spans more than one line.

    Implementation notes:
        Consecutive non-blank lines at the same indent are a wrap, except in the sections that list one entry per line, where they are the expected shape. Usage and Examples are skipped entirely, because they hold literal commands and sample output, which must keep their own line breaks to stay runnable.
    """
    previous_indent = None
    previous_was_entry = False
    section = None
    for raw in dedent_doc(doc).split("\n"):
        stripped = raw.strip()
        if not stripped:
            previous_indent = None
            continue
        heading = HEADING_RE.match(stripped)
        if heading:
            section = heading.group(1)
            previous_indent = None
            continue
        lead = LEAD_RE.match(stripped)
        if lead and raw == raw.lstrip():
            section = lead.group(1)
            previous_indent = None
            continue
        if section in LITERAL_SECTIONS:
            previous_indent = None
            continue
        indent = len(raw) - len(raw.lstrip())
        is_entry = bool(ENTRY_RE.match(stripped)) and section in ENTRY_SECTIONS
        if previous_indent is not None and indent == previous_indent:
            if not (is_entry and previous_was_entry):
                return True
        previous_indent = indent
        previous_was_entry = is_entry
    return False


def first_split_section(doc):
    """
    Purpose:
        Find the first section whose body is broken into more than one paragraph.

    Parameters:
        doc: The docstring text.

    Returns:
        The heading of the offending section, or None when every section is a single block.

    Implementation notes:
        A section is one line of prose, so a blank line between two content lines of the same section is a split. Usage and Examples are exempt, since they hold literal commands whose line breaks are meaningful, and the entry sections are exempt because one entry per line is their shape.
    """
    section = None
    seen_content = False
    saw_blank = False
    for raw in dedent_doc(doc).split("\n"):
        stripped = raw.strip()
        if not stripped:
            if seen_content:
                saw_blank = True
            continue
        heading = HEADING_RE.match(stripped)
        lead = LEAD_RE.match(stripped) if raw == raw.lstrip() else None
        if heading or lead:
            section = (heading or lead).group(1)
            seen_content = False
            saw_blank = False
            continue
        if section in LITERAL_SECTIONS or section in ENTRY_SECTIONS:
            continue
        if seen_content and saw_blank:
            return section
        seen_content = True
    return None


def walk_definitions(node, prefix):
    """
    Purpose:
        Yield every class and function under a node, including those nested inside statements.

    Parameters:
        node: The node to walk.
        prefix: The qualified name of the enclosing scope.

    Returns:
        Triples of qualified name, definition node, and whether it sits directly in a class body.

    Implementation notes:
        Definitions inside conditionals, loops and exception handlers are included, because a helper defined under a platform check still ships and still needs documenting. The class flag is carried here rather than recovered from the qualified name, because a function nested inside a method also has a dotted name and is not a method itself.
    """
    in_class = isinstance(node, ast.ClassDef)
    for attribute in ("body", "orelse", "finalbody", "handlers"):
        for child in getattr(node, attribute, None) or []:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qualified = "%s.%s" % (prefix, child.name) if prefix else child.name
                yield qualified, child, in_class
                yield from walk_definitions(child, qualified)
            else:
                yield from walk_definitions(child, prefix)


def check_file_level(path, source, violations):
    """
    Purpose:
        Apply the rules that concern the file as a whole rather than any one docstring.

    Parameters:
        path: The file being checked.
        source: Its text.
        violations: Collected failures, appended to in place.

    Side effects:
        Appends to the violations list.
    """
    if not source.startswith(SHEBANG + "\n"):
        violations.append(Violation(
            path, "<file>", "shebang",
            "line 1 must be exactly %r" % SHEBANG))
    for number, line in enumerate(source.splitlines()[1:], start=2):
        if line.startswith("#!"):
            violations.append(Violation(
                path, "<file>", "shebang",
                "a second shebang line at line %d" % number))
    if source and not source.endswith("\n"):
        violations.append(Violation(
            path, "<file>", "newline",
            "file must end with exactly one newline terminator"))
    if source.endswith("\n\n"):
        violations.append(Violation(
            path, "<file>", "trailing-blank",
            "file ends with a blank line; end with the newline terminator alone"))
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT and token.start[0] != 1:
            violations.append(Violation(
                path, "<file>", "hash-comment",
                "hash comment at line %d; use a docstring instead" % token.start[0]))


def check_docstring(path, label, node, doc, expr, source_lines, violations, is_module,
                    is_method):
    """
    Purpose:
        Apply every docstring rule to one module, class or function.

    Parameters:
        path: The file being checked.
        label: The qualified name of the thing being documented.
        node: Its AST node.
        doc: Its docstring text.
        expr: The docstring expression node, used to find the opening delimiter.
        source_lines: The file's lines, for inspecting that delimiter.
        violations: Collected failures, appended to in place.
        is_module: Whether this docstring belongs to the module itself.
        is_method: Whether the thing being documented sits directly in a class body.

    Side effects:
        Appends to the violations list.
    """
    def fail(rule, detail):
        """
        Purpose:
            Record one failure against the docstring being checked.

        Parameters:
            rule: Short identifier for the rule that failed.
            detail: Human-readable explanation.

        Side effects:
            Appends to the enclosing violations list.
        """
        violations.append(Violation(path, label, rule, detail))

    opener = source_lines[expr.lineno - 1].strip()
    if opener.startswith((SINGLE_TRIPLE, "r" + SINGLE_TRIPLE, "f" + SINGLE_TRIPLE)):
        fail("quotes", "docstring must be delimited with double-quote triples")

    bodies, order = parse_sections(doc)

    for heading in sorted({h for h in order if h not in ALLOWED_SECTIONS}):
        fail("section", "unknown heading %r" % heading)
    if len(order) != len(set(order)):
        repeated = sorted({h for h in order if order.count(h) > 1})
        fail("section", "repeated heading(s) %s" % repeated)
    for heading in order:
        if heading in bodies and not [ln for ln in bodies[heading] if ln.strip()]:
            fail("section", "section %r is empty" % heading)
    if "Purpose" not in bodies:
        fail("section", "no Purpose section")

    if is_module:
        if "Module" not in bodies:
            fail("section", "module docstring has no Module line")
        else:
            declared = (bodies["Module"] or [""])[0].strip()
            expected = expected_module_name(Path(path))
            if declared != expected:
                fail("module-name",
                     "declares %r but the importable name is %r" % (declared, expected))
    elif "Module" in bodies:
        fail("section", "a Module line belongs only on a module docstring")

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        parameters = declared_parameters(node, is_method)
        if parameters and "Parameters" not in bodies:
            fail("parameters", "takes %s but has no Parameters section" % parameters)
        if "Parameters" in bodies:
            documented = set()
            for line in bodies["Parameters"]:
                entry = ENTRY_RE.match(line.strip())
                if entry:
                    for name in entry.group(1).split(","):
                        documented.add(name.strip().lstrip("*"))
            for name in parameters:
                if name not in documented:
                    fail("parameters", "parameter %r is undocumented" % name)
            for name in sorted(documented - set(parameters)):
                fail("parameters", "documents %r, which is not a parameter" % name)
        if produces_value(node) and "Returns" not in bodies:
            fail("returns", "returns or yields a value but has no Returns section")

    if has_wrapped_prose(doc):
        fail("wrapping", "prose is hard-wrapped; each paragraph must be one line")
    split_section = first_split_section(doc)
    if split_section is not None:
        fail("paragraph",
             "section %r is split into paragraphs; each section is one line"
             % split_section)
    for line in doc.split("\n")[:-1]:
        if line.strip() and line != line.rstrip():
            fail("whitespace", "docstring line has trailing whitespace")
            break
    if SECRET_RE.search(doc):
        fail("secret", "docstring contains credential-shaped text")


def check_path(path):
    """
    Purpose:
        Check one file against every rule.

    Parameters:
        path: The file to check.

    Returns:
        The violations found, empty when the file is clean.

    Raises:
        SyntaxError: When the file does not parse. The caller turns this into a violation rather than letting it crash the run.
        tokenize.TokenError: When tokenizing fails before parsing does, which is how an unterminated construct usually surfaces.
    """
    source = path.read_text(encoding="utf-8")
    source_lines = source.splitlines()
    violations = []

    check_file_level(path, source, violations)

    tree = ast.parse(source)
    if tree.body:
        doc, expr = docstring_expr(tree)
        if doc is None:
            violations.append(Violation(
                path, "<module>", "docstring",
                "the module docstring must be the first statement"))
        elif expr.lineno != 2:
            violations.append(Violation(
                path, "<module>", "docstring",
                "the module docstring must start on line 2, under the shebang"))

    targets = [("<module>", tree, True, False)]
    for qualified, node, in_class in walk_definitions(tree, ""):
        targets.append((qualified, node, False, in_class))

    for label, node, is_module, is_method in targets:
        doc, expr = docstring_expr(node)
        if doc is None:
            violations.append(Violation(path, label, "docstring", "has no docstring"))
            continue
        if stacked_docstring(node):
            violations.append(Violation(
                path, label, "docstring",
                "a second string literal sits directly under the docstring"))
        check_docstring(path, label, node, doc, expr, source_lines,
                        violations, is_module, is_method)
    return violations


def run(targets):
    """
    Purpose:
        Check every file under the targets.

    Parameters:
        targets: Files or directories to check.

    Returns:
        A pair of the number of files checked and the violations found.

    Side effects:
        Reads the target files.
    """
    violations = []
    files = iter_python_files(targets)
    for path in files:
        try:
            violations.extend(check_path(path))
        except (SyntaxError, tokenize.TokenError, UnicodeDecodeError) as error:
            violations.append(Violation(
                path, "<file>", "syntax", "file does not parse: %s" % error))
    return len(files), violations


def main(argv=None):
    """
    Purpose:
        Command-line entry point.

    Parameters:
        argv: Argument vector to parse; None reads the process arguments.

    Returns:
        The process exit code: 0 when every file is clean, 1 otherwise.

    Side effects:
        Writes the report to stdout.
    """
    parser = argparse.ArgumentParser(
        prog="check_comment_style",
        description="Verify that source files follow the project commenting standard.")
    parser.add_argument("targets", nargs="*", default=list(DEFAULT_TARGETS),
                        help="files or directories to check")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable output")
    parser.add_argument("--quiet", action="store_true",
                        help="print nothing when every file is clean")
    args = parser.parse_args(argv)

    targets = args.targets or list(DEFAULT_TARGETS)
    checked, violations = run(targets)

    if args.json:
        print(json.dumps({
            "files_checked": checked,
            "violations": [v.as_dict() for v in violations],
        }, indent=2))
        return 1 if violations else 0

    if violations:
        current = None
        for violation in violations:
            if violation.path != current:
                current = violation.path
                print("")
                print(current)
            print("  %s [%s] %s" % (violation.symbol, violation.rule, violation.detail))
        print("")
        print("comment style: %d violation(s) across %d file(s)"
              % (len(violations), len({v.path for v in violations})))
        print("see CONTRIBUTING.md for the standard")
        return 1

    if not args.quiet:
        print("comment style: %d file(s) clean" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
