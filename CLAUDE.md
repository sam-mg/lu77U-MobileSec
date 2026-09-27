# CLAUDE.md

Project rules for lu77U-MobileSec. These are strict. Code that breaks any of them is rejected by `scripts/check_comment_style.py`, and the `pre-push` hook refuses the push.

Human contributors: see [CONTRIBUTING.md](CONTRIBUTING.md), which says the same thing at more length.

---

## 1. Scope

Every `.py` file that belongs to this repository:

| Path | Covered |
|---|---|
| `lu77U_MobileSec/**` | yes |
| `tests/**` | yes |
| `scripts/**` | yes |
| `etc/**` | **no** - gitignored clones of third-party vulnerable apps, with their own `.git` and licences |
| `.venv/` `build/` `dist/` `demo-dist/` `brag-output/` `*.egg-info/` `node_modules/` `__pycache__/` | **no** - generated or vendored |

## 2. File layout

```python
#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.example.thing

Purpose:
    One line saying what this module is for.
"""

import os
```

- Line 1 is exactly `#!/usr/bin/env python3`. Every file, no exceptions.
- The module docstring is the **next statement, on line 2**. Nothing above it.
- The file ends with **exactly one newline terminator**. No blank line at the end. Do not strip the final newline either - a file with no terminator breaks POSIX
  tools and shows as `\ No newline at end of file` in git.

## 3. No `#` comments

**Zero `#` comments past line 1.** Not `# noqa`, not `# pragma: no cover`, not a section banner, not a TODO. Every explanation goes in a docstring.

The only `#` permitted in the whole file is the shebang on line 1.

## 4. Docstrings

- Delimit with `"""`. Never `'''`.
- Document **every** module, class, function and method - including nested functions, and functions defined inside an `if` or a `try`.
- Every docstring has a `Purpose:`.
- `Module:` states the real importable dotted path, and appears **only** on module docstrings.
- Document every parameter, and nothing that is not a parameter. A method's leading `self` or `cls` is exempt - only that one, only on a method, and not on a `@staticmethod`. A parameter that merely happens to be named `cls` still needs documenting.
- Never leave a second string literal under a docstring. Only the first one is the docstring; a second renders as a duplicated block and is otherwise invisible. The checker catches it.
- Anything that returns or yields a value has a `Returns:`.
- No trailing whitespace on any line.
- **Never put a credential, key or token in a docstring.**

### Allowed sections

Use the ones that apply, omit the rest. Nothing outside this set is accepted.

| Where | Sections |
|---|---|
| Module | `Module` `Purpose` `Responsibilities` `Dependencies` `Security considerations` |
| Class | `Purpose` `Attributes` `Invariants` `Thread-safety` |
| Function | `Purpose` `Parameters` `Returns` `Raises` `Preconditions` `Postconditions` `Complexity` `Side effects` `Security considerations` |
| Public API | `Usage` `Examples` `Compatibility` `Deprecation` |
| Anywhere | `Implementation notes` `Known limitations` |

## 5. One line per section - never paragraphs

A section body is **one single line**, however long it runs. Do not wrap it, and do not split it into paragraphs.

```python
# WRONG - hard-wrapped across lines
    Purpose:
        Resolve the per-user configuration directory, creating it if it does not exist.

# WRONG - split into two paragraphs
    Implementation notes:
        Creation happens here rather than at first write.

        The cost is that merely asking where config lives creates it.

# RIGHT - one line, however long
    Implementation notes:
        Creation happens here rather than at first write so that every caller can assume the directory exists. The cost is that merely asking where config lives creates it.
```

Blank lines separate **sections**, never content inside one.

Three exceptions:

- `Parameters:`, `Raises:` and `Attributes:` get **one entry per line**.
- `Usage:` and `Examples:` keep their own line breaks, because they hold literal commands that must stay runnable.

## 6. Write why, not what

```python
# Useless - the signature already says this
    Purpose:
        Returns the config directory.

# Useful - says what the reader cannot see
    Purpose:
        Resolve the per-user configuration directory, creating it if needed.

    Implementation notes:
        Creation happens here rather than at first write so that every caller can assume the directory exists.
```

Document what bites people: security-sensitive behaviour, side effects, exceptions, non-obvious decisions, assumptions, workarounds, known limitations.

Keep it accurate. A docstring describing parameters a function does not have is worse than no docstring, and the checker rejects it.

## 7. Tests are part of the change

A feature or fix is not finished until something would fail if it regressed.

- Add tests in `tests/`, in the existing style: classes grouping related cases, plain `assert`, `pytest.mark.parametrize` for tables of inputs.
- If you add a rule or a check, **test the rule itself**. See `tests/test_comment_style.py`, which pins each rule against a crafted file so a rule that silently stops firing is caught.
- The whole suite must pass. Not the tests you touched - all of them.

## 8. The push gate

Both must pass or the push is refused:

```bash
python scripts/check_comment_style.py    # the standard above
python -m pytest                         # the whole suite
```

Run both with `./scripts/preflight.sh`. Enable the hook once per clone with `./scripts/install_hooks.sh`.

`git push --no-verify` bypasses the hook, but `.github/workflows/ci.yml` runs the identical pair, so a bypassed push fails there instead.

## 9. Working on this repo

- Never claim a change is done without running `./scripts/preflight.sh` and reporting the real result.
- Never weaken a rule or a test to make a check pass. Fix the code.
- When the checker and the code disagree, work out which is actually wrong before changing either.
- Do not edit anything under `etc/` - those are other people's repositories.