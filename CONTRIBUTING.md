# Contributing to lu77U-MobileSec

Contributions are welcome. This page is the contract: if your change satisfies what is below, it will pass the gates and can be merged.

## Quick start

```bash
git clone https://github.com/sam-mg/lu77U-MobileSec.git
cd lu77U-MobileSec
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

./scripts/install_hooks.sh      # enable the commit-msg and pre-push hooks - do this once
```

Then work as normal:

```bash
git checkout -b feature-name
# ...make your change, with tests and docstrings...
./scripts/preflight.sh          # same checks the hook runs
git commit -m "Add feature"
git push origin feature-name
```

Open a pull request when the push succeeds.

## The five gates

A push is refused unless **all five** pass. The pre-push hook runs them locally and CI runs the identical five, via the identical scripts, on every push and pull request.

| Gate | Command | What it means |
|---|---|---|
| Commit messages | `python scripts/check_commit_message.py --unpushed` | Every commit being pushed follows the [commit message format](#commit-messages) |
| Comment style | `python scripts/check_comment_style.py` | Every file follows the commenting standard below |
| Tests | `python -m pytest` | The whole suite passes, including tests for your change |
| CodeQL | `./scripts/codeql_scan.sh` | Zero findings from every finding-producing suite CodeQL ships for Python, JavaScript and the workflows - security and code quality both, including experimental queries |
| Clean install | `./scripts/verify_install.sh` | A fresh venv, `pip install -e .` from cold, then `-v` and `-V` both actually work |

Run all five at once with `./scripts/preflight.sh`.

The clean-install gate is the slowest one: it builds a brand-new venv and installs every dependency from PyPI with nothing reused, since that is the whole point of the check. `-v` has to print the exact version `pyproject.toml` declares - catching a case where the packaging metadata drifted from the source of truth - and `-V` has to start the real web dashboard without error. `-V` alone blocks forever and never exits by itself, so the script starts it with the real (if undocumented) `--port`/`--no-browser` flags and stops it again once it sees a clean startup with no traceback.

The CodeQL gate installs its own CLI and query packs the first time it runs on a machine (a few hundred MB, cached outside the repo so later runs are fast) and does not stop at security bugs - `security-and-quality`, `security-experimental` and `code-quality-extended` all have to come back empty. There is no suppression: this project's ban on `#` comments also rules out CodeQL's usual inline `lgtm[rule-id]` marker, so a finding gets fixed or the code gets restructured, never silenced. A query is never dropped from the suites, even when its stock form cannot be satisfied by application code: `js/untrusted-data-to-external-api-more-sources` has no code-level sanitizer (tested against real validation already in this codebase - a type guard, primitive extraction, a JSON round trip - none of it clears the taint, because the query's `Sanitizer` class has no implementations upstream), so `scripts/codeql/lu77u-js-models/` supplies a small, real model extension marking exactly the two packages this pattern hits (`react`, `react-router-dom`) as not being external security boundaries, and `scripts/codeql/javascript-suite.qls` runs that copy under the same rule id in place of the stock one. The check still runs against every file and would still catch a real external-API sink; nothing is skipped.

If the hooks were not installed, `./scripts/install_hooks.sh` enables them. You can bypass them with `git push --no-verify`, but CI runs the same five gates, so a bypassed push fails there instead.

## Every change needs tests

A feature or a fix is not finished until something would fail if it regressed. Add tests alongside the change, in `tests/`, following the existing style: classes grouping related cases, plain `assert`, `pytest.mark.parametrize` for tables of inputs. If you add a rule or a check, test the rule itself - see `tests/test_comment_style.py`, which pins each rule against a crafted file so a rule that stops firing is caught rather than silently passing everything.

## The commenting standard

The rule is simple to state: **no `#` comments anywhere, and everything is documented with a sectioned docstring.**

Every `.py` file under `lu77U_MobileSec/` looks like this:

```python
#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.example.thing

Purpose:
    What this module is for, and why it exists as its own module.

Responsibilities:
    What it does, and what it deliberately leaves to someone else.

Dependencies:
    What it needs, and anything notable about when those are loaded.

Security considerations:
    Anything here that handles untrusted input, credentials or a device.
"""

import os


def resolve(path, strict=False):
    """
    Purpose:
        What this does, stated once.

    Parameters:
        path: What the caller should pass.
        strict: What changes when it is set.

    Returns:
        What comes back, including what an absent result means.

    Raises:
        ValueError: When, and why this raises rather than returning a default.

    Side effects:
        Anything that outlives the call.

    Implementation notes:
        Why it is done this way, if that is not obvious from reading it.
    """
    return os.path.abspath(path)
```

### The rules

1. Line 1 is exactly `#!/usr/bin/env python3`.
2. The module docstring is the very next statement, on line 2.
3. **No `#` comments past line 1.** None - not `# noqa`, not `# pragma: no cover`, not a banner. Explanations go in docstrings.
4. Docstrings use `"""`, never `'''`.
5. Every module, class, function and method is documented - including functions nested inside other functions, and functions defined under an `if`.
6. `Module:` names the real importable path, and appears only on module docstrings.
7. Every docstring has a `Purpose:`.
8. Every parameter is documented, and nothing is documented that is not a parameter. A method's leading `self` or `cls` is exempt - only that one, only on a method, and not on a `@staticmethod`. A parameter that merely happens to be named `cls`, which a test parametrized over classes has, still needs documenting.
9. Anything that returns or yields a value has a `Returns:`.
10. Prose is **not hard-wrapped** - each paragraph is one long line, however long. Blank lines separate paragraphs. Entries under `Parameters:`, `Raises:` and `Attributes:` get one line each. `Usage:` and `Examples:` keep their own line breaks, because they hold literal commands.
11. No trailing whitespace, and files end with a newline.
12. **Never put a credential in a docstring.**

### The sections

Use the ones that apply and omit the rest. Nothing outside this set is accepted.

| Where | Sections |
|---|---|
| Module | `Module` `Purpose` `Responsibilities` `Dependencies` `Security considerations` |
| Class | `Purpose` `Attributes` `Invariants` `Thread-safety` |
| Function | `Purpose` `Parameters` `Returns` `Raises` `Preconditions` `Postconditions` `Complexity` `Side effects` `Security considerations` |
| Public API | `Usage` `Examples` `Compatibility` `Deprecation` |
| Anything | `Implementation notes` `Known limitations` |

### What to actually write

Explain **why**, not what the code plainly says.

```python
# Useless - the signature already says this:
    Purpose:
        Returns the config directory.

# Useful - says what the reader cannot see:
    Purpose:
        Resolve the per-user configuration directory, creating it if needed.

    Implementation notes:
        Creation happens here rather than at first write so that every caller can assume the directory exists. The cost is that merely asking where config lives creates it.
```

Document the things that bite people: security-sensitive behaviour, side effects, exceptions, non-obvious decisions, assumptions, workarounds and known limitations. Keep it accurate - a docstring describing parameters the function does not have is worse than none, and the checker will reject it.

## When the checker fails

It names the file, the symbol, the rule and the reason:

```
lu77U_MobileSec/example/thing.py
  resolve [parameters] parameter 'strict' is undocumented
  resolve [returns] returns or yields a value but has no Returns section

comment style: 2 violation(s) across 1 file(s)
```

Useful flags:

```bash
python scripts/check_comment_style.py lu77U_MobileSec/example/thing.py   # one file
python scripts/check_comment_style.py --json                             # machine-readable
python scripts/check_comment_style.py --quiet                            # silent when clean
```

## Commit messages

The first line is the subject. If more is needed, add one blank line, then a flat list with one `- ` item per line. Each item is a single line however long it runs: do not hard-wrap it, and do not write paragraphs or any other block. The `commit-msg` hook refuses a message that breaks this when you commit, and the pre-push hook and CI check every commit a push sends; merge commits and commits GitHub itself made are skipped.

```text
docs(wiki): add Benchmarks page, sidebar and footer

- Benchmarks: Ghera results (59/60 vulnerable apps found, 17/59 fixed apps still reported), comparison with published results, how it was scored
- Sidebar and footer on every page
```

## Reporting security issues

Do not open a public issue for a vulnerability in this tool. See [SECURITY.md](SECURITY.md).