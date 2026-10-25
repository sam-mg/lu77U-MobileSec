#!/usr/bin/env python3
"""
Module: check_commit_message

Purpose:
    Enforce the project's commit message format mechanically: a one-line subject, then optionally one blank line and a flat list with one "- " item per line, each item on a single line however long it runs.

Responsibilities:
    Check a message file for the commit-msg hook, the commits a push would send for the pre-push hook, the commits not yet on any remote for preflight, and an explicit range for CI, reporting each problem with its line number.

Dependencies:
    The standard library and the git executable only, so it runs in a hook before any project dependency is installed.

Usage:
    python scripts/check_commit_message.py .git/COMMIT_EDITMSG
    python scripts/check_commit_message.py --unpushed
    python scripts/check_commit_message.py --range origin/main..HEAD
    git push    (the pre-push hook pipes its ref lines to --pre-push)

Examples:
    A clean run prints a one-line summary and exits 0. A failing run prints each offending commit or file with one line per problem and exits 1.

Implementation notes:
    A hard-wrapped item is the failure this exists for. The line that continues an item does not start with "- ", so requiring every body line to start with it catches wrapping and paragraphs with one rule. Merge commits are skipped, because git or GitHub writes their message, not the author, and so are commits GitHub itself committed.

Security considerations:
    git is run with an argument list, never through a shell, so a ref name or range cannot inject a command.
"""

import argparse
import subprocess
import sys
from typing import List, Optional, Tuple

ZERO_SHA = "0" * 40
SCISSORS = "# ------------------------ >8 ------------------------"
GITHUB_COMMITTER = "noreply@github.com"


def message_problems(message: str, strip_comments: bool = False) -> List[str]:
    """
    Purpose:
        List every way a commit message breaks the format.

    Parameters:
        message: The message text.
        strip_comments: Drop what git itself strips before committing - lines starting with "#", and everything from the scissors line on - because the file the commit-msg hook receives still carries them.

    Returns:
        One sentence per problem, each naming its line; empty when the message follows the format.

    Implementation notes:
        Blank lines at either end are dropped first, as git's own cleanup does, so line numbers count from the subject.
    """
    lines = message.split("\n")
    if strip_comments:
        kept = []
        for line in lines:
            if line.rstrip() == SCISSORS:
                break
            if not line.startswith("#"):
                kept.append(line)
        lines = kept
    while lines and not lines[-1].strip():
        lines.pop()
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return ["the message is empty"]
    problems = []
    for number, line in enumerate(lines, 1):
        if line != line.rstrip():
            problems.append(f"line {number} ends in whitespace")
    if len(lines) > 1 and lines[1].strip():
        problems.append("line 2 is not blank: the subject is one line, so a line straight under it is a wrapped subject - join it to line 1, or leave a blank line before the list")
    for number, line in enumerate(lines[2:], 3):
        if not line.strip():
            problems.append(f"line {number} is blank: the list under the subject has no paragraphs, so no blank line goes between items")
        elif not line.startswith("- "):
            problems.append(f'line {number} is not a "- " item: a line that continues the item above is a wrapped item, so join it to that item, and write any paragraph as items')
        elif not line[2:].strip():
            problems.append(f"line {number} is an empty item")
    return problems


def _git(args: List[str]) -> str:
    """
    Purpose:
        Run git in the current repository and return what it printed.

    Parameters:
        args: The arguments after "git".

    Returns:
        Standard output.

    Raises:
        RuntimeError: When git exits non-zero, carrying its error output.
    """
    done = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout


def _is_commit(sha: str) -> bool:
    """
    Purpose:
        Tell whether a commit is present in this repository.

    Parameters:
        sha: The commit id.

    Returns:
        True when git can read it.

    Implementation notes:
        The remote's tip in a pre-push line can be missing locally, after someone else pushed or a force push, and a range from a missing commit makes rev-list fail.
    """
    try:
        _git(["cat-file", "-e", f"{sha}^{{commit}}"])
    except RuntimeError:
        return False
    return True


def commits_for(spec: List[str]) -> List[str]:
    """
    Purpose:
        List the non-merge commits a rev-list specification selects, oldest first.

    Parameters:
        spec: The rev-list arguments, such as ["origin/main..HEAD"] or ["HEAD", "--not", "--remotes"].

    Returns:
        The commit ids.

    Raises:
        RuntimeError: When git cannot resolve the specification.
    """
    return _git(["rev-list", "--no-merges", "--reverse", *spec]).split()


def pre_push_specs(ref_lines: str) -> List[List[str]]:
    """
    Purpose:
        Turn the lines git hands a pre-push hook into the rev-list specifications of the commits that push would send.

    Parameters:
        ref_lines: The hook's standard input: one "<local ref> <local sha> <remote ref> <remote sha>" line per ref being pushed.

    Returns:
        One specification per ref that sends commits.

    Implementation notes:
        A deleted ref sends nothing and is skipped. A new ref, or one whose remote tip is not present locally, sends whatever no remote branch already has.
    """
    specs = []
    for line in ref_lines.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        local_sha, remote_sha = parts[1], parts[3]
        if local_sha == ZERO_SHA:
            continue
        if remote_sha == ZERO_SHA or not _is_commit(remote_sha):
            specs.append([local_sha, "--not", "--remotes"])
        else:
            specs.append([f"{remote_sha}..{local_sha}"])
    return specs


def check_commits(shas: List[str]) -> List[Tuple[str, str, List[str]]]:
    """
    Purpose:
        Check the message of each commit.

    Parameters:
        shas: The commit ids.

    Returns:
        A (short id, subject, problems) triple for each commit that breaks the format.

    Implementation notes:
        A commit GitHub committed - an edit made on github.com, or a pull request merged there - is skipped. GitHub writes its description as a paragraph and appends a Signed-off-by line when the repository asks for sign-off, and such a commit exists on the remote before any hook or CI step can refuse it, so reporting it would fail every later run with nothing left to fix.
    """
    failures = []
    for sha in dict.fromkeys(shas):
        committer, _, message = _git(["log", "-1", "--format=%ce%x00%B", sha]).partition("\x00")
        if committer.strip() == GITHUB_COMMITTER:
            continue
        problems = message_problems(message)
        if problems:
            subject = message.strip().split("\n", 1)[0] if message.strip() else ""
            failures.append((sha[:7], subject, problems))
    return failures


def _report(failures: List[Tuple[str, str, List[str]]], checked: int) -> int:
    """
    Purpose:
        Print the result of a commit check and give the exit status.

    Parameters:
        failures: The (short id, subject, problems) triples of the commits that break the format.
        checked: How many commits were checked.

    Returns:
        0 when every commit is clean, 1 otherwise.
    """
    if not failures:
        print(f"commit message: {checked} commit(s) clean")
        return 0
    for short, subject, problems in failures:
        print(f"commit {short} {subject}")
        for problem in problems:
            print(f"  {problem}")
    print(f"commit message: {len(failures)} of {checked} commit(s) break the format; reword them with git commit --amend or git rebase -i, as CONTRIBUTING.md describes")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    """
    Purpose:
        Run the check the arguments ask for.

    Parameters:
        argv: The command-line arguments; sys.argv is used when omitted.

    Returns:
        The process exit status: 0 when clean, 1 when a message breaks the format, 2 when git could not be read.
    """
    parser = argparse.ArgumentParser(description="Check commit messages against the project's format.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("message_file", nargs="?", help="a message file, as the commit-msg hook passes it")
    mode.add_argument("--range", dest="revision_range", help="check every non-merge commit in this rev-list range")
    mode.add_argument("--unpushed", action="store_true", help="check the commits on HEAD that no remote branch has")
    mode.add_argument("--pre-push", action="store_true", help="check what a push sends, reading the pre-push hook's lines from standard input")
    args = parser.parse_args(argv)
    if args.message_file:
        with open(args.message_file, encoding="utf-8") as handle:
            problems = message_problems(handle.read(), strip_comments=True)
        if not problems:
            print("commit message: clean")
            return 0
        for problem in problems:
            print(f"  {problem}")
        print(f"commit message refused. The message is kept in {args.message_file}; fix it and commit again with: git commit -e -F {args.message_file}")
        return 1
    try:
        if args.revision_range:
            specs = [[args.revision_range]]
        elif args.unpushed:
            specs = [["HEAD", "--not", "--remotes"]]
        else:
            specs = pre_push_specs(sys.stdin.read())
        shas = [sha for spec in specs for sha in commits_for(spec)]
        return _report(check_commits(shas), len(dict.fromkeys(shas)))
    except RuntimeError as exc:
        print(f"commit message: could not read the commits: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
