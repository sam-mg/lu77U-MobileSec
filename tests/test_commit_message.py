#!/usr/bin/env python3
"""
Module: test_commit_message

Purpose:
    Pin the commit message format and every place that enforces it, so a rule that silently stops firing, or a hook that stops calling the checker, is caught.

Dependencies:
    pytest, the standard library, the git executable, and the checker script, imported by path.
"""

import importlib.util
import io
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPO_ROOT / "scripts" / "check_commit_message.py"
ZERO = "0" * 40


def _load_checker():
    """
    Purpose:
        Import the checker from its path.

    Returns:
        The imported checker module.

    Implementation notes:
        Imported by path because the scripts directory is not an installed package.
    """
    spec = importlib.util.spec_from_file_location("check_commit_message", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()

APPROVED = (
    "docs(wiki): add Benchmarks page, sidebar and footer; document device verification and recent analysis changes\n"
    "\n"
    "- Benchmarks: Ghera results (59/60 vulnerable apps found, 17/59 fixed apps still reported), comparison with published results, how it was scored\n"
    "- Sidebar and footer on every page\n"
    "- Links: absolute GitHub URLs to code and between pages, so they open on GitHub instead of a 404 or the raw markdown\n"
)

REJECTED = (
    "docs(wiki): add Benchmarks page, sidebar and footer; document device verification and recent analysis changes\n"
    "\n"
    "- Benchmarks: Ghera results (59/60 vulnerable apps found, 17/59 fixed apps\n"
    "  still reported), comparison with published results, how it was scored\n"
    "- Sidebar and footer on every page\n"
)


class TestFormat:
    """
    Purpose:
        The format itself: a one-line subject, then optionally a blank line and one single-line "- " item per line.
    """

    @pytest.mark.parametrize("message", [
        "fix: one line",
        "fix: one line\n",
        "fix: one line\n\n\n",
        "feat: subject\n\n- one\n- two\n",
        "feat: subject\n\n- " + ("a long item that runs on " * 20).strip() + "\n",
        APPROVED,
    ])
    def test_a_clean_message_passes(self, message):
        """
        Purpose:
            Pin that a subject alone, or a subject and a list of single-line items however long, passes.

        Parameters:
            message: A message in the format.
        """
        assert checker.message_problems(message) == []

    @pytest.mark.parametrize("message, problem", [
        (REJECTED, 'line 4 is not a "- " item'),
        ("fix: subject\n\nSome prose about the change.\n", 'line 3 is not a "- " item'),
        ("fix: subject\n\n- one\n\n- two\n", "line 4 is blank"),
        ("fix: a subject that\nruns onto a second line\n", "line 2 is not blank"),
        ("fix: subject\n\n- one\n  - nested\n", 'line 4 is not a "- " item'),
        ("fix: subject \n", "line 1 ends in whitespace"),
        ("fix: subject\n\n- \n", "line 3 is an empty item"),
        ("", "the message is empty"),
        ("\n\n", "the message is empty"),
    ])
    def test_a_broken_message_is_reported(self, message, problem):
        """
        Purpose:
            Pin each way a message can break the format, with the line it names.

        Parameters:
            message: A message that breaks the format.
            problem: The start of the problem it must produce.
        """
        assert any(found.startswith(problem) for found in checker.message_problems(message))

    def test_the_example_in_contributing_passes(self):
        """
        Purpose:
            Pin that the example CONTRIBUTING.md gives is a message the checker accepts.
        """
        text = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        section = text.split("## Commit messages", 1)[1]
        example = re.search(r"```text\n(.*?)```", section, re.S).group(1)
        assert checker.message_problems(example) == []


class TestMessageFile:
    """
    Purpose:
        The commit-msg hook's form: a message file that may still carry git's comment lines.
    """

    def test_git_comment_lines_are_ignored(self):
        """
        Purpose:
            Pin that the template git writes for the editor does not count against the message.
        """
        message = "fix: subject\n\n- one\n# Please enter the commit message for your changes.\n#\n# On branch main\n"
        assert checker.message_problems(message, strip_comments=True) == []
        assert checker.message_problems(message) != []

    def test_everything_after_the_scissors_is_ignored(self):
        """
        Purpose:
            Pin that the diff git commit -v appends below the scissors line is not read as the message.
        """
        message = "fix: subject\n\n" + checker.SCISSORS + "\ndiff --git a/x b/x\n+changed\n"
        assert checker.message_problems(message, strip_comments=True) == []

    def test_a_broken_file_is_refused_and_kept(self, tmp_path, capsys):
        """
        Purpose:
            Pin that a broken message file exits 1 and says where the message is kept.

        Parameters:
            tmp_path: A scratch directory.
            capsys: Captures the output.
        """
        path = tmp_path / "COMMIT_EDITMSG"
        path.write_text(REJECTED, encoding="utf-8")
        assert checker.main([str(path)]) == 1
        assert str(path) in capsys.readouterr().out
        path.write_text(APPROVED, encoding="utf-8")
        assert checker.main([str(path)]) == 0


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """
    Purpose:
        A scratch git repository, isolated from the developer's own git configuration, as the current directory.

    Parameters:
        tmp_path: A scratch directory.
        monkeypatch: Sets the environment and the working directory.

    Returns:
        A function that commits a message and returns the new commit's id.
    """
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "Tester")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "tester@example.com")
    monkeypatch.chdir(tmp_path)
    subprocess.run(["git", "init", "-q", "-b", "main"], check=True)

    def commit(message, committer_email=None):
        """
        Purpose:
            Make an empty commit with a given message.

        Parameters:
            message: The commit message.
            committer_email: The committer's email, when it should differ from the default.

        Returns:
            The commit id.
        """
        env = dict(os.environ)
        if committer_email:
            env["GIT_COMMITTER_EMAIL"] = committer_email
        subprocess.run(["git", "commit", "-q", "--allow-empty", "--cleanup=verbatim", "-F", "-"],
                       input=message, text=True, check=True, env=env)
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()

    return commit


class TestCommits:
    """
    Purpose:
        The forms that read commits from git: a range, the unpushed commits, and what a push sends.
    """

    def test_a_range_reports_only_the_broken_commit(self, repo, capsys):
        """
        Purpose:
            Pin that a range check exits 1 and names the commit that breaks the format, not the clean one.

        Parameters:
            repo: Commits into a scratch repository.
            capsys: Captures the output.
        """
        base = repo("chore: start")
        repo(APPROVED)
        bad = repo(REJECTED)
        assert checker.main(["--range", f"{base}..HEAD"]) == 1
        out = capsys.readouterr().out
        assert bad[:7] in out and "1 of 2 commit(s)" in out

    def test_a_merge_commit_is_skipped(self, repo):
        """
        Purpose:
            Pin that a merge commit, whose message git writes, is not checked.

        Parameters:
            repo: Commits into a scratch repository.
        """
        base = repo("chore: start")
        subprocess.run(["git", "checkout", "-q", "-b", "side"], check=True)
        repo("feat: side work")
        subprocess.run(["git", "checkout", "-q", "main"], check=True)
        subprocess.run(["git", "merge", "-q", "--no-ff", "side", "-m", "Merge branch side\n\nA paragraph git would never accept here."], check=True)
        assert checker.main(["--range", f"{base}..HEAD"]) == 0

    def test_a_commit_github_made_is_skipped(self, repo):
        """
        Purpose:
            Pin that a commit GitHub committed, with its paragraph and Signed-off-by line, is not checked.

        Parameters:
            repo: Commits into a scratch repository.
        """
        base = repo("chore: start")
        repo("Update FUNDING.yml\n\nUpdated funding options.\n\nSigned-off-by: Someone <someone@example.com>\n",
             committer_email=checker.GITHUB_COMMITTER)
        assert checker.main(["--range", f"{base}..HEAD"]) == 0

    def test_unpushed_checks_what_no_remote_has(self, repo):
        """
        Purpose:
            Pin that with no remote, every commit on HEAD is unpushed and checked.

        Parameters:
            repo: Commits into a scratch repository.
        """
        repo(REJECTED)
        assert checker.main(["--unpushed"]) == 1

    def test_pre_push_reads_the_hook_lines(self, repo, monkeypatch):
        """
        Purpose:
            Pin that the pre-push form checks exactly the commits between the remote's tip and the pushed one.

        Parameters:
            repo: Commits into a scratch repository.
            monkeypatch: Replaces standard input.
        """
        pushed = repo("chore: already on the remote\n\nA paragraph, from before the rule.\n")
        tip = repo(APPROVED)
        monkeypatch.setattr("sys.stdin", io.StringIO(f"refs/heads/main {tip} refs/heads/main {pushed}\n"))
        assert checker.main(["--pre-push"]) == 0
        bad = repo(REJECTED)
        monkeypatch.setattr("sys.stdin", io.StringIO(f"refs/heads/main {bad} refs/heads/main {pushed}\n"))
        assert checker.main(["--pre-push"]) == 1

    def test_pre_push_specs_cover_new_deleted_and_unknown_refs(self, repo):
        """
        Purpose:
            Pin how each kind of pushed ref becomes a rev-list specification.

        Parameters:
            repo: Commits into a scratch repository.
        """
        old = repo("chore: start")
        new = repo("chore: next")
        lines = "\n".join([
            f"refs/heads/main {new} refs/heads/main {old}",
            f"refs/heads/fresh {new} refs/heads/fresh {ZERO}",
            f"(delete) {ZERO} refs/heads/gone {old}",
            f"refs/heads/main {new} refs/heads/main {'1' * 40}",
        ])
        assert checker.pre_push_specs(lines) == [
            [f"{old}..{new}"],
            [new, "--not", "--remotes"],
            [new, "--not", "--remotes"],
        ]


class TestWiring:
    """
    Purpose:
        Every place that must run the check still runs it, so dropping one is caught.
    """

    def test_the_commit_msg_hook_checks_the_message_file(self):
        """
        Purpose:
            Pin that the versioned commit-msg hook exists, is executable and passes git's message file to the checker.
        """
        hook = REPO_ROOT / ".githooks" / "commit-msg"
        assert os.access(hook, os.X_OK)
        assert 'scripts/check_commit_message.py "$1"' in hook.read_text(encoding="utf-8")

    @pytest.mark.parametrize("path, call", [
        (".githooks/pre-push", "scripts/check_commit_message.py --pre-push"),
        ("scripts/preflight.sh", "scripts/check_commit_message.py --unpushed"),
        (".github/workflows/ci.yml", 'scripts/check_commit_message.py --range "$range"'),
    ])
    def test_every_gate_runs_the_check(self, path, call):
        """
        Purpose:
            Pin that the pre-push hook, preflight and CI each run the commit message check.

        Parameters:
            path: The file that must run it.
            call: The invocation it must contain.
        """
        assert call in (REPO_ROOT / path).read_text(encoding="utf-8")

    def test_ci_fetches_the_history_it_checks(self):
        """
        Purpose:
            Pin that CI checks out full history, without which the pushed range cannot be read.
        """
        assert "fetch-depth: 0" in (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
