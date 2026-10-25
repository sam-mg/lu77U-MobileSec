#!/usr/bin/env bash
#
# Points git at the versioned hooks in .githooks so commit-msg and pre-push run for this clone.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
chmod +x .githooks/* scripts/*.sh 2>/dev/null || true
git config core.hooksPath .githooks
echo "hooks enabled: core.hooksPath -> .githooks"
echo "commit-msg will now check each commit message, and pre-push will check the commit messages being pushed, then run the comment-style checker, the test suite, the CodeQL scan and a clean-install check."
