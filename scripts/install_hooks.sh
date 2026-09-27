#!/usr/bin/env bash
#
# Points git at the versioned hooks in .githooks so pre-push runs for this clone.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
chmod +x .githooks/* scripts/*.sh 2>/dev/null || true
git config core.hooksPath .githooks
echo "hooks enabled: core.hooksPath -> .githooks"
echo "pre-push will now run the comment-style checker and the test suite."
