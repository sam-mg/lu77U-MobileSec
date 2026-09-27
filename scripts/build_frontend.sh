#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
frontend_dir="$repo_root/lu77U_MobileSec/frontend"
static_dir="$repo_root/lu77U_MobileSec/web/static"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to build the frontend (https://nodejs.org)." >&2
  exit 1
fi

cd "$frontend_dir"

version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo_root/pyproject.toml" | head -1)"
if [ -n "$version" ]; then
  npm pkg set "version=$version" >/dev/null
fi

if [ -f package-lock.json ]; then
  npm ci
else
  npm install
fi

npm run build

echo "Built into $static_dir"