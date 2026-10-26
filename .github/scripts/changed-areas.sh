#!/usr/bin/env bash
# Decide which CI areas a change touches. A push to main runs every area; a
# pull request runs only the areas its files belong to, and CI's own files
# belong to every area. The jobs skip the rest, so no stale required check is
# left waiting.
set -euo pipefail

output="${GITHUB_OUTPUT:?}"
if [ "${EVENT:-}" != "pull_request" ]; then
  printf 'python=true\nweb=true\n' >> "$output"
  echo "not a pull request: every area runs"
  exit 0
fi

python=false
web=false
while IFS= read -r file; do
  case "$file" in
    .github/*) python=true; web=true ;;
    services/*|packages/*|scenarios/*) python=true ;;
    apps/web/*) web=true ;;
  esac
done < <(git diff --name-only "${BASE:?}...HEAD")

printf 'python=%s\nweb=%s\n' "$python" "$web" >> "$output"
echo "python=$python web=$web"
