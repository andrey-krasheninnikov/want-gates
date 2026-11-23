#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 [--apply] PR_NUMBER MERGE_SHA" >&2
    exit 2
}

apply=false
if [ "$#" -gt 0 ] && [ "$1" = --apply ]; then
    apply=true
    shift
fi
[ "$#" -eq 2 ] || usage
pr=$1
merge=$2
case "$pr" in ''|*[!0-9]*) usage ;; esac
case "$merge" in ''|*[!0-9a-f]*) usage ;; esac
[ "$(printf '%s' "$merge" | wc -c | tr -d ' ')" -eq 40 ] || usage

repo=andrey-krasheninnikov/want-gates
branch=feat/11-netbird-isolation
case "$(git remote get-url origin)" in
    "https://github.com/$repo.git"|"git@github.com:$repo.git") ;;
    *) echo 'Unexpected origin' >&2; exit 1 ;;
esac
live=$(gh pr view "$pr" --repo "$repo" --json state,baseRefName,headRefName,headRefOid,mergeCommit \
    --jq '[.state, .baseRefName, .headRefName, .headRefOid, .mergeCommit.oid] | join(" ")')
head=$(git rev-parse "$merge^2")
[ "$live" = "MERGED main $branch $head $merge" ] || {
    echo 'PR, merge SHA, or source revision does not match issue #11' >&2
    exit 1
}
if git rev-parse --verify -q "$merge^3" >/dev/null; then
    echo 'Expected a merge with two parents' >&2
    exit 1
fi
remote=$(git ls-remote --exit-code origin refs/heads/main | cut -f1)
[ "$(git rev-parse HEAD)" = "$remote" ] && git merge-base --is-ancestor "$merge" "$remote" || {
    echo 'Start from current origin/main with the merge in its ancestry' >&2
    exit 1
}
git diff --name-status "$merge^1" "$merge"
if "$apply"; then
    [ "$(git branch --show-current)" = revert/11-netbird-isolation ] && \
        [ -z "$(git status --porcelain)" ] || {
        echo 'Use a clean revert/11-netbird-isolation worktree' >&2
        exit 1
    }
    git revert --no-edit -m 1 "$merge"
fi
