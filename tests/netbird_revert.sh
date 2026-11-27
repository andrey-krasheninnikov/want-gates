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
if [ "$pr" = 31 ]; then
    task=11
    branch=feat/11-netbird-isolation
else
    task=12
    branch=feat/12-netbird-routing
fi
case "$(git remote get-url origin)" in
    "https://github.com/$repo.git"|"git@github.com:$repo.git") ;;
    *) echo 'Unexpected origin' >&2; exit 1 ;;
esac
live=$(gh pr view "$pr" --repo "$repo" --json state,baseRefName,headRefName,headRefOid,mergeCommit,isCrossRepository,headRepositoryOwner \
    --jq '[.state, .baseRefName, .headRefName, .headRefOid, .mergeCommit.oid, (.isCrossRepository|tostring), .headRepositoryOwner.login] | join(" ")')
head=$(git rev-parse "$merge^2")
[ "$live" = "MERGED main $branch $head $merge false andrey-krasheninnikov" ] || {
    echo "PR, merge SHA, or source revision does not match issue #$task" >&2
    exit 1
}
if [ "$task" = 12 ]; then
    linked=$(gh pr view "$pr" --repo "$repo" --json closingIssuesReferences \
        --jq '[.closingIssuesReferences[] | select(.number == 12 and .repository.name == "want-gates" and .repository.owner.login == "andrey-krasheninnikov")] | length')
    [ "$linked" = 1 ] || { echo 'Adapter PR must close issue #12' >&2; exit 1; }
fi
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
    rollback="revert/${branch#feat/}"
    [ "$(git branch --show-current)" = "$rollback" ] && \
        [ -z "$(git status --porcelain)" ] || {
        echo "Use a clean $rollback worktree" >&2
        exit 1
    }
    git revert --no-edit -m 1 "$merge"
fi
