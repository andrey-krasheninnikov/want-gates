#!/usr/bin/env bash
set -euo pipefail
umask 022

fail() { printf '%s\n' "$*" >&2; exit 1; }

[[ $# == 1 ]] || fail 'Usage: packaging/panel/build.sh OUTPUT_DIRECTORY'
[[ $(uname -s) == Linux ]] || fail 'Build 3x-ui on Linux'
case "$(uname -m)" in
    x86_64)
        platform=amd64
        fixture_sha=0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916
        ;;
    aarch64)
        platform=arm64
        fixture_sha=f50b4c30fd919d018f2f4c3d8db53a4ca027503d581328727770afb116a79d90
        ;;
    *) fail 'Supported architectures are x86_64 and aarch64' ;;
esac

export GOTOOLCHAIN=local
[[ $(go env GOVERSION) == go1.27.3 ]] || fail 'Install Go 1.27.3'
[[ $(node --version) == v26.0.0 ]] || fail 'Install Node.js 26.0.0'
command -v musl-gcc >/dev/null || fail 'Install musl-gcc'

panel_version=3.11.0
panel_commit=c621ba9014a6aa21fd7c9ecf45655e44e24ebf13
panel_url=https://github.com/MHSanaei/3x-ui
recipe=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p -- "$1"
output=$(cd -- "$1" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export LC_ALL=C TZ=UTC STORYBOOK_DISABLE_TELEMETRY=1
git init -q "$scratch/upstream"
git -C "$scratch/upstream" fetch -q --depth=1 "$panel_url" "refs/tags/v$panel_version"
[[ $(git -C "$scratch/upstream" rev-parse 'FETCH_HEAD^{commit}') == "$panel_commit" ]] ||
    fail 'Upstream panel tag does not match the expected commit'
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(git -C "$scratch/upstream" show -s --format=%ct "$panel_commit")
mkdir -- "$scratch/source"
git -C "$scratch/upstream" archive "$panel_commit" | tar -xf - -C "$scratch/source"
(
    cd -- "$scratch/source"
    git apply --unidiff-zero --check "$recipe/3x-ui-v3.11.0.patch"
    git apply --unidiff-zero "$recipe/3x-ui-v3.11.0.patch"
)
cp -R -- "$recipe/overlay/." "$scratch/source/"

archive() {
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
        --mode='u+rwX,go+rX,go-w' \
        -C "$1" -cf - -- "$2" | gzip -n > "$3"
}

prefix="3x-ui-$panel_version-want-gates"
archive "$scratch" source "$scratch/$prefix-source.tar.gz"
(
    cd -- "$scratch/source/frontend"
    npm ci --ignore-scripts --no-audit --no-fund >&2
    npm run typecheck >&2
    npm test -- src/test/navigation-contract.test.tsx src/test/want-gates- >&2
    npm run build >&2
)
(
    cd -- "$scratch/source"
    CGO_ENABLED=1 CC=musl-gcc CGO_CFLAGS=-D_LARGEFILE64_SOURCE \
        go test -mod=readonly ./internal/web/controller -run '^TestWantGates' >&2
    CGO_ENABLED=1 CC=musl-gcc CGO_CFLAGS=-D_LARGEFILE64_SOURCE \
        go build -mod=readonly -trimpath -buildvcs=false \
        -ldflags '-w -s -linkmode external -extldflags -static' -o "$scratch/x-ui" .
)
[[ $("$scratch/x-ui" -v) == "$panel_version" ]] || fail 'Built panel version does not match'

fixture="$scratch/upstream-release.tar.gz"
curl --fail --silent --show-error --location --retry 3 --output "$fixture" \
    "$panel_url/releases/download/v$panel_version/x-ui-linux-$platform.tar.gz"
printf '%s  %s\n' "$fixture_sha" "$fixture" | sha256sum --check --strict >&2
mkdir -- "$scratch/package"
tar -xzf "$fixture" -C "$scratch/package"
install -m 0755 -- "$scratch/x-ui" "$scratch/package/x-ui/x-ui"
install -m 0644 -- "$scratch/source/LICENSE" "$scratch/package/x-ui/LICENSE"
archive "$scratch/package" x-ui "$scratch/$prefix-linux-$platform.tar.gz"
install -m 0644 -- "$scratch/$prefix-source.tar.gz" "$scratch/$prefix-linux-$platform.tar.gz" "$output/"
printf '%s\n' "$output/$prefix-linux-$platform.tar.gz"
