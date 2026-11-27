#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 ]] || { printf 'Usage: package.sh BINARY OUTPUT_DIR\n' >&2; exit 1; }
here=$(cd -- "$(dirname -- "$0")" && pwd)
binary=$(realpath -- "$1")
architecture=$(uname -m)
[[ $(uname -s) == Linux && $architecture =~ ^(x86_64|aarch64)$ ]] ||
    { printf 'Package on the target Linux architecture.\n' >&2; exit 1; }
read -r product version < <("$binary" --version)
[[ $product == wgates && $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
mkdir -p -- "$2"
output=$(realpath -- "$2")
stage=$(mktemp -d -t wgates-package.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
install -m 0755 -- "$binary" "$stage/wgates"
install -m 0644 -- "$here/systemd/"*.service "$here/sysusers.d/wgates.conf" "$here/../LICENSE" "$stage/"
printf '%s %s\n' "$version" "$architecture" > "$stage/support"
name=wgates-v$version-linux-$architecture.tar.gz
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$stage" \
    -czf "$output/$name" LICENSE support wgates wgates-native.service wgates.conf wgates.service
(cd -- "$output" && sha256sum -- "$name" > "$name.sha256")
printf '%s\n' "$output/$name"
