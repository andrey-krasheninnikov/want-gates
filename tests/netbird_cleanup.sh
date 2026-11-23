#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 [--apply] DOCKER_CONTEXT CONTAINER_ID [CONTAINER_ID ...]" >&2
    exit 2
}

apply=false
if [ "$#" -gt 0 ] && [ "$1" = --apply ]; then
    apply=true
    shift
fi
[ "$#" -ge 2 ] || usage
context=$1
shift

docker_task() {
    docker --context "$context" "$@"
}

for id do
    case "$id" in ''|*[!0-9a-f]*) usage ;; esac
    [ "$(printf '%s' "$id" | wc -c | tr -d ' ')" -eq 64 ] || usage
    actual=$(docker_task container ls -a --no-trunc --filter "id=$id" --format '{{.ID}}')
    if [ -z "$actual" ]; then
        printf '%s already absent\n' "$id"
        continue
    fi
    [ "$actual" = "$id" ] || exit 1
    identity=$(docker_task container inspect --format \
        '{{.Name}} {{index .Config.Labels "want-gates.issue"}}{{range .Mounts}} {{.Type}}:{{.RW}}{{end}}' "$id")
    case "$identity" in
        '/wgates-11-linux 11'|'/wgates-11-linux 11 bind:false'|'/wgates-11-netbird-artifact 11') ;;
        *) echo "Unexpected name, ownership label or mounts for $id" >&2; exit 1 ;;
    esac
    printf '%s %s\n' "$id" "$identity"
    if "$apply"; then
        docker_task container stop "$id" >/dev/null
        docker_task container rm "$id" >/dev/null
        remaining=$(docker_task container ls -a --no-trunc --filter "id=$id" --format '{{.ID}}')
        [ -z "$remaining" ] || exit 1
        printf '%s removed\n' "$id"
    fi
done
