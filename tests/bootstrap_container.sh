#!/bin/bash
set -euo pipefail
[[ $# == 4 ]] || { echo 'Usage: bootstrap_container.sh IMAGE SETUP PANEL_DIR ARCHIVE'; exit 1; }
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
image=$1 setup=$2 panel=$(realpath -e -- "$3") archive=$(realpath -e -- "$4")
docker context show
docker system df
df -h -- "$repo"
container=
cleanup() {
    local result=$?
    if [[ -n $container ]]; then
        docker rm -f -v "$container" || result=1
        if docker inspect "$container" >/dev/null 2>&1; then result=1; fi
        docker system df
        df -h -- "$repo"
    fi
    exit "$result"
}
trap cleanup EXIT
container=$(docker run --detach --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
    --label want-gates.fixture=bootstrap --sysctl net.ipv4.ip_forward=1 \
    --mount "type=bind,source=$repo,target=/src,readonly" \
    --mount "type=bind,source=$panel,target=/fixture/panel,readonly" \
    --mount "type=bind,source=$archive,target=/fixture/release.tar.gz,readonly" \
    "$image" /bin/bash -ec "$setup; exec /sbin/init")
for _ in {1..180}; do
    if docker exec "$container" test -d /run/systemd/system 2>/dev/null; then break; fi
    if [[ $(docker inspect "$container" --format '{{.State.Running}}') != true ]]; then
        docker logs "$container"
        exit 1
    fi
    sleep 1
done
if ! docker exec "$container" test -d /run/systemd/system; then
    docker logs "$container"
    exit 1
fi
docker exec "$container" bash -ec '
  if command -v wg >/dev/null; then
    echo "WireGuard tools are already installed in the dependency fixture." >&2
    exit 1
  fi
  bash /src/tests/bootstrap_smoke.sh /fixture/panel /fixture/release.tar.gz wireguard
'
