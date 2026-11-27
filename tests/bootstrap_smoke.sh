#!/bin/bash
set -euo pipefail
[[ $(uname -s) == Linux && $EUID == 0 && ( $# == 2 || $# == 3 ) ]] ||
    { echo 'Run as root on a disposable Linux systemd host: bootstrap_smoke.sh PANEL_DIR ARCHIVE [wireguard].'; exit 1; }
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
panel=$(realpath -e -- "$1")
archive=$(realpath -e -- "$2")
protocol=()
if [[ ${3:-} == wireguard ]]; then protocol=(--protocol wireguard); fi
release=$(dirname -- "$archive")
(cd "$release" && sha256sum --check --strict SHA256SUMS)
digest=$(awk -v archive="$(basename -- "$archive")" '$2 == archive { hash=$1; count++ } END { if (count != 1) exit 1; print hash }' "$release/SHA256SUMS")
binary=/usr/local/bin/wgates
unit=/etc/systemd/system/wgates.service
fixture_unit=/run/systemd/system/x-ui.service
custom_unit=/run/systemd/system/wgates.service
override_dir=/run/systemd/system/wgates.service.d
custom_wants=/etc/systemd/system/wgates-bootstrap-fixture.target.wants
default_link=/etc/systemd/system/multi-user.target.wants/wgates.service
for owned in /usr/local/x-ui "$fixture_unit" "$custom_unit" "$override_dir" "$custom_wants" "$default_link" "$binary" "$unit" \
    /etc/systemd/system/wgates-native.service /usr/lib/sysusers.d/wgates.conf \
    /var/lib/wgates /var/lib/wgates-install /var/lib/wgates-native; do
    [[ ! -e $owned && ! -L $owned ]] || { echo "Fixture path already exists: $owned"; exit 1; }
done
for service in wgates.service wgates-native.service x-ui.service; do
    [[ $(systemctl show -p LoadState --value "$service") == not-found ]]
done
if getent passwd wgates >/dev/null || getent group wgates >/dev/null; then
    echo 'The fixture requires an unused wgates account and group.' >&2
    exit 1
fi
tmp=$(mktemp -d /var/tmp/wgates-bootstrap-test.XXXXXXXX)
chmod 0755 "$tmp"

cleanup() {
    status=$?
    systemctl disable --now wgates-native.service wgates.service >/dev/null 2>&1 || true
    systemctl stop x-ui.service || true
    rm -f -- "$unit" /etc/systemd/system/wgates-native.service "$fixture_unit" "$custom_unit" "$binary" /usr/lib/sysusers.d/wgates.conf
    rm -rf -- "$override_dir" "$custom_wants"
    systemctl daemon-reload
    rm -rf -- /usr/local/x-ui /var/lib/wgates /var/lib/wgates-install /var/lib/wgates-native "$tmp"
    if getent passwd wgates >/dev/null; then userdel wgates; fi
    if getent group wgates >/dev/null; then groupdel wgates; fi
    [[ ! -e $binary && ! -e /var/lib/wgates && ! -e /usr/local/x-ui && ! -e /run/wgates/control.sock ]]
    exit "$status"
}
trap cleanup EXIT
trap 'echo "Bootstrap smoke failed at line $LINENO." >&2; if [[ -s $tmp/result ]]; then tail -n 18 "$tmp/result" >&2; fi' ERR

script="$tmp/bootstrap.sh"
install -m 0755 -- "$release/bootstrap.sh" "$script"
cp -- "$archive" "$tmp/release.tar.gz"
chmod 0644 "$tmp/release.tar.gz"
archive=$tmp/release.tar.gz
if "$script" preflight >"$tmp/result" 2>&1; then exit 1; fi
grep -q 'existing 3x-ui' "$tmp/result"
if runuser -u nobody -- "$script" install --archive "$archive" --sha256 "$digest" >"$tmp/result" 2>&1; then exit 1; fi
grep -q 'requires root' "$tmp/result"

cp -R --no-preserve=ownership -- "$panel" /usr/local/x-ui
cat >"$fixture_unit" <<'UNIT'
[Unit]
Description=Disposable 3x-ui bootstrap fixture
[Service]
ExecStart=/usr/local/x-ui/x-ui run
WorkingDirectory=/usr/local/x-ui
Environment=XUI_DB_FOLDER=/usr/local/x-ui/acceptance-db
Environment=XUI_LOG_FOLDER=/usr/local/x-ui/acceptance-log
Environment=XUI_BIN_FOLDER=/usr/local/x-ui/bin
Environment=XUI_ENABLE_FAIL2BAN=false
UNIT
cd /usr/local/x-ui
env XUI_DB_FOLDER=/usr/local/x-ui/acceptance-db ./x-ui setting -port 20531 -listenIP 127.0.0.1 >/dev/null
systemctl daemon-reload
systemctl start x-ui.service
panel_pid=$(systemctl show -p MainPID --value x-ui.service)
panel_hash=$(sha256sum /usr/local/x-ui/x-ui)
for _ in {1..50}; do
    if "$script" preflight > "$tmp/result" 2>&1; then break; fi
    sleep 0.2
done
"$script" preflight
if (( ${#protocol[@]} )); then
    xray=$(printf '%s\n' /usr/local/x-ui/bin/xray-linux-*)
    chown 1001:1001 -- "$xray"
    if "$script" preflight "${protocol[@]}" > "$tmp/result" 2>&1; then exit 1; fi
    grep -q 'requires a root-controlled Xray executable' "$tmp/result"
    chown root:root -- "$xray"
    "$script" preflight "${protocol[@]}"
fi
if "$script" install --archive "$archive" --sha256 "$(printf '%064d' 0)" >"$tmp/result" 2>&1; then exit 1; fi
grep -q 'archive checksum mismatch' "$tmp/result"
[[ ! -e $binary && ! -e $unit && ! -e /var/lib/wgates-install/staging && ! -e /var/lib/wgates-install/receipt ]]
printf '[Service]\nExecStart=/usr/bin/true\n' > "$custom_unit"
systemctl daemon-reload
if "$script" install --archive "$archive" --sha256 "$digest" > "$tmp/result" 2>&1; then exit 1; fi
grep -q 'Unmanaged unit wgates.service' "$tmp/result"
[[ -f $custom_unit && ! -e $unit && ! -e $binary ]]
rm -- "$custom_unit"
systemctl daemon-reload
mkdir -m 0700 /var/lib/wgates-install/staging
touch /var/lib/wgates-install/staging/interrupted-copy
"$script" install --archive "$archive" --sha256 "$digest" "${protocol[@]}"
[[ ! -e /var/lib/wgates-install/staging ]]
wgates status
if (( ${#protocol[@]} )); then
    command -v wg >/dev/null
    systemctl is-active --quiet wgates-native.service
    wg_owner=$(stat -c '%u:%g' /usr/bin/wg)
    chown 1001:1001 /usr/bin/wg
    result=0
    "$script" preflight "${protocol[@]}" > "$tmp/result" 2>&1 || result=$?
    chown "$wg_owner" /usr/bin/wg
    [[ $result != 0 ]]
    grep -q 'native executable must be controlled by root: /usr/bin/wg' "$tmp/result"
    systemctl stop wgates-native.service
    if "$script" install --archive "$archive" --sha256 "$digest" > "$tmp/result" 2>&1; then exit 1; fi
    grep -q 'native service is enabled but inactive' "$tmp/result"
    systemctl is-active --quiet wgates.service
    ! systemctl is-active --quiet wgates-native.service
    systemctl start wgates-native.service
fi
wgates group create --name 'Bootstrap example' >/dev/null
wgates group list > "$tmp/groups"
[[ $(stat -c %a /var/lib/wgates) == 700 ]]
[[ $(stat -c %a /run/wgates/control.sock) == 660 ]]
if runuser -u nobody -- wgates status >"$tmp/result" 2>&1; then
    echo 'An unauthorized caller could read the control socket.' >&2
    exit 1
fi
systemctl disable wgates.service
mkdir -- "$custom_wants"
ln -s -- "$unit" "$custom_wants/wgates.service"
systemctl daemon-reload
systemctl is-enabled --quiet wgates.service
service_pid=$(systemctl show -p MainPID --value wgates.service)
"$script" install --archive "$archive" --sha256 "$digest"
[[ $(systemctl show -p MainPID --value wgates.service) == "$service_pid" ]]
[[ -L $custom_wants/wgates.service && ! -e $default_link ]]

mkdir "$tmp/changed"
tar -xzf "$archive" -C "$tmp/changed"
printf '\nBootstrap upgrade fixture\n' >> "$tmp/changed/wgates"
# Use the same member names as the released package.
tar -C "$tmp/changed" -czf "$tmp/upgrade.tar.gz" LICENSE support wgates wgates-native.service wgates.conf wgates.service
upgrade=$(sha256sum -- "$tmp/upgrade.tar.gz")
if (( ${#protocol[@]} )); then
    systemctl disable wgates-native.service
    systemctl is-active --quiet wgates-native.service
fi
chmod 0700 -- "$binary"
"$script" install --archive "$tmp/upgrade.tar.gz" --sha256 "${upgrade%% *}"
cmp -- "$tmp/changed/wgates" "$binary"
[[ $(stat -c %a "$binary") == 755 ]]
wgates group list | cmp - "$tmp/groups"

if (( ${#protocol[@]} )); then
    systemctl is-active --quiet wgates-native.service
    [[ $(systemctl is-enabled wgates-native.service || true) == disabled ]]
    sed -i 's|^ExecStart=.*|ExecStart=/usr/local/bin/wgates unsupported-command|' "$tmp/changed/wgates-native.service"
    tar -C "$tmp/changed" -czf "$tmp/bad-native.tar.gz" LICENSE support wgates wgates-native.service wgates.conf wgates.service
    bad_native=$(sha256sum -- "$tmp/bad-native.tar.gz")
    if "$script" install --archive "$tmp/bad-native.tar.gz" --sha256 "${bad_native%% *}" > "$tmp/result" 2>&1; then exit 1; fi
    grep -q 'Restored the previous wgates files and service state' "$tmp/result"
    systemctl is-active --quiet wgates-native.service
    cmp -- "$repo/packaging/systemd/wgates-native.service" /etc/systemd/system/wgates-native.service
    cp -- "$repo/packaging/systemd/wgates-native.service" "$tmp/changed/wgates-native.service"
fi

# A refused service restart must restore the previous install.
sed -i 's|^ExecStart=.*|ExecStart=/usr/local/bin/wgates unsupported-command|' "$tmp/changed/wgates.service"
tar -C "$tmp/changed" -czf "$tmp/bad.tar.gz" LICENSE support wgates wgates-native.service wgates.conf wgates.service
bad=$(sha256sum -- "$tmp/bad.tar.gz")
if "$script" install --archive "$tmp/bad.tar.gz" --sha256 "${bad%% *}" >"$tmp/result" 2>&1; then exit 1; fi
grep -q 'Restored the previous wgates files and service state' "$tmp/result"
[[ ! -e /var/lib/wgates-install/pending ]]
cmp -- "$repo/packaging/systemd/wgates.service" "$unit"
[[ -L $custom_wants/wgates.service && ! -e $default_link ]]
wgates group list | cmp - "$tmp/groups"

# Interrupt a second attempt after the replacement was staged. The next install
# must reconcile it before making a new persistent change.
"$script" install --archive "$tmp/bad.tar.gz" --sha256 "${bad%% *}" > "$tmp/interrupted" 2>&1 &
installer=$!
for _ in {1..100}; do
    if [[ -d /var/lib/wgates-install/pending ]] && cmp -s "$unit" "$tmp/changed/wgates.service"; then break; fi
    sleep 0.1
done
test -d /var/lib/wgates-install/pending
cmp -s "$unit" "$tmp/changed/wgates.service"
kill -KILL "$installer"
wait "$installer" 2>/dev/null || test "$?" = 137
# Let any in-flight systemd command release the installer's lock.
flock -w 20 /var/lib/wgates-install/lock true
# Recreate the previous live service before testing the unregistered override.
install -m 0644 -- "$repo/packaging/systemd/wgates.service" "$unit"
systemctl daemon-reload
systemctl reset-failed wgates.service 2>/dev/null || true
systemctl start wgates.service
service_pid=$(systemctl show -p MainPID --value wgates.service)
if (( ${#protocol[@]} )); then
    ln -s -- /etc/systemd/system/wgates-native.service "$custom_wants/wgates-native.service"
fi
mkdir -- "$override_dir"
printf '[Service]\nPrivateTmp=yes\n' > "$override_dir/override.conf"
if "$script" install --archive "$archive" --sha256 "$digest" > "$tmp/result" 2>&1; then exit 1; fi
grep -q 'Inspect the overrides for wgates.service' "$tmp/result"
[[ -f $override_dir/override.conf && -d /var/lib/wgates-install/pending ]]
[[ $(systemctl show -p MainPID --value wgates.service) == "$service_pid" ]]
wgates group list | cmp - "$tmp/groups"
rm -- "$override_dir/override.conf"
rmdir -- "$override_dir"
systemctl daemon-reload
[[ $(systemctl show -p MainPID --value x-ui.service) == "$panel_pid" ]]
systemctl stop x-ui.service
if "$script" install --archive "$archive" --sha256 "$digest" > "$tmp/result" 2>&1; then exit 1; fi
grep -q 'Restored the previous wgates files and service state' "$tmp/result"
grep -q 'start an existing 3x-ui' "$tmp/result"
[[ ! -e /var/lib/wgates-install/pending ]]
if (( ${#protocol[@]} )); then
    [[ -L $custom_wants/wgates-native.service ]]
fi
wgates group list | cmp - "$tmp/groups"
systemctl start x-ui.service
for _ in {1..50}; do
    if "$script" preflight > "$tmp/result" 2>&1; then break; fi
    sleep 0.2
done
"$script" install --archive "$archive" --sha256 "$digest"
[[ $(sha256sum /usr/local/x-ui/x-ui) == "$panel_hash" ]]
printf 'Bootstrap preflight, archive rejection, permissions, install, repeat, upgrade and recovery passed on %s.\n' "$(uname -m)"
