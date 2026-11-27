#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

fail() { printf 'wgates bootstrap: %s\n' "$*" >&2; exit 1; }

mode=${1:-}
case $mode in
    preflight|install) shift ;;
    *) fail 'usage: bootstrap.sh preflight|install [--protocol NAME] [--archive PATH --sha256 HASH]' ;;
esac

archive= digest=
declare -A protocols=() packages=()
while (($#)); do
    (($# >= 2)) || fail 'missing option value'
    case "$1" in
        --archive) [[ -z $archive ]] || fail 'duplicate archive'; archive=$2 ;;
        --sha256) [[ -z $digest ]] || fail 'duplicate SHA-256'; digest=${2,,} ;;
        --protocol)
            case "$2" in
                vless|openvpn|forti|wireguard|netbird) protocols[$2]=1 ;;
                *) fail 'unknown protocol; use vless, openvpn, forti, wireguard or netbird' ;;
            esac ;;
        *) fail 'unknown option' ;;
    esac
    shift 2
done

[[ $(uname -s) == Linux ]] || fail 'Linux and systemd required; see docs/bootstrap.md'
architecture=$(uname -m)
case $architecture in
    x86_64) xray_arch=amd64 ;;
    aarch64) xray_arch=arm64 ;;
    *) fail 'use a Linux x86_64 or aarch64 gateway' ;;
esac
if [[ $mode == install ]]; then
    ((EUID == 0)) || fail 'installation requires root'
    [[ -n $archive ]] || fail 'provide the release archive and its published SHA-256'
fi
trusted() {
    local resolved name owner permissions
    resolved=$(realpath -e -- "$1") || return 1
    for name in "$1" "$resolved"; do
        while [[ $name != / ]]; do
            read -r owner permissions < <(stat -c '%u %a' -- "$name")
            [[ $owner == 0 && $permissions =~ ^[0-7]{3,4}$ ]] || return 1
            [[ -L $name ]] || (((8#$permissions & 022) == 0)) || return 1
            name=$(dirname -- "$name")
        done
    done
}
bounded_version() { timeout --kill-after=1s 5s "$@" </dev/null; }
version_probe() {
    local binary
    if trusted "$1"; then
        binary=$(realpath -e -- "$1") || return 1
        shift
        bounded_version "$binary" "$@"
    else
        "${version_user[@]}" timeout --kill-after=1s 5s "$@" </dev/null
    fi
}

missing_paths=()
need() {
    if [[ ! -x $1 ]]; then
        packages[$2]=1
        missing_paths+=("$1")
    fi
}
check_version() {
    local value
    trusted "$1" || fail "native executable must be controlled by root: $1"
    value=$(version_probe "$1" --version 2>&1) || fail "cannot read $1 version"
    [[ $value =~ $2 ]] || fail "$1 requires $3; install a supported version manually"
}

preflight() {
    [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null || fail 'systemd must be running'
    systemctl is-active --quiet x-ui.service ||
        fail 'start an existing 3x-ui v3.11.0 installation in x-ui.service'
    panel=/usr/local/x-ui
    xray=$panel/bin/xray-linux-$xray_arch
    [[ -x $panel/x-ui && -x $xray ]] ||
        fail 'expected panel and Xray executables under /usr/local/x-ui; see manual steps'
    version_user=()
    if ((EUID == 0)); then
        version_user=(setpriv --reuid 65534 --regid 65534 --clear-groups --no-new-privs)
        panel_pid=$(systemctl show -p MainPID --value x-ui.service)
        [[ $panel_pid =~ ^[1-9][0-9]*$ && $panel/x-ui -ef /proc/$panel_pid/exe ]] ||
            fail 'x-ui.service uses another executable; see manual installation'
        live_xray=0
        for child_list in /proc/"$panel_pid"/task/*/children; do
            [[ -r $child_list ]] || continue
            read -r -a children < "$child_list" || true
            for child in "${children[@]}"; do
                if [[ $xray -ef /proc/$child/exe ]]; then live_xray=1; break 2; fi
            done
        done
        ((live_xray)) || fail 'the panel has not started the expected Xray executable; see manual installation'
    fi
    panel_version=$(version_probe "$panel/x-ui" -v) || fail 'cannot read the panel version'
    [[ $panel_version == 3.11.0 ]] || fail 'bootstrap requires 3x-ui 3.11.0'
    xray_version=$(version_probe "$xray" version) || fail 'cannot read the Xray version'
    read -r product version _ <<< "$xray_version"
    [[ $product == Xray && $version == 26.10.21 ]] || fail 'bootstrap requires Xray 26.10.21'

    distribution=$(sed -nE 's/^ID="?([a-z0-9_-]+)"?$/\1/p' /etc/os-release)
    case $distribution in
        debian|ubuntu) manager=apt; ip_package=iproute2; proc_package=procps; libc_package=libc-bin ;;
        fedora) manager=dnf; ip_package=iproute; proc_package=procps-ng; libc_package=glibc-common ;;
        arch) manager=pacman; ip_package=iproute2; proc_package=procps-ng; libc_package=glibc ;;
        opensuse-leap|opensuse-tumbleweed)
            manager=zypper; ip_package=iproute2; proc_package=procps; libc_package=glibc ;;
        *) manager=manual; ip_package=iproute2; proc_package=procps; libc_package=libc ;;
    esac
    if ! command -v "$manager" >/dev/null || [[ $manager == manual ]]; then manager=manual; fi

    native=0
    if [[ -v protocols[openvpn] || -v protocols[forti] || -v protocols[wireguard] || -v protocols[netbird] ]]; then
        native=1
        trusted "$xray" || fail 'native routing requires a root-controlled Xray executable; see docs/bootstrap.md#optional-native-protocols'
        [[ $(< /proc/sys/net/ipv4/ip_forward) == 1 ]] ||
            fail 'native connections require IPv4 forwarding; configure it before installing'
        need /usr/sbin/ip "$ip_package"
        need /usr/sbin/nft nftables
        need /usr/sbin/sysctl "$proc_package"
        need /usr/bin/getent "$libc_package"
    fi
    if [[ -v protocols[openvpn] || -v protocols[netbird] ]]; then
        [[ -c /dev/net/tun ]] || fail 'OpenVPN and NetBird require /dev/net/tun'
    fi
    if [[ -v protocols[openvpn] ]]; then
        need /usr/sbin/openvpn openvpn
        if [[ -x /usr/sbin/openvpn ]]; then
            check_version /usr/sbin/openvpn '^OpenVPN 2\.6\.' 'OpenVPN 2.6.x'
        fi
    fi
    if [[ -v protocols[forti] ]]; then
        [[ -c /dev/ppp ]] || fail 'Forti requires kernel PPP and /dev/ppp'
        need /usr/sbin/pppd ppp
        need /usr/bin/openfortivpn openfortivpn
        if [[ -x /usr/sbin/pppd ]]; then
            check_version /usr/sbin/pppd '(^| )2\.4\.9($|[[:space:]])' 'pppd 2.4.9'
        fi
        if [[ -x /usr/bin/openfortivpn ]]; then
            check_version /usr/bin/openfortivpn '^1\.(21|22|23|24)(\.|$)' 'openfortivpn 1.21–1.24'
        fi
    fi
    if [[ -v protocols[wireguard] ]]; then
        need /usr/bin/wg wireguard-tools
    fi
    if [[ -v protocols[netbird] ]]; then
        [[ -x /usr/bin/netbird ]] || fail 'install the verified NetBird 0.83.2 client manually; see docs/netbird.md'
        trusted /usr/bin/netbird || fail 'the NetBird client must be controlled by root'
        netbird_version=$(version_probe /usr/bin/netbird version) || fail 'cannot read the NetBird version'
        [[ $netbird_version == 0.83.2 ]] || fail 'NetBird 0.83.2 is required'
        need /usr/bin/curl curl
    fi
    printf 'Platform %s/%s, package manager %s, panel 3.11.0 with Xray 26.10.21\n' \
        "$distribution" "$architecture" "$manager"
    if (( ${#packages[@]} )); then
        printf 'Missing selected executables:'
        printf ' %s' "${missing_paths[@]}"
        printf '\n'
    fi
    if [[ $manager == manual ]]; then
        printf 'Use the manual steps in docs/bootstrap.md for this distribution.\n'
        [[ $mode == preflight ]] || fail 'automatic package installation is unavailable'
    fi
}

workspace=$(mktemp -d /var/tmp/wgates-bootstrap.XXXXXXXX)
root=/var/lib/wgates-install
pending=$root/pending
retired=$root/retired
files=(wgates wgates.service wgates.conf wgates-native.service)
destinations=(/usr/local/bin/wgates /etc/systemd/system/wgates.service /usr/lib/sysusers.d/wgates.conf /etc/systemd/system/wgates-native.service)
units=(wgates.service wgates-native.service)
owns_transaction=0
transaction=

same() {
    [[ -f $1 && ! -L $1 && -f $2 && ! -L $2 ]] || return 1
    [[ $(stat -c '%u:%g:%a' -- "$1") == "$(stat -c '%u:%g:%a' -- "$2")" ]] || return 1
    local left right
    left=$(sha256sum -- "$1") && right=$(sha256sum -- "$2") &&
        [[ ${left%% *} == "${right%% *}" ]]
}
absent() { [[ ! -e $1 && ! -L $1 ]]; }
put() {
    local source=$1 destination=$2
    absent "$destination.wgates-new" || return 1
    cp -p -- "$source" "$destination.wgates-new" &&
        mv -fT -- "$destination.wgates-new" "$destination"
}

wait_ready() {
    local attempt
    for attempt in {1..30}; do
        if systemctl is-active --quiet wgates.service && /usr/local/bin/wgates status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

flush_destinations() {
    local i
    for i in "${!files[@]}"; do
        if [[ -f $pending/new/${files[i]} ]]; then
            sync -f "$(dirname -- "${destinations[i]}")" || return 1
        fi
    done
    sync -f /etc
}

recover() {
    local i file destination unit
    if [[ -f $pending/verified ]]; then
        for i in "${!files[@]}"; do
            file=${files[i]} destination=${destinations[i]}
            if [[ -f $pending/new/$file ]]; then
                same "$destination" "$pending/new/$file" || return 1
            fi
        done
        if ! absent "$root/receipt.wgates-new"; then
            [[ -f $root/receipt.wgates-new && ! -L $root/receipt.wgates-new ]] || return 1
            rm -- "$root/receipt.wgates-new" || return 1
        fi
        put "$pending/receipt" "$root/receipt" || return 1
    else
        for i in "${!files[@]}"; do
            file=${files[i]} destination=${destinations[i]}
            [[ -f $pending/new/$file ]] || continue
            if ! absent "$destination" &&
                ! same "$destination" "$pending/new/$file" &&
                ! same "$destination" "$pending/old/$file"; then
                printf 'Install interrupted. Inspect changed file %s before retrying.\n' "$destination" >&2
                return 1
            fi
            if ! absent "$destination.wgates-new"; then
                if [[ ! -f $destination.wgates-new || -L $destination.wgates-new ]]; then
                    return 1
                fi
                # The transaction claimed this name before copying into it.
                rm -- "$destination.wgates-new" || return 1
            fi
        done
        for unit in "${units[@]}"; do
            [[ -f $pending/new/$unit ]] || continue
            if [[ $(systemctl show -p LoadState --value "$unit") != not-found ]]; then
                systemctl stop "$unit" || return 1
            fi
            if [[ ! -f $pending/enabled/$unit ]] && systemctl is-enabled --quiet "$unit"; then
                systemctl disable "$unit" || return 1
            fi
        done
        for i in "${!files[@]}"; do
            file=${files[i]} destination=${destinations[i]}
            [[ -f $pending/new/$file ]] || continue
            if [[ -f $pending/old/$file ]]; then
                put "$pending/old/$file" "$destination" || return 1
            elif ! absent "$destination"; then
                rm -- "$destination" || return 1
            fi
        done
        systemctl daemon-reload || return 1
        for unit in "${units[@]}"; do
            if [[ -f $pending/active/$unit ]]; then
                systemctl reset-failed "$unit" && systemctl start "$unit" || return 1
            fi
        done
        if [[ -f $pending/active/wgates.service ]]; then wait_ready || return 1; fi
        flush_destinations || return 1
        printf 'Restored the previous wgates files and service state. Package dependencies and persistent data remain installed.\n' >&2
    fi
    mv -T -- "$pending" "$retired" || return 1
    sync -f "$root" || return 1
    rm -rf -- "$retired"
}

cleanup() {
    local result=$?
    trap - EXIT
    if ((owns_transaction)) && [[ -d $pending ]]; then
        recover || { printf 'Reconciliation required at %s before retrying.\n' "$pending" >&2; result=1; }
    fi
    if [[ -n $transaction ]]; then rm -rf -- "$transaction"; fi
    rm -rf -- "$workspace"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

lock_installation() {
    trusted /var/lib || fail 'unsafe /var/lib'
    if absent "$root"; then mkdir -m 0700 -- "$root"; fi
    [[ -d $root && ! -L $root && $(stat -c '%u:%a' "$root") == 0:700 ]] ||
        fail 'unsafe installation directory'
    for destination in "${destinations[@]}"; do
        trusted "$(dirname -- "$destination")" || fail "unsafe destination directory for $destination"
    done
    exec 9>"$root/lock"
    flock -n 9 || fail 'another installation is in progress'
    if ! absent "$retired"; then
        [[ -d $retired && ! -L $retired && $(stat -c '%u:%a' "$retired") == 0:700 ]] ||
            fail 'unsafe retired installation record'
        rm -rf -- "$retired"
    fi
    if ! absent "$pending"; then
        [[ -d $pending && ! -L $pending ]] || fail 'invalid pending installation directory'
        recover || fail 'previous installation could not be reconciled'
    fi
    locked=1
}
locked=0
if [[ $mode == install ]] && ! absent "$root"; then lock_installation; fi
preflight

if [[ -n $archive || -n $digest ]]; then
    [[ -f $archive && $digest =~ ^[a-f0-9]{64}$ ]] || fail 'provide a regular archive and a 64-digit SHA-256'
    cp -- "$archive" "$workspace/release.tar.gz"
    printf '%s  %s\n' "$digest" "$workspace/release.tar.gz" | sha256sum --check --status ||
        fail 'archive checksum mismatch'
    mkdir -- "$workspace/new"
    for file in "${files[@]}" support; do
        tar -xOzf "$workspace/release.tar.gz" -- "$file" > "$workspace/new/$file" ||
            fail 'release archive does not contain the expected files'
        [[ -s $workspace/new/$file ]] || fail 'release archive contains an empty component'
        chmod 0644 "$workspace/new/$file"
    done
    read -r release release_arch < "$workspace/new/support"
    [[ $release =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && $release_arch == "$architecture" ]] ||
        fail 'release archive version or architecture mismatch'
    chmod 0755 "$workspace/new/wgates"
    binary_version=$(bounded_version "$workspace/new/wgates" --version) || fail 'cannot execute the release binary'
    [[ $binary_version == "wgates $release" ]] || fail 'release binary version mismatch'
    printf 'Verified wgates %s release archive for %s\n' "$release" "$architecture"
fi
[[ $mode == install ]] || exit 0

if ((!locked)); then lock_installation; fi

check_identity() {
    local account service_gid service_home service_shell
    account=$(getent passwd wgates) || fail 'missing wgates system account'
    IFS=: read -r _ _ service_uid service_gid _ service_home service_shell <<< "$account"
    [[ $service_uid =~ ^[1-9][0-9]*$ && $service_gid =~ ^[1-9][0-9]*$ &&
        $service_home == /var/lib/wgates && $service_shell == */nologin &&
        $(getent group wgates | cut -d: -f3) == "$service_gid" ]] ||
        fail 'wgates must be an unprivileged system account with its own group'
}
if getent passwd wgates >/dev/null; then
    check_identity
else
    service_uid=
    absent /var/lib/wgates || fail 'inspect the existing state before creating a service account'
    if getent group wgates >/dev/null; then fail 'inspect the existing wgates group before installation'; fi
fi
for directory in /var/lib/wgates /var/lib/wgates-native; do
    absent "$directory" && continue
    owner=$service_uid
    if [[ $directory == /var/lib/wgates-native ]]; then owner=0; fi
    [[ -d $directory && ! -L $directory && $(stat -c '%u:%a' "$directory") == "$owner:700" ]] ||
        fail "unsafe existing state directory: $directory"
done

if (( ${#packages[@]} )); then
    case $manager in
        apt) apt-get update -q ;;
        zypper) zypper --non-interactive refresh ;;
    esac
    candidate_version() {
        case $manager in
            apt) apt-cache policy "$1" | awk '$1=="Candidate:" {print $2}' ;;
            dnf) dnf -q repoquery --latest-limit=1 --qf '%{version}' "$1" ;;
            pacman) pacman -Si "$1" | awk '/^Version *:/ {print $3}' ;;
            zypper) zypper --no-refresh info "$1" | awk '/^Version *:/ {print $3}' ;;
        esac
    }
    for package in "${!packages[@]}"; do
        case $package in
            openvpn) pattern='(^|:)2\.6\.' ;;
            openfortivpn) pattern='(^|:)1\.(21|22|23|24)\.' ;;
            ppp) pattern='(^|:)2\.4\.9($|[-+])' ;;
            *) continue ;;
        esac
        offered=$(candidate_version "$package") || fail "no package candidate for $package"
        [[ $offered =~ $pattern ]] || fail "repositories lack a supported $package; see manual steps"
    done
    case $manager in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -qy --no-install-recommends "${!packages[@]}" ;;
        dnf) dnf -y --setopt=install_weak_deps=False install "${!packages[@]}" ;;
        pacman) pacman -S --noconfirm --needed "${!packages[@]}" ;;
        zypper) zypper --non-interactive install --no-recommends "${!packages[@]}" ;;
    esac
fi
if ((native)); then
    for executable in /usr/sbin/ip /usr/sbin/nft /usr/sbin/sysctl /usr/bin/getent; do
        [[ -x $executable ]] || fail "required executable is absent: $executable"
    done
fi
if [[ -v protocols[openvpn] ]]; then check_version /usr/sbin/openvpn '^OpenVPN 2\.6\.' 'OpenVPN 2.6.x'; fi
if [[ -v protocols[forti] ]]; then
    check_version /usr/sbin/pppd '(^| )2\.4\.9($|[[:space:]])' 'pppd 2.4.9'
    check_version /usr/bin/openfortivpn '^1\.(21|22|23|24)(\.|$)' 'openfortivpn 1.21–1.24'
fi
if [[ -v protocols[wireguard] ]]; then [[ -x /usr/bin/wg ]] || fail 'wireguard-tools did not supply wg'; fi
if [[ -v protocols[netbird] ]]; then [[ -x /usr/bin/curl ]] || fail 'curl is missing'; fi

if ((!native)) && absent "${destinations[3]}"; then
    rm -- "$workspace/new/wgates-native.service"
fi
absent "$root/receipt.wgates-new" || fail 'unexpected installation receipt staging file'
mkdir -- "$workspace/old" "$workspace/active" "$workspace/enabled"
changed=0
for i in "${!files[@]}"; do
    file=${files[i]} destination=${destinations[i]}
    [[ -f $workspace/new/$file ]] || continue
    absent "$destination.wgates-new" || fail "inspect the existing staging file at $destination.wgates-new"
    if ! absent "$destination"; then
        [[ -f $destination && ! -L $destination && $(stat -c %a "$destination") == [0-7][0-7][0-7] ]] &&
            trusted "$destination" ||
            fail "unsafe existing file $destination"
        hash=$(sha256sum -- "$destination")
        if ! same "$destination" "$workspace/new/$file" &&
            ! { [[ -f $root/receipt ]] && grep -Fxq -- "$hash" "$root/receipt"; }; then
            fail "unmanaged file at $destination; reconcile it before installation"
        fi
        cp -p -- "$destination" "$workspace/old/$file"
    fi
    if ! same "$destination" "$workspace/new/$file"; then changed=1; fi
    hash=$(sha256sum -- "$workspace/new/$file")
    printf '%s  %s\n' "${hash%% *}" "$destination" >> "$workspace/receipt"
done
for unit in "${units[@]}"; do
    if systemctl is-active --quiet "$unit"; then touch "$workspace/active/$unit"; fi
    state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    case $state in
        enabled) touch "$workspace/enabled/$unit" ;;
        ''|disabled|not-found) ;;
        *) fail "reconcile $unit enablement ($state) before installation" ;;
    esac
done
rm -- "$workspace/release.tar.gz" "$workspace/new/support"
# Keep the rollback copy on the same filesystem as its final transaction path.
staging=$root/staging
if ! absent "$staging"; then
    [[ -d $staging && ! -L $staging && $(stat -c '%u:%a' "$staging") == 0:700 ]] ||
        fail 'unsafe previous staging directory'
    rm -rf -- "$staging"
fi
mkdir -- "$staging"
transaction=$staging
cp -a -- "$workspace/." "$transaction"
rm -rf -- "$workspace"
mv -T -- "$transaction" "$pending"
transaction=
owns_transaction=1
sync -f "$root"
if ((changed)) && [[ -f $pending/active/wgates.service ]]; then
    systemctl stop wgates.service
fi
for i in "${!files[@]}"; do
    file=${files[i]} destination=${destinations[i]}
    source=$pending/new/$file
    if [[ -f $source ]] && ! same "$destination" "$source"; then put "$source" "$destination"; fi
done
systemd-sysusers /usr/lib/sysusers.d/wgates.conf
check_identity
systemctl daemon-reload
if ((native)); then systemctl enable wgates-native.service; fi
systemctl enable --now wgates.service
if ((!native)) && [[ -f $pending/active/wgates-native.service ]]; then
    systemctl start wgates-native.service
fi
wait_ready || fail 'wgates did not reach control-service readiness'
if ((native)) || [[ -f $pending/active/wgates-native.service ]]; then
    systemctl is-active --quiet wgates-native.service || fail 'native runtime did not start'
fi
flush_destinations
touch "$pending/verified"
sync -f "$root"
recover || fail 'installation succeeded but the receipt needs reconciliation'
owns_transaction=0
printf 'wgates %s is ready. Configure panel API access with wgates panel configure and run wgates panel preflight.\n' "$release"
