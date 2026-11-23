#!/usr/bin/env python3
"""Exercise native WireGuard with real 3x-ui and VLESS on the routing stand."""
import json
from pathlib import Path
import sys
import time

import routing_smoke as stand


def acceptance(context):
    ns, control = context['ns'], context['control']
    prefix, work = context['prefix'], context['work']
    unit = Path('/run/systemd/system') / f'{prefix}-native.service'
    state = Path('/var/lib') / f'{prefix}-native'
    runtime = Path('/run') / f'{prefix}-native'
    assert not any(p.exists() or p.is_symlink() for p in (unit, state, runtime))
    secrets = []

    def data(*args, **kwargs):
        result = json.dumps(control(*args, **kwargs))
        assert all(secret not in result for secret in secrets), 'WireGuard key in public output'
        return json.loads(result)['data']

    def apply():
        return data('routing', 'apply', data('routing', 'preview')['plan_id'])

    def key(command, value=None):
        result = stand.checked('wg', command, input=None if value is None else value + '\n')
        return result.stdout.strip()

    def provision(peer, slot, port, snat4, snat6):
        address = f'10.250.0.{slot}'
        address6 = f'fd42:250::{slot}'
        private, server, shared = (key(cmd) for cmd in ('genkey', 'genkey', 'genpsk'))
        secrets.extend((private, server, shared))
        device = f'wgtest{port}'
        ns(peer, 'ip', 'link', 'add', 'dev', device, 'type', 'wireguard')
        ns(peer, 'wg', 'setconf', device, '/dev/stdin', input=(
            f'[Interface]\nPrivateKey = {server}\nListenPort = {port}\n'
            f'[Peer]\nPublicKey = {key("pubkey", private)}\nPresharedKey = {shared}\n'
            f'AllowedIPs = {address}/32, {address6}/128\n'
        ))
        ns(peer, 'ip', 'link', 'set', device, 'up')
        ns(peer, 'ip', 'route', 'add', f'{address}/32', 'dev', device)
        ns(peer, 'ip', '-6', 'route', 'add', f'{address6}/128', 'dev', device)
        ns(peer, 'nft', '-f', '-', input=(
            f'table inet wgtest{port} {{ chain nat {{ type nat hook postrouting priority srcnat; '
            f'iifname "{device}" ip saddr {address} snat ip to {snat4}; '
            f'iifname "{device}" ip6 saddr {address6} snat ip6 to {snat6}; }}; }}\n'
        ))
        endpoint = '10.213.0.2' if peer == 'a' else '[fd42:214::2]'
        return (
            f'[Interface]\nPrivateKey = {private}\nAddress = {address}/32, {address6}/128\n'
            f'DNS = 10.220.0.10\nMTU = 1380\n[Peer]\nPublicKey = {key("pubkey", server)}\n'
            f'PresharedKey = {shared}\nEndpoint = {endpoint}:{port}\nAllowedIPs = 0.0.0.0/0, ::/0\n'
        )

    def tcp(address, marker, source=None):
        result = stand.run(
            'ip', 'netns', 'exec', context['names']['client'], 'curl', '--noproxy', '',
            '--socks5-hostname', '127.0.0.1:10880', '--max-time', '4', '-fsS',
            f'http://{address}:18080/{marker}',
        )
        if source is None:
            assert result.returncode != 0, 'blocked TCP reached the resource'
        else:
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)['peer'] == source, result.stdout

    def udp(port, marker, answer=None):
        result = stand.run(
            'ip', 'netns', 'exec', context['names']['client'], 'python3',
            str(stand.__file__), '--udp', str(port), marker,
        )
        if answer is None:
            assert result.returncode != 0, 'blocked UDP reached the resource'
        else:
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)['answer'] == answer, result.stdout

    def inventory():
        records = (json.loads(path.read_text()) for path in state.glob('*.json'))
        return {record['prepared']['id']: record for record in records}

    for name in ('gateway', 'a', 'b'):
        ns(name, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    ns('a', 'ip', 'address', 'add', '10.211.0.3/24', 'dev', 'w4211a')
    ns('a', 'ip', '-6', 'address', 'add', 'fd42:211::3/64', 'dev', 'w4211a', 'nodad')
    profiles = {
        'primary': provision('a', 2, 51821, '10.211.0.1', 'fd42:211::1'),
        'reserve': provision('a', 3, 51822, '10.211.0.3', 'fd42:211::3'),
        'other': provision('b', 2, 51823, '10.212.0.1', 'fd42:212::1'),
    }
    ns('resource', 'nft', '-f', '-', input=(
        'table inet wgtest_dns { chain dns { type nat hook prerouting priority dstnat; '
        'ip daddr 10.220.0.10 udp dport 53 dnat ip to 10.220.0.10:15353; '
        'ip daddr 10.221.0.10 udp dport 53 dnat ip to 10.221.0.10:15353; }; }\n'
    ))
    baseline = [ns('gateway', 'ip', family, 'route', 'show', 'default').stdout
                for family in ('-4', '-6')]
    template = (Path(__file__).resolve().parents[1] / 'packaging/systemd/wgates-native.service').read_text()
    template = template.replace('wgates', prefix).replace(
        '[Service]', '[Service]\nNetworkNamespacePath=/run/netns/' + context['names']['gateway']
    )
    template = '\n'.join(
        f'{line} --xray-bin {context["xray"]}' if line.startswith(('ExecStart=', 'ExecStopPost=')) else line
        for line in template.splitlines()
    ) + '\n'
    try:
        with unit.open('x') as file:
            file.write(template)
        stand.checked('systemd-analyze', 'verify', str(unit))
        stand.checked('systemctl', 'daemon-reload')
        stand.checked('systemctl', 'start', unit.name)

        a = data('group', 'create', '--name', 'WireGuard A')['id']
        b = data('group', 'create', '--name', 'WireGuard B')['id']
        primary = data('connection', 'import', '--group', a, '--name', 'Primary',
                       '--protocol', 'wireguard', '--file', '-', payload=profiles['primary'])['id']
        reserve = data('connection', 'import', '--group', a, '--name', 'Reserve',
                       '--protocol', 'wireguard', '--file', '-', payload=profiles['reserve'])['id']
        other = data('connection', 'import', '--group', b, '--name', 'Other',
                     '--protocol', 'wireguard', '--file', '-', '--dns', 'udp://10.221.0.10:53',
                     payload=profiles['other'])['id']

        def probes(index, label):
            v4, v6 = f'10.{index}.0.10', f'fd42:{index}::10'
            return dict(
                tcp_ipv4=dict(url=f'http://{v4}:18080/probe'),
                tcp_ipv6=dict(url=f'http://[{v6}]:18080/probe'),
                udp_ipv4=dict(server=f'{v4}:15353', query_name='probe.example.test', query_type='A'),
                udp_ipv6=dict(server=f'[{v6}]:15353', query_name='probe.example.test', query_type='AAAA'),
                dns=dict(query_name=f'v4.{label}.corp.test', query_type='A'),
            )

        capabilities = {'tcp_ipv4', 'udp_ipv4', 'tcp_ipv6', 'udp_ipv6'}
        data('group', 'update', a, '--primary', primary, '--fallbacks', reserve,
             '--healthcheck-file', '-', payload=dict(
                 target='http://health.a.corp.test:18080/health', required_capabilities=sorted(capabilities),
                 interval_seconds=1, timeout_seconds=1, failure_threshold=2, recovery_threshold=2,
             ))
        data('group', 'update', a, '--probe-file', '-', payload=probes(220, 'a'))
        data('group', 'update', b, '--primary', other, '--probe-file', '-', payload=probes(221, 'b'))
        for group, index, label in ((a, 220, 'a'), (b, 221, 'b')):
            for destination in (f'10.{index}.0.0/24', f'fd42:{index}::/64', f'{label}.corp.test'):
                data('rule', 'create', '--group', group, '--destination', destination)

        for key in ('net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding'):
            assert ns('gateway', 'sysctl', '-n', key).stdout.strip() == '1', key
        protected_endpoint = profiles['primary'].replace('10.213.0.2:51821', 'peer.a.corp.test:51821')
        data('connection', 'update', primary, '--file', '-', payload=protected_endpoint)
        refused = control('routing', 'preview', success=False)
        assert 'WireGuard peer name overlaps a protected domain' in refused.stderr
        data('connection', 'update', primary, '--file', '-', payload=profiles['primary'])
        applied = apply()
        assert applied['state'] == 'applied', applied
        for connection, dns in ((primary, '10.220.0.10'), (other, '10.221.0.10')):
            shown = data('connection', 'show', connection)
            assert shown['authentication'] == 'configured', shown
            assert set(shown['capabilities']) == capabilities | {'dns'}, shown
            assert shown['effective_dns'] == f'udp://{dns}:53'
        tcp('10.220.0.10', 'wireguard-ipv4', '10.211.0.1')
        tcp('[fd42:220::10]', 'wireguard-ipv6', 'fd42:211::1')
        udp(15354, 'wireguard-v4.example.test', '198.18.1.1')
        udp(15356, 'wireguard-v6.example.test', '198.18.1.1')
        tcp('v4.a.corp.test', 'wireguard-dns-a', '10.211.0.1')
        tcp('v4.b.corp.test', 'wireguard-dns-b', '10.212.0.1')
        tcp('public.v4.a.corp.test', 'wireguard-shared-destination-a', '10.211.0.1')
        tcp('public.v4.b.corp.test', 'wireguard-shared-destination-b', '10.212.0.1')
        records = inventory()
        assert set(records) == {primary, reserve, other}
        assert len({record['namespace'] for record in records.values()}) == 3
        print('WireGuard IPv4/IPv6 TCP and UDP, shared destination and private DNS passed', flush=True)

        def selected(expected):
            deadline = time.monotonic() + 45
            while True:
                report = data('routing', 'status')['health']
                assert not report['error'], report
                group = next(item for item in report['groups'] if item['group_id'] == a)
                if group['selected_connection'] == expected:
                    return
                assert time.monotonic() < deadline, group
                time.sleep(0.2)

        def resource_failure(*sources):
            pending = work / 'health-failures.tmp'
            pending.write_text(json.dumps(sources))
            pending.replace(work / 'health-failures.json')

        selected(primary)
        resource_failure('10.211.0.1')
        selected(reserve)
        tcp('v4.a.corp.test', 'wireguard-fallback', '10.211.0.3')
        resource_failure('10.211.0.1', '10.211.0.3')
        selected(None)
        tcp('10.220.0.10', 'wireguard-denied-tcp')
        udp(15360, 'wireguard-denied-dns.a.corp.test')
        tcp('v4.b.corp.test', 'wireguard-independent', '10.212.0.1')
        tcp('1.1.1.1', 'wireguard-direct', '10.210.0.1')
        assert 'wireguard-denied' not in context['events'].read_text()
        resource_failure()
        selected(primary)
        tcp('v4.a.corp.test', 'wireguard-failback', '10.211.0.1')

        original = data('connection', 'show', other)['native_runtime']['session']
        records = inventory()
        data('connection', 'restart', other)
        restarted = data('connection', 'show', other)
        assert restarted['native_runtime']['session'] != original
        assert not restarted['capabilities'], restarted
        assert inventory()[other]['namespace_identity'] != records[other]['namespace_identity']
        assert inventory()[primary]['namespace_identity'] == records[primary]['namespace_identity']
        tcp('10.221.0.10', 'wireguard-denied-restart')
        assert 'wireguard-denied-restart' not in context['events'].read_text()
        apply()
        tcp('v4.b.corp.test', 'wireguard-recovered', '10.212.0.1')

        data('connection', 'update', other, '--capabilities', 'tcp_ipv4,udp_ipv4')
        apply()
        result = data('connection', 'verify', other)['verification']['capabilities']
        assert result['tcp_ipv6']['reason'] == 'configured_limit', result
        tcp('[fd42:221::10]', 'wireguard-denied-ipv6')
        udp(15357, 'wireguard-denied-udp6.example.test')
        assert 'wireguard-denied' not in context['events'].read_text()

        previous = inventory()[other]
        data('group', 'update', b, '--primary', '-')
        data('connection', 'delete', other)
        apply()
        assert not (Path('/run/netns') / previous['namespace']).exists()
        assert other not in inventory() and primary in inventory()
        assert previous['interface'] not in ns('gateway', 'ip', 'link', 'show').stdout
        assert previous['prepared']['generation'] not in ns('gateway', 'nft', 'list', 'tables').stdout
        assert baseline == [ns('gateway', 'ip', family, 'route', 'show', 'default').stdout
                            for family in ('-4', '-6')]
        assert context['api']('server/status')['xray']['state'] == 'running'
        print('WireGuard failover, failback, fail-closed traffic and owned cleanup passed', flush=True)
    finally:
        if unit.exists():
            stand.checked('systemctl', 'stop', unit.name)
            unit.unlink()
            stand.checked('systemctl', 'daemon-reload')
        if state.exists():
            for record in inventory().values():
                assert not (Path('/run/netns') / record['namespace']).exists()
                assert record['prepared']['generation'] not in ns('gateway', 'nft', 'list', 'tables').stdout
            for path in state.glob('*.json'):
                path.unlink()
            state.rmdir()
        assert not runtime.exists()


if __name__ == '__main__':
    stand.main(sys.argv[1], sys.argv[2], native_acceptance=acceptance)
