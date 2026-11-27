#!/usr/bin/env python3
"""Run the supported NetBird adapter through wgates, systemd and 3x-ui."""
import argparse
from contextlib import ExitStack
from html.parser import HTMLParser
from http.cookiejar import CookieJar
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, HTTPSHandler, ProxyHandler, build_opener

import netbird_smoke as fixture
import routing_smoke as stand


def complete_device_login(certificate):
    supplied = json.load(sys.stdin)
    url = supplied["url"]
    origin = urlsplit(supplied['origin']).netloc

    def same_origin(target):
        parsed = urlsplit(target)
        return parsed.scheme == 'https' and parsed.netloc == origin

    class Redirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not same_origin(newurl):
                raise RuntimeError('unexpected test IdP redirect')
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    class Page(HTMLParser):
        def __init__(self):
            super().__init__()
            self.form = None
            self.forms = []
            self.local_login = None

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == 'form' and attrs.get('method', '').lower() == 'post':
                self.form = (attrs.get('action', ''), {})
                self.forms.append(self.form)
            if tag == 'input' and self.form and attrs.get('name'):
                self.form[1][attrs['name']] = attrs.get('value', '')
            if tag == 'a' and urlsplit(attrs.get('href', '')).path.endswith('/auth/local'):
                self.local_login = attrs['href']

        def handle_endtag(self, tag):
            if tag == 'form':
                self.form = None

    opener = build_opener(ProxyHandler({}), Redirect(), HTTPCookieProcessor(CookieJar()),
                          HTTPSHandler(context=ssl.create_default_context(cafile=certificate)))
    body = None
    for step in range(1, 7):
        if not same_origin(url):
            raise RuntimeError('unexpected test IdP form origin')
        try:
            with opener.open(url, body, timeout=8) as response:
                url = response.geturl()
                html = response.read(256 * 1024).decode()
        except HTTPError as error:
            raise RuntimeError(f'test IdP HTTP {error.code} at step {step}') from None
        except URLError:
            raise RuntimeError(f'test IdP TLS or transport error at step {step}') from None
        if urlsplit(url).path == '/oauth2/device/callback':
            return
        page = Page()
        page.feed(html)
        for action, fields in page.forms:
            if 'user_code' in fields:
                fields['user_code'] = supplied['code']
            elif 'login' in fields and 'password' in fields:
                fields.update(login=supplied['email'], password=supplied['password'])
            elif fields.get('approval') != 'approve':
                continue
            url = urljoin(url, action)
            body = urlencode(fields).encode()
            break
        else:
            if not page.local_login:
                path = urlsplit(url).path
                phase = next((name for name in ('device', 'callback', 'auth', 'approval')
                              if f'/{name}' in path), 'other')
                raise RuntimeError(f'expected test IdP form at step {step} ({phase})')
            url = urljoin(url, page.local_login)
            body = None
    raise RuntimeError('test IdP sign-in did not finish')


def acceptance(context, client, server, geodata):
    ns, control = context['ns'], context['control']
    prefix = context['prefix']
    state = Path('/var/lib') / f'{prefix}-native'
    runtime = Path('/run') / f'{prefix}-native'
    unit = Path('/run/systemd/system') / f'{prefix}-native.service'
    assert not any(p.exists() or p.is_symlink() for p in (unit, state, runtime))

    for option in ('net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1'):
        ns('gateway', 'sysctl', '-qw', option)
    ns('gateway', 'ip', '-4', 'route', 'add', 'default', 'via', '10.210.0.2')
    ns('gateway', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd42:210::2')

    def management():
        assert context['api']('server/status')['xray']['state'] == 'running'
        return tuple(ns('gateway', 'ip', family, '-j', *args).stdout
                     for family in ('-4', '-6')
                     for args in (('rule', 'list'), ('route', 'show', 'default')))

    default_route = management()
    control_files = [path for path in map(Path, ('/etc/hosts', '/etc/resolv.conf',
                                                 '/etc/iproute2/rt_tables')) if path.is_file()]
    original_files = [path.read_bytes() for path in control_files]
    redacted = []

    def data(*args, **kwargs):
        value = control(*args, **kwargs)['data']
        encoded = json.dumps(value)
        assert all(secret not in encoded for secret in redacted), 'NetBird secret leaked'
        return value

    def apply():
        return data('routing', 'apply', data('routing', 'preview')['plan_id'])

    def vless(*args):
        return stand.run('ip', 'netns', 'exec', context['names']['client'], *map(str, args), timeout=12)

    def tcp(target, marker):
        return vless('curl', '--noproxy', '', '--socks5-hostname', '127.0.0.1:10880',
                     '--max-time', '4', '-fsS', f'http://{target}:18080/{marker}')

    def udp(port, marker):
        return vless(sys.executable, stand.__file__, '--udp', port, marker)

    def observed(path, marker):
        return path.exists() and marker in path.read_text()

    def packet(result, marker, company=None, expected=None):
        if company is None:
            no_dns_answer = expected is not None and result.returncode == 0 and \
                json.loads(result.stdout)['answer'] is None
            assert result.returncode != 0 or no_dns_answer, 'protected traffic escaped'
        else:
            assert result.returncode == 0, f'{company.name} traffic timed out'
            value = json.loads(result.stdout)
            if expected is None:
                assert value['company'] == company.name, 'wrong TCP destination'
            else:
                assert value['answer'] == expected, 'wrong UDP destination'
            assert observed(company.events, marker), 'expected company witness missing'
        assert not observed(context['events'], marker), 'protected traffic reached direct witness'
        for other in companies:
            if other is not company:
                assert not observed(other.events, marker), 'traffic reached a different company'

    def traffic(company, mode, allowed=True):
        label = company.name

        def positive(description, probe, marker):
            def attempt():
                result = probe()
                assert not observed(context['events'], marker), 'protected traffic reached direct witness'
                for other in companies:
                    if other is not company:
                        assert not observed(other.events, marker), 'traffic reached a different company'
                return result
            return fixture.wait_for(description, attempt, lambda result: result.returncode == 0,
                                    seconds=15) if allowed else attempt()

        for family in (4, 6):
            marker = secrets.token_hex(12)
            name = fixture.host(mode, family, label)
            result = positive(f'{label} {mode} TCP IPv{family}', lambda: tcp(name, marker), marker)
            packet(result, marker, company if allowed else None)
            marker = secrets.token_hex(12) + '.payload.test'
            port = fixture.UDP_TARGETS[mode, family, label]
            result = positive(f'{label} {mode} UDP IPv{family}', lambda: udp(port, marker), marker)
            packet(result, marker, company if allowed else None,
                   f'198.18.{fixture.COMPANIES.index(label) + 1}.1')

    def protected_dns(company, allowed=True):
        marker = secrets.token_hex(12)
        name = f'{marker}.who.private.v4.{company.name}.corp.test'
        result = vless(sys.executable, stand.__file__, '--dns-query', 'udp', name, '1')
        packet(result, marker, company if allowed else None,
               f'198.18.{fixture.COMPANIES.index(company.name) + 1}.1')

    def direct_path():
        for destination, peer, (port, _) in zip(
            fixture.EXIT, ('10.210.0.1', 'fd42:210::1'), fixture.DIRECT_UDP, strict=True
        ):
            marker = secrets.token_hex(12)
            host = f'[{destination}]' if ':' in destination else destination
            result = tcp(host, marker)
            assert result.returncode == 0 and json.loads(result.stdout)['peer'] == peer
            assert observed(context['events'], marker)
            marker = secrets.token_hex(12) + '.payload.test'
            result = udp(port, marker)
            assert result.returncode == 0 and json.loads(result.stdout)['answer'] == '198.18.0.1'
            assert observed(context['events'], marker)

    def observations(connection):
        return data('connection', 'show', connection)['native_runtime']

    def enrollment(company, connection, device=False):
        status = lambda: observations(connection)
        fixture.wait_for('NetBird ready for enrollment', status,
                         lambda v: v['authentication'] == 'credentials_required')
        existing_peers = {peer['id'] for peer in company.api('/peers')}
        if device:
            data('connection', 'login', connection)
            fixture.wait_for('NetBird device challenge', status,
                             lambda v: v['authentication'] == 'browser_required')
            action = data('connection', 'login', connection)
            assert action['method'] == 'web' and action['expires_at'] > time.time()
            redacted.extend((action['url'], action['user_code'], company.password))
            status()
            o = stand.run(
                'ip', 'netns', 'exec', context['names']['gateway'], sys.executable, '-B', __file__,
                '--device-login', str(company.work / 'cert.pem'),
                input=json.dumps(dict(url=action['url'], origin=company.url, email=company.email,
                                      password=company.password, code=action['user_code'])),
                timeout=30,
            )
            if o.returncode:
                details = o.stderr.splitlines()[-1] if o.stderr.splitlines() else ''
                if details.startswith('RuntimeError: ') and 'test IdP' in details:
                    raise RuntimeError(details.removeprefix('RuntimeError: '))
                raise RuntimeError('test device authorization did not complete')
        else:
            setup_key = company.setup_key(f'gateway-{connection}-{secrets.token_hex(4)}')
            redacted.append(setup_key)
            data('connection', 'login', connection, '--file', '-', payload=dict(setup_key=setup_key))
        peer = fixture.wait_for('enrolled NetBird peer', lambda: next((
            peer for peer in company.api('/peers') if peer['id'] not in existing_peers
            and peer['name'].startswith(f'wgates-{connection}-')
        ), None))
        mode = next(mode for mode, identifier in company.connections.items() if identifier == connection)
        company.api(f'/groups/{company.route_groups[mode]}',
                    dict(name=f'Want Gates {mode}', peers=[peer['id']]), method='PUT')
        try:
            fixture.wait_for(f'{company.name} NetBird login', status,
                             lambda v: v['authentication'] == 'authenticated')
        except RuntimeError:
            raise RuntimeError(f'{company.name} auth status: {status()["reason"]}') from None

    def selected(company, expected):
        def current():
            health = data('routing', 'status')['health']
            assert not health['error'], health['error']
            return next(group for group in health['groups'] if group['group_id'] == company.group)

        return fixture.wait_for(
            f'{company.name} selection {expected}', current,
            lambda health: health['selected_connection'] == expected
            and (expected is None or observations(expected)['admitted']), seconds=75,
        )

    def inventory():
        records = (json.loads(file.read_text()) for file in state.glob('*.json'))
        return {record['prepared']['id']: record for record in records}

    with ExitStack() as cleanup:
        companies = [fixture.Company(context, name, None, client, server, geodata, cleanup)
                     for name in fixture.COMPANIES]
        for company in companies:
            company.api(f'/networks/{company.private_network}/resources', dict(
                name='Domain resource', address=f'unused.{company.name}.invalid',
                enabled=True, groups=[company.resource_group]))
        legacy_profiles = {}
        for name in ('netbird/config.json', 'wiretrustee/config.json', 'ssh/ssh_config.d/99-netbird.conf'):
            config = Path('/etc') / name
            directory = config.parent
            for parent in reversed([p for p in directory.parents if not p.exists()]):
                parent.mkdir(mode=0o700)
                cleanup.callback(parent.rmdir)
            if not directory.exists():
                directory.mkdir(mode=0o700)
                cleanup.callback(directory.rmdir)
            marker = f'# {name} host configuration must stay isolated'.encode()
            with config.open('xb') as file:
                file.write(marker)
            cleanup.callback(config.unlink)
            legacy_profiles[config] = marker
        # Trust the two disposable lab certificates for the duration of this test.
        cleanup.callback(stand.checked, 'update-ca-certificates', '--fresh')
        for company in companies:
            ca = Path('/usr/local/share/ca-certificates') / f'{prefix}-{company.name}.crt'
            with ca.open('xb') as output, (company.work / 'cert.pem').open('rb') as source:
                shutil.copyfileobj(source, output)
            cleanup.callback(ca.unlink)
        stand.checked('update-ca-certificates')

        def remove_unit():
            stand.checked('systemctl', 'stop', unit.name)
            unit.unlink()
            stand.checked('systemctl', 'daemon-reload')
            if state.exists():
                for record in inventory().values():
                    assert not (Path('/run/netns') / record['namespace']).exists()
                    assert record['prepared']['generation'] not in ns('gateway', 'nft', 'list', 'tables').stdout
                shutil.rmtree(state)
            assert not runtime.exists()

        template = (Path(__file__).resolve().parents[1] / 'packaging/systemd/wgates-native.service').read_text()
        template = template.replace('wgates', prefix).replace(
            '[Service]', f'[Service]\nNetworkNamespacePath=/run/netns/{context["names"]["gateway"]}')
        text = '\n'.join(
            f'{line} --xray-bin {context["xray"]} --netbird-bin {client}'
            if line.startswith(('ExecStart=', 'ExecStopPost=')) else line
            for line in template.splitlines()
        ) + '\n'
        with unit.open('x') as file:
            file.write(text)
        cleanup.callback(remove_unit)
        stand.checked('systemd-analyze', 'verify', str(unit))
        stand.checked('systemctl', 'daemon-reload')
        stand.checked('systemctl', 'start', unit.name)
        apply()
        direct_path()

        for company in companies:
            label = company.name
            company.group = data('group', 'create', '--name', f'Company {label}')['id']
            company.connections = {}
            for mode in ('private', 'exit'):
                profile = dict(management_url=company.url, mode=mode, control_endpoints=[
                    dict(host=company.ip, port=18443, transport='udp')
                ])
                if mode == 'exit':
                    profile['exit_network_id'] = 'exit'
                company.connections[mode] = data(
                    'connection', 'import', '--group', company.group, '--name', f'NetBird {mode}',
                    '--protocol', 'netbird', '--file', '-', '--dns', f'udp://{fixture.PRIVATE[0]}:15353',
                    payload=profile,
                )['id']
            v4, v6 = fixture.PRIVATE
            probes = dict(
                tcp_ipv4=dict(url=f'http://{v4}:18080/probe'),
                tcp_ipv6=dict(url=f'http://[{v6}]:18080/probe'),
                udp_ipv4=dict(server=f'{v4}:15353', query_name='probe.example.test', query_type='A'),
                udp_ipv6=dict(server=f'[{v6}]:15353', query_name='probe.example.test', query_type='A'),
                dns=dict(query_name=f'probe.private.v4.{label}.corp.test', query_type='A'),
            )
            group = company.group
            data('group', 'update', group, '--probe-file', '-', payload=probes)
            data('group', 'update', group, '--primary', company.connections['private'],
                 '--fallbacks', company.connections['exit'], '--healthcheck-file', '-', payload=dict(
                     target=f'http://private.v4.{label}.corp.test:18080/health',
                     required_capabilities=sorted(fixture.CAPABILITIES),
                     interval_seconds=2, timeout_seconds=2, failure_threshold=2, recovery_threshold=2,
                 ))
            data('rule', 'create', '--group', group, '--destination', f'{label}.corp.test')

        apply()
        for company in companies:
            private = company.connections['private']
            enrollment(company, private)
            selected(company, private)
            previous_session = observations(private)['session']
            enrollment(company, company.connections['exit'], device=company.name == 'b')
            selected(company, private)
            assert observations(private)['session'] == previous_session, 'unchanged route lost its admission'
        for company in companies:
            selected(company, company.connections['private'])
        records = inventory()
        assert len(records) == 4 and len({record['namespace'] for record in records.values()}) == 4
        for company in companies:
            generation = records[company.connections['exit']]['prepared']['generation']
            socket = runtime / generation / 'netbird' / 'json.sock'
            response = stand.checked('curl', '--disable', '--silent', '--show-error', '--fail',
                                     '--noproxy', '*', '--max-time', '5', '--unix-socket', str(socket),
                                     '--header', 'Content-Type: application/json', '--data', '{}',
                                     'http://localhost/daemon.DaemonService/ListNetworks')
            assert {route['ID'] for route in json.loads(response.stdout)['routes']} == {'exit'}
            traffic(company, 'private')
            protected_dns(company)
            traffic(company, 'exit', allowed=False)
        print('Two private groups passed TCP, UDP, IPv4, IPv6 and protected DNS', flush=True)

        a, b = companies
        for company in companies:
            data('connection', 'logout', company.connections['private'])
            selected(company, company.connections['exit'])
            traffic(company, 'exit')
            protected_dns(company)
            if company is a:
                traffic(b, 'private')
                traffic(b, 'exit', allowed=False)
        print('Both exit nodes passed and failed over within their own groups', flush=True)

        control_unit = f'{prefix}.service'

        def control_pid():
            return int(stand.checked('systemctl', 'show', '--property=MainPID',
                                     '--value', control_unit).stdout)

        initial_pid = control_pid()
        assert initial_pid > 0
        for restarted_unit in (unit.name, control_unit):
            previous = observations(b.connections['exit'])['session']
            stand.checked('systemctl', 'restart', restarted_unit)
            fixture.wait_for('restarted control socket', lambda: stand.run(
                str(context['installed']), 'status', '--socket', f'/run/{prefix}/control.sock'
            ).returncode == 0)
            if restarted_unit == unit.name:
                assert control_pid() == initial_pid, 'native restart stopped the control service'
            fixture.wait_for('B enrollment restored', lambda: observations(b.connections['exit']),
                             lambda v: v.get('authentication') == 'authenticated' and v['session'] != previous)
            selected(b, b.connections['exit'])
            selected(a, a.connections['exit'])
            traffic(b, 'exit')
        print('Native-only and full service restarts restored the exit groups', flush=True)

        data('connection', 'logout', a.connections['exit'])
        selected(a, None)
        traffic(a, 'exit', allowed=False)
        protected_dns(a, allowed=False)
        traffic(b, 'exit')
        protected_dns(b)
        data('connection', 'forget-auth', a.connections['private'])
        data('connection', 'restart', a.connections['private'])
        enrollment(a, a.connections['private'])
        selected(a, a.connections['private'])
        traffic(a, 'private')
        traffic(b, 'exit')
        direct_path()
        assert management() == default_route
        assert [path.read_bytes() for path in control_files] == original_files
        for path, marker in legacy_profiles.items():
            assert path.read_bytes() == marker, f'Host configuration changed: {path}'
        print('Service restart, all-down isolation, independent re-enrollment and host routes passed', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('wgates', 'panel_root', 'netbird', 'netbird_server', 'geodata'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    stand.main(args.wgates, args.panel_root,
               native_acceptance=lambda context: acceptance(
                   context, args.netbird.resolve(strict=True), args.netbird_server.resolve(strict=True),
                   list(fixture.geodata_files(args.geodata))),
               extra_udp_targets=[(port, fixture.host(*target)) for target, port in fixture.UDP_TARGETS.items()]
               + fixture.DIRECT_UDP, extra_udp_witnesses=fixture.EXIT)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--device-login':
        complete_device_login(*sys.argv[2:])
    else:
        main()
