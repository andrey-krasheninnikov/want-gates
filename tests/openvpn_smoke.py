#!/usr/bin/env python3
"""Exercise native OpenVPN only on the disposable local Linux systemd stand."""
import json
import base64
import pwd
from pathlib import Path
import shutil
import socket
import threading
import subprocess
import sys
import time
import routing_smoke as stand


class AuthenticationServer:
    """Authenticate the stand's own native server through its management interface."""
    def __init__(self, path):
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        path.chmod(0o600)
        self.listener.listen(1)
        self.listener.settimeout(1)
        self.stream = None
        self.stopping = threading.Event()
        self.error = None
        self.lock = threading.Lock()
        self.pending = None
        self.mode = 'password'
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def send(self, command):
        with self.lock:
            self.stream.sendall((command+'\n').encode())

    def run(self):
        try:
            while not self.stopping.is_set():
                try:
                    self.stream, _ = self.listener.accept()
                    break
                except TimeoutError:
                    continue
            if self.stream is None:
                return
            self.send('version 5')
            self.send('hold release')
            environment, event = {}, None
            with self.stream.makefile('r') as reader:
                for line in reader:
                    line = line.rstrip('\r\n')
                    if line.startswith(('>CLIENT:CONNECT,', '>CLIENT:REAUTH,', '>CLIENT:CR_RESPONSE,')):
                        event, environment = line.removeprefix('>CLIENT:').split(','), {}
                    elif line == '>CLIENT:ENV,END' and event:
                        self.authenticate(event, environment)
                        event = None
                    elif line.startswith('>CLIENT:ENV,') and event:
                        key, _, value = line.removeprefix('>CLIENT:ENV,').partition('=')
                        environment[key] = value
        except (OSError, ValueError) as error:
            if not self.stopping.is_set():
                self.error = type(error).__name__

    def authenticate(self, event, environment):
        kind, cid, kid = event[:3]
        user, password = environment.get('username'), environment.get('password')
        if kind == 'CR_RESPONSE':
            accepted = self.pending == (cid,kid) and base64.b64decode(event[3]) == b'mfa-transient-marker'
            self.send(f'client-auth-nt {cid} {kid}' if accepted else f'client-deny {cid} {kid} "Challenge rejected"')
            self.pending = None
            return
        if self.mode in ('text','web','openurl','expired') and user == 'native-user' and password == 'native-password-marker':
            self.pending = (cid,kid)
            extra = 'WEB_AUTH:external:https://signin.example.test/complete?token=native-web-secret-marker' if self.mode == 'web' else 'OPEN_URL:https://signin.example.test/complete?token=native-web-secret-marker' if self.mode == 'openurl' else 'CR_TEXT:R:One-time code'
            timeout = 2 if self.mode == 'expired' else 30
            self.send(f'client-pending-auth {cid} {kid} "{extra}" {timeout}')
            return
        if self.mode == 'dynamic':
            if user == 'native-user' and password == 'native-password-marker':
                identity = base64.b64encode(b'native-user').decode()
                self.send(f'client-deny {cid} {kid} "Challenge required" "CRV1:R,E:native-state-marker:{identity}:One-time code"')
                return
            accepted = user == 'native-user' and password == 'CRV1::native-state-marker::mfa-transient-marker'
        elif self.mode == 'static':
            expected = 'SCRV1:'+base64.b64encode(b'native-password-marker').decode()+':'+base64.b64encode(b'mfa-transient-marker').decode()
            accepted = user == 'native-user' and password == expected
        else:
            accepted = user == 'native-user' and password == 'native-password-marker'
        self.send(f'client-auth-nt {cid} {kid}' if accepted else f'client-deny {cid} {kid} "Authentication rejected"')

    def complete(self):
        assert self.pending is not None
        cid,kid = self.pending
        self.pending = None
        self.send(f'client-auth-nt {cid} {kid}')

    def close(self):
        self.stopping.set()
        if self.stream:
            try: self.stream.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.stream.close()
        self.listener.close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), 'native test authentication did not stop'
        assert self.error is None, self.error


def helper_outage(context, group, connection):
    control, ns, prefix = (context[k] for k in ('control', 'ns', 'prefix'))
    profile = context['outbound']('10.214.0.2',19002,context['ids']['b'])
    reserve = control('connection','import','--group',group,'--name','Outage reserve','--protocol','vless','--file','-','--dns','udp://10.220.0.10:53',payload=profile)['data']['id']
    pure_group = control('group','create','--name','Independent VLESS')['data']['id']
    pure = control('connection','import','--group',pure_group,'--name','VLESS primary','--protocol','vless','--file','-','--dns','udp://10.220.0.10:53',payload=profile)['data']['id']
    probes = control('group','show',group)['data']['probes']
    policy = dict(target='http://health.corp.test:18080/health',required_capabilities=['tcp_ipv4','udp_ipv4','tcp_ipv6','udp_ipv6'],interval_seconds=1,timeout_seconds=1,failure_threshold=2,recovery_threshold=3)
    control('group','update',group,'--fallbacks',reserve,'--healthcheck-file','-',payload=policy)
    policy_path = context['work']/'outage-policy.json'
    policy_path.write_text(json.dumps(policy))
    control('group','update',pure_group,'--primary',pure,'--probe-file','-','--healthcheck-file',policy_path,payload=probes)
    control('rule','create','--group',pure_group,'--destination','10.221.0.10')
    plan = control('routing','preview')['data']['plan_id']
    assert control('routing','apply',plan)['data']['state']=='applied'
    def health():
        report=control('routing','status')['data']['health']
        assert not report['error'],report
        return {g['group_id']:g for g in report['groups']}
    before=health()[pure_group]['connections'][pure]['observed_at']
    stand.checked('systemctl','stop',prefix+'-native.service')
    deadline=time.monotonic()+30
    while True:
        current=health()
        if current[group]['selected_connection']==reserve and current[pure_group]['connections'][pure]['observed_at']>before:
            break
        assert time.monotonic()<deadline,current
        time.sleep(.1)
    assert current[pure_group]['selected_connection']==pure,current
    def traffic(address, peer):
        result=ns('client','curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','4','-fsS',f'http://{address}:18080/helper-outage')
        assert json.loads(result.stdout)['peer']==peer,result.stdout
    traffic('10.220.0.10','10.212.0.1')
    traffic('10.221.0.10','10.212.0.1')
    traffic('1.1.1.1','10.210.0.1')
    stand.checked('systemctl','start',prefix+'-native.service')
    deadline=time.monotonic()+30
    while True:
        current=health()
        if current[group]['selected_connection']==connection:
            break
        assert time.monotonic()<deadline,current
        time.sleep(.1)
    assert current[group]['connections'][connection]['successes']>=3,current
    traffic('10.220.0.10','10.211.0.1')
    traffic('10.221.0.10','10.212.0.1')
    print('Helper outage preserves VLESS monitoring and fallback, then native recovery observes its threshold',flush=True)


def acceptance(context, only_helper_outage=False):
    ns, spawn, control = (context[k] for k in ('ns', 'spawn', 'control'))
    work, installed, xray, prefix = (context[k] for k in ('work', 'installed', 'xray', 'prefix'))
    tls = work / 'tls'
    stand.checked('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Native stand client', '-keyout', str(tls/'client.key'), '-out', str(tls/'client.csr'))
    (tls/'client.ext').write_text('extendedKeyUsage=clientAuth\n')
    stand.checked('openssl', 'x509', '-req', '-in', str(tls/'client.csr'), '-CA', str(tls/'ca.crt'), '-CAkey', str(tls/'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(tls/'client.ext'), '-out', str(tls/'client.crt'))
    (tls/'native-server.ext').write_text('keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    stand.checked('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Native stand server', '-keyout', str(tls/'native-server.key'), '-out', str(tls/'native-server.csr'))
    stand.checked('openssl', 'x509', '-req', '-in', str(tls/'native-server.csr'), '-CA', str(tls/'ca.crt'), '-CAkey', str(tls/'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(tls/'native-server.ext'), '-out', str(tls/'native-server.crt'))
    runtime, state = Path('/run') / f'{prefix}-native', Path('/var/lib') / f'{prefix}-native'
    assert not runtime.exists() and not state.exists()
    helper = None
    authentication = None
    helper_enabled = False
    unit = Path('/run/systemd/system') / f'{prefix}-native.service'
    assert not unit.exists()
    class HelperUnit:
        def poll(self):
            value = stand.checked('systemctl','show','--property=ActiveState','--value',unit.name).stdout.strip()
            return None if value in ('active','activating','deactivating') else 1
        def terminate(self): stand.checked('systemctl','stop',unit.name)
        def wait(self, timeout=None): return 0
        def kill(self): stand.checked('systemctl','kill',unit.name)
    try:
        for name in ('gateway', 'a', 'b'):
            ns(name, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
        server_a_args = ['/usr/sbin/openvpn', '--dev', 'tun', '--server', '10.231.0.0', '255.255.255.0', '--server-ipv6', 'fd42:231::/64', '--topology', 'subnet', '--proto', 'udp', '--local', '10.213.0.2', '--port', '1194', '--ca', tls/'ca.crt', '--cert', tls/'native-server.crt', '--key', tls/'native-server.key', '--dh', 'none', '--data-ciphers', 'AES-256-GCM', '--keepalive', '1', '5', '--push', 'route 10.220.0.0 255.255.255.0', '--push', 'route-ipv6 fd42:220::/64', '--push', 'dhcp-option DNS 10.220.0.10', '--verb', '3']
        dns_index = server_a_args.index('dhcp-option DNS 10.220.0.10')
        server_a_args[dns_index-1:dns_index+1] = ['--push','dhcp-option DOMAIN corp.test','--push','dhcp-option DNS 10.220.0.10',*[part for index in range(7) for part in ('--push',f'dhcp-option DOMAIN-SEARCH zone{index}.test')],'--push','dhcp-option DNS 1.1.1.1']
        server = spawn('a',server_a_args,'native-server')
        ns('a', 'nft', '-f', '-', input='table inet native_stand { chain nat { type nat hook postrouting priority srcnat; ip saddr 10.231.0.0/24 oifname "w4211a" masquerade; ip6 saddr fd42:231::/64 oifname "w4211a" masquerade; }; }\n')
        ns('resource', 'nft', '-f', '-', input='table inet native_dns { chain input { type nat hook prerouting priority dstnat; ip daddr 10.220.0.10 udp dport 53 dnat ip to 10.220.0.10:15353; ip daddr 10.220.0.10 tcp dport 53 dnat ip to 10.220.0.10:15353; }; }\n')
        template = (Path(__file__).resolve().parent.parent/'packaging/systemd/wgates-native.service').read_text().replace('wgates',prefix)
        template = template.replace('[Service]', '[Service]\nNetworkNamespacePath=/run/netns/'+context['names']['gateway'])
        template = '\n'.join(line+f' --xray-bin {xray}' if line.startswith(('ExecStart=','ExecStopPost=')) else line for line in template.splitlines())+'\n'
        unit.write_text(template)
        stand.checked('systemd-analyze','verify',str(unit))
        stand.checked('systemctl','daemon-reload')
        helper = HelperUnit()
        stand.checked('systemctl','start',unit.name)

        deadline = time.monotonic() + 10
        while not (runtime/'control.sock').exists():
            assert helper.poll() is None, 'native helper stopped during startup'
            assert time.monotonic() < deadline, 'native helper did not become ready'
            time.sleep(.05)
        gid = pwd.getpwnam(prefix).pw_gid
        denied = stand.checked('python3','-c',"import os,socket,json,sys; os.setgroups([]); os.setgid(int(sys.argv[2])); os.setuid(65534); s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(b'{\"api_version\":1,\"command\":\"preflight\"}\\n'); print(s.recv(4096).decode())",str(runtime/'control.sock'),str(gid))
        assert json.loads(denied.stdout)['error']=='native peer is not authorized'
        group = control('group', 'create', '--name', 'Native company')['data']['id']
        profile = 'client\ndev tun\nproto udp\nremote 10.213.0.2 1194\nremote 10.213.0.2 1195\nremote-cert-tls server\n'
        for kind, file in [('ca','ca.crt'), ('cert','client.crt'), ('key','client.key')]:
            profile += f'<{kind}>\n{(tls/file).read_text()}</{kind}>\n'
        connection = control('connection','import','--group',group,'--name','OpenVPN primary','--protocol','openvpn','--file','-',payload=profile)['data']['id']
        control('group','update',group,'--primary',connection,'--probe-file','-',payload=dict(tcp_ipv4=dict(url='http://10.220.0.10:18080/native'),tcp_ipv6=dict(url='http://[fd42:220::10]:18080/native'),udp_ipv4=dict(server='10.220.0.10:15353',query_name='probe.example.test',query_type='A'),udp_ipv6=dict(server='[fd42:220::10]:15353',query_name='probe.example.test',query_type='AAAA'),dns=dict(query_name='v4.corp.test',query_type='A')))
        for destination in ('10.220.0.0/24', 'fd42:220::/64', 'corp.test'):
            control('rule','create','--group',group,'--destination',destination)
        for attempt in range(3):
            plan = control('routing','preview')['data']['plan_id']
            result = control('routing','apply',plan)['data']
            if result['state'] == 'applied': break
            assert result['state'] in ('partial','blocked')
            time.sleep(2)
        assert result['state'] == 'applied', dict(result=result, connection=control('connection','show',connection)['data'])
        observed = control('connection','show',connection)['data']
        assert observed['authentication'] == 'authenticated', observed
        assert set(observed['capabilities']) == {'tcp_ipv4','udp_ipv4','tcp_ipv6','udp_ipv6','dns'}, observed
        for address in ('10.220.0.10','[fd42:220::10]','v4.corp.test'):
            traffic = ns('client','curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','5','-fsS',f'http://{address}:18080/native-accepted')
            assert json.loads(traffic.stdout)['peer'] in ('10.211.0.1','fd42:211::1'), traffic.stdout
        assert server.poll() is None
        for port in (15354,15356):
            reply = ns('client', 'python3', Path(stand.__file__), '--udp', str(port), 'native-capability.example.test')
            assert json.loads(reply.stdout)['answer'] == '198.18.1.1'
        print('OpenVPN imported-profile VLESS traffic, four capabilities and pushed DNS passed', flush=True)
        if only_helper_outage:
            helper_outage(context, group, connection)
            return

        management = work/'server-management.sock'
        authentication = AuthenticationServer(management)
        server_b_args = ['/usr/sbin/openvpn', '--dev', 'tun', '--server', '10.231.0.0', '255.255.255.0', '--server-ipv6', 'fd42:231::/64', '--topology', 'subnet', '--proto', 'udp', '--local', '10.214.0.2', '--port', '1194', '--ca', tls/'ca.crt', '--cert', tls/'native-server.crt', '--key', tls/'native-server.key', '--dh', 'none', '--data-ciphers', 'AES-256-GCM', '--duplicate-cn', '--keepalive', '1', '5', '--push', 'route 10.220.0.0 255.255.255.0', '--push', 'route 10.221.0.0 255.255.255.0', '--push', 'route-ipv6 fd42:220::/64', '--push', 'route-ipv6 fd42:221::/64', '--push', 'dhcp-option DNS 10.220.0.10', '--management', management, 'unix', '--management-client', '--management-client-auth', '--management-hold', '--verb', '3']
        server_b = spawn('b',server_b_args,'native-auth-server')
        ns('b', 'nft', '-f', '-', input='table inet native_stand { chain nat { type nat hook postrouting priority srcnat; ip saddr 10.231.0.0/24 oifname "w4212a" masquerade; ip6 saddr fd42:231::/64 oifname "w4212a" masquerade; }; }\n')
        group_b = control('group','create','--name','Native second company')['data']['id']
        profile_b = profile.replace('10.213.0.2','10.214.0.2')+'auth-user-pass\n'
        connection_b = control('connection','import','--group',group_b,'--name','OpenVPN password','--protocol','openvpn','--file','-',payload=profile_b)['data']['id']
        probes = dict(tcp_ipv4=dict(url='http://10.221.0.10:18080/native'),tcp_ipv6=dict(url='http://[fd42:221::10]:18080/native'),udp_ipv4=dict(server='10.221.0.10:15353',query_name='probe.example.test',query_type='A'),udp_ipv6=dict(server='[fd42:221::10]:15353',query_name='probe.example.test',query_type='AAAA'),dns=dict(query_name='v4.dev.corp.test',query_type='A'))
        control('group','update',group_b,'--primary',connection_b,'--probe-file','-',payload=probes)
        for destination in ('10.221.0.0/24','fd42:221::/64','dev.corp.test'):
            control('rule','create','--group',group_b,'--destination',destination)
        def apply():
            deadline=time.monotonic()+15
            while True:
                plan = control('routing','preview')['data']['plan_id']
                try:
                    return control('routing','apply',plan)['data']
                except RuntimeError as error:
                    # Health selection can invalidate a preview before its write begins.
                    if 'observed panel drift; preview again; no changes applied' not in str(error) or time.monotonic()>=deadline:
                        raise
        def await_connection(id, predicate, seconds=15):
            deadline = time.monotonic()+seconds
            while True:
                value = control('connection','show',id)['data']
                if predicate(value): return value
                assert time.monotonic()<deadline, value
                time.sleep(.05)
        pending = apply()
        assert pending['state']=='partial', pending
        action = control('connection','login',connection_b)['data']
        assert action['method']=='password', action
        credentials = dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker')
        control('connection','login',connection_b,'--file','-','--remember',payload=credentials)
        current = await_connection(connection_b, lambda v:v['authentication']=='authenticated')
        assert current['capabilities']==[] and current['native_runtime']['remembered'],current
        control('connection','login',connection_b,'--file','-',payload=credentials,success=False)
        assert apply()['state']=='applied'
        for address,peer in [('10.220.0.10','10.211.0.1'),('10.221.0.10','10.212.0.1'),('v4.corp.test','10.211.0.1'),('v4.dev.corp.test','10.212.0.1')]:
            traffic = ns('client','curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','4','-fsS',f'http://{address}:18080/native-isolation')
            assert json.loads(traffic.stdout)['peer']==peer, traffic.stdout
        for port in (15355,15357):
            reply=ns('client','python3',Path(stand.__file__),'--udp',str(port),'native-second.example.test')
            assert json.loads(reply.stdout)['answer']=='198.18.2.1'
        stopped = control('connection','logout',connection_b)['data']
        assert stopped['authentication']=='stopped' and not stopped['resources_active'], stopped
        assert control('connection','show',connection_b)['data']['capabilities']==[]
        control('connection','login',connection_b)
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        assert control('connection','show',connection_b)['data']['capabilities']==[]
        assert apply()['state']=='applied'
        control('connection','forget-auth',connection_b)
        assert not control('connection','show',connection_b)['data']['native_runtime']['remembered']
        control('connection','restart',connection_b)
        await_connection(connection_b,lambda v:v['authentication']=='credentials_required')
        assert control('connection','show',connection)['data']['authentication']=='authenticated'
        assert server_b.poll() is None
        print('OpenVPN password login, remember/forget, challenge replay rejection, logout/restart and concurrent overlapping TUN/DNS isolation passed',flush=True)
        password_file = work/'key-password'
        password_file.write_text('encrypted-key-password-marker')
        password_file.chmod(0o600)
        try:
            stand.checked('openssl','pkey','-in',tls/'client.key','-aes-256-cbc','-passout',f'file:{password_file}','-out',tls/'encrypted-client.key')
        finally:
            password_file.unlink()
        encrypted_profile = profile_b.replace((tls/'client.key').read_text(),(tls/'encrypted-client.key').read_text())
        assert encrypted_profile != profile_b
        control('connection','update',connection_b,'--file','-',payload=encrypted_profile)
        assert apply()['state']=='partial'
        methods = set()
        deadline = time.monotonic()+20
        while True:
            action = control('connection','login',connection_b)['data']
            if action['authentication']=='authenticated': break
            if action.get('method'):
                methods.add(action['method'])
                answer = dict(challenge_id=action['challenge_id'])
                if action['method']=='private_key': answer['private_key_password']='encrypted-key-password-marker'
                else:
                    assert action['method']=='password', action
                    answer.update(username='native-user',password='native-password-marker')
                control('connection','login',connection_b,'--file','-','--remember',payload=answer)
            assert time.monotonic()<deadline, action
            time.sleep(.05)
        assert methods=={'password','private_key'},methods
        assert apply()['state']=='applied'
        control('connection','restart',connection_b)
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        assert apply()['state']=='applied'
        print('OpenVPN encrypted private key, independent credential challenges and explicit remembered restart passed',flush=True)
        authentication.mode = 'static'
        control('connection','update',connection_b,'--file','-',payload=profile_b+'static-challenge "One-time code" 1\n')
        assert apply()['state']=='partial'
        action = control('connection','login',connection_b)['data']
        assert action['method']=='static' and action['prompt']=='One-time code',action
        control('connection','login',connection_b,'--file','-','--remember',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker',response='mfa-transient-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        assert apply()['state']=='applied'
        for path in state.iterdir():
            if path.is_file():
                assert b'mfa-transient-marker' not in path.read_bytes(),'MFA response persisted'
                assert path.stat().st_mode & 0o777 == 0o600
        public = json.dumps(control('routing','status'))+json.dumps(control('connection','list'))
        assert all(marker not in public for marker in ['native-password-marker','encrypted-key-password-marker','mfa-transient-marker'])
        print('OpenVPN native static challenge and transient MFA response passed',flush=True)
        authentication.mode = 'dynamic'
        control('connection','update',connection_b,'--file','-',payload=profile_b)
        assert apply()['state']=='partial'
        action = control('connection','login',connection_b)['data']
        assert action['method']=='password',action
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='challenge_required',30)
        action = control('connection','login',connection_b)['data']
        assert action['method']=='dynamic' and action['prompt']=='One-time code',action
        control('connection','login',connection_b,'--file','-','--remember',payload=dict(challenge_id=action['challenge_id'],response='mfa-transient-marker',password='mfa-as-base-marker'),success=False)
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],response='mfa-transient-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='authenticated',30)
        assert apply()['state']=='applied'
        print('OpenVPN native dynamic challenge and native reconnect passed',flush=True)
        authentication.mode = 'text'
        control('connection','restart',connection_b)
        await_connection(connection_b,lambda v:v['authentication']=='credentials_required')
        action = control('connection','login',connection_b)['data']
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='challenge_required')
        action = control('connection','login',connection_b)['data']
        assert action['method']=='text' and action['prompt']=='One-time code' and action['expires_at'],action
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],response='mfa-transient-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        assert apply()['state']=='applied'
        print('OpenVPN native CR_TEXT challenge, pending deadline and response passed',flush=True)
        for mode in ('web','openurl'):
            authentication.mode = mode
            control('connection','restart',connection_b)
            await_connection(connection_b,lambda v:v['authentication']=='credentials_required')
            action = control('connection','login',connection_b)['data']
            control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
            await_connection(connection_b,lambda v:v['authentication']=='browser_required')
            action = control('connection','login',connection_b)['data']
            assert action['method']=='web' and action['url']=='https://signin.example.test/complete?token=native-web-secret-marker' and action['expires_at'],action
            public = json.dumps(control('routing','status'))+json.dumps(control('connection','list'))
            assert 'native-web-secret-marker' not in public
            for path in state.iterdir():
                if path.is_file(): assert b'native-web-secret-marker' not in path.read_bytes()
            control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],response='ignored'),success=False)
            authentication.complete()
            await_connection(connection_b,lambda v:v['authentication']=='authenticated')
            assert apply()['state']=='applied'
        print('OpenVPN native WEB_AUTH and OPEN_URL, explicit URL access and URL redaction passed',flush=True)
        authentication.mode = 'expired'
        control('connection','restart',connection_b)
        await_connection(connection_b,lambda v:v['authentication']=='credentials_required')
        action = control('connection','login',connection_b)['data']
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='challenge_required')
        action = control('connection','login',connection_b)['data']
        assert action['expires_at']<=time.time()+3,action
        await_connection(connection_b,lambda v:v['authentication']=='expired',8)
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],response='mfa-transient-marker'),success=False)
        assert control('connection','show',connection_b)['data']['capabilities']==[]
        print('OpenVPN native challenge expiry and expired response rejection passed',flush=True)
        await_connection(connection_b,lambda v:v['authentication']=='credentials_required')
        action=control('connection','login',connection_b)['data']
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='challenge_required')
        control('connection','logout',connection_b)
        time.sleep(3)
        assert control('connection','show',connection_b)['data']['authentication']=='stopped','an old challenge deadline changed a stopped connection'
        control('connection','login',connection_b)
        authentication.mode = 'password'
        await_connection(connection_b,lambda v:v['authentication']=='credentials_required')
        action = control('connection','login',connection_b)['data']
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        assert apply()['state']=='applied'
        reserve = control('connection','import','--group',group,'--name','VLESS reserve','--protocol','vless','--file','-','--dns','udp://10.220.0.10:53',payload=json.dumps(context['outbound']('10.214.0.2',19002,context['ids']['b'])))['data']['id']
        policy = dict(target='http://health.corp.test:18080/health',required_capabilities=['tcp_ipv4','udp_ipv4','tcp_ipv6','udp_ipv6'],interval_seconds=1,timeout_seconds=1,failure_threshold=2,recovery_threshold=3)
        control('group','update',group,'--fallbacks',reserve,'--healthcheck-file','-',payload=policy)
        assert apply()['state']=='applied'
        def await_health(selected, seconds=45):
            deadline = time.monotonic()+seconds
            while True:
                report = control('routing','status')['data']['health']
                assert not report['error'],report
                current = next(g for g in report['groups'] if g['group_id']==group)
                if current['selected_connection']==selected: return current
                assert time.monotonic()<deadline,current
                time.sleep(.1)
        def traffic(address,peer):
            result=ns('client','curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','4','-fsS',f'http://{address}:18080/native-failover')
            assert json.loads(result.stdout)['peer']==peer,result.stdout
        def dns(name, expected):
            for mode in ('udp','tcp'):
                answer=ns('client','python3',Path(stand.__file__),'--dns-query',mode,name,'1')
                assert json.loads(answer.stdout)['answer']==expected,answer.stdout
        await_health(connection)
        server.terminate();server.wait(timeout=5)
        await_health(reserve)
        traffic('10.220.0.10','10.212.0.1')
        traffic('[fd42:220::10]','fd42:212::1')
        dns('v4.corp.test','10.221.0.10')
        traffic('v4.dev.corp.test','10.212.0.1')
        for port in (15354,15356):
            reply=ns('client','python3',Path(stand.__file__),'--udp',str(port),'native-fallback.example.test')
            assert json.loads(reply.stdout)['answer']=='198.18.2.1'
        server = spawn('a',server_a_args,'native-server-recovered')
        recovered=await_health(connection)
        assert recovered['connections'][connection]['successes']>=3,recovered
        traffic('10.220.0.10','10.211.0.1')
        dns('v4.corp.test','10.220.0.10')
        failures=work/'health-failures.json'
        failures.write_text(json.dumps(['10.212.0.1','fd42:212::1']))
        control('connection','logout',connection)
        await_health(None)
        marker='/native-blocked-marker'
        denied=stand.run('ip','netns','exec',context['names']['client'],'curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','2','-fsS',f'http://10.220.0.10:18080{marker}')
        assert denied.returncode!=0,'protected traffic escaped while every group path was down'
        assert marker not in context['events'].read_text()
        traffic('v4.dev.corp.test','10.212.0.1')
        traffic('1.1.1.1','10.210.0.1')
        failures.unlink()
        control('connection','login',connection)
        await_health(connection)
        traffic('10.220.0.10','10.211.0.1')
        print('OpenVPN/VLESS ordered fallback, DNS switch, native failback threshold, all-down blocking and independent company traffic passed',flush=True)
        control('connection','restart',connection_b)
        await_connection(connection_b,lambda v:v['authentication']=='credentials_required')
        action=control('connection','login',connection_b)['data']
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        started=time.time()
        deadline=time.monotonic()+10
        while await_health(connection)['connections'][connection]['observed_at']<=started+1:
            assert time.monotonic()<deadline,'health worker did not advance after native login'
            time.sleep(.1)
        current=control('connection','show',connection_b)['data']
        assert current['capabilities']==[] and not current['native_runtime']['admitted'],'another group healthcheck admitted an unchecked native session'
        assert apply()['state']=='applied'
        traffic('10.221.0.10','10.212.0.1')
        print('An unrelated group healthcheck cannot admit a native session without its own health policy or explicit apply',flush=True)
        server_b.terminate();server_b.wait(timeout=5)
        authentication.close();authentication=None
        management.unlink()
        authentication=AuthenticationServer(management)
        tcp_args=server_b_args.copy()
        tcp_args[tcp_args.index('--proto')+1]='tcp6-server'
        tcp_args[tcp_args.index('--local')+1]='fd42:214::2'
        server_b=spawn('b',tcp_args,'native-tcp6-server')
        tcp_profile=profile_b.replace('proto udp','proto tcp6-client').replace('10.214.0.2','fd42:214::2')
        control('connection','update',connection_b,'--file','-',payload=tcp_profile)
        assert apply()['state']=='partial'
        action=control('connection','login',connection_b)['data']
        assert action['method']=='password',action
        control('connection','login',connection_b,'--file','-','--remember',payload=dict(challenge_id=action['challenge_id'],username='native-user',password='native-password-marker'))
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        assert apply()['state']=='applied'
        traffic('10.221.0.10','10.212.0.1')
        traffic('[fd42:221::10]','fd42:212::1')
        dns('v4.dev.corp.test','10.221.0.10')
        for port in (15355,15357):
            reply=ns('client','python3',Path(stand.__file__),'--udp',str(port),'native-tcp6.example.test')
            assert json.loads(reply.stdout)['answer']=='198.18.2.1'
        print('OpenVPN TCP over an IPv6 endpoint carries verified TCP/UDP and IPv4/IPv6 payloads',flush=True)
        stand.checked('systemctl','enable','--runtime',unit.name)
        helper_enabled=True
        stand.checked('systemctl','restart',prefix+'.service')
        deadline=time.monotonic()+15
        while stand.run(installed,'status','--socket',Path('/run')/prefix/'control.sock').returncode:
            assert time.monotonic()<deadline,'control service did not become ready after native restart'
            time.sleep(.05)
        await_connection(connection,lambda v:v['authentication']=='authenticated')
        await_connection(connection_b,lambda v:v['authentication']=='authenticated')
        await_health(connection)
        assert control('connection','show',connection_b)['data']['capabilities']==[]
        assert apply()['state']=='applied'
        traffic('10.220.0.10','10.211.0.1')
        traffic('10.221.0.10','10.212.0.1')
        print('Packaged helper/control restart preserves private preparation and re-verifies new native sessions',flush=True)
        fault=control('connection','import','--group',group,'--name','Native preparation collision','--protocol','openvpn','--file','-',payload=profile)['data']['id']
        plan=control('routing','preview')['data']['plan_id']
        # The private plan is used only to inject a deterministic ownership collision.
        intent=json.loads((Path('/var/lib')/prefix/'routing'/'plan.json').read_text())
        generation=intent['native_intents'][fault]
        table='wgates_'+generation
        assert table not in ns('gateway','nft','-j','list','tables').stdout
        ns('gateway','nft','-f','-',input=f'table inet {table} {{ comment "preserved stand witness"; chain retained_stand {{ }}; }}\n')
        original=json.loads(ns('gateway','nft','-j','list','table','inet',table).stdout)
        try:
            control('routing','apply',plan,success=False)
            assert json.loads(ns('gateway','nft','-j','list','table','inet',table).stdout)==original,'native prepare changed an unowned firewall table'
        finally:
            if table in ns('gateway','nft','-j','list','tables').stdout:
                ns('gateway','nft','delete','table','inet',table)
        recovered=control('routing','recover',plan)['data']
        assert recovered['state']=='restored',recovered
        assert not (state/f'{generation}.json').exists()
        control('connection','delete',fault)
        assert apply()['state']=='applied'
        traffic('10.220.0.10','10.211.0.1')
        print('Failed native preparation preserves an unowned table and recovery releases only its recorded resources',flush=True)
        record=next(json.loads(path.read_text()) for path in state.glob('*.json') if json.loads(path.read_text())['prepared']['id']==connection_b)
        generation=record['prepared']['generation']
        table='wgates_'+generation
        ns('gateway','nft','add','chain','inet',table,'retained_stand')
        try:
            control('group','update',group_b,'--primary','-')
            control('connection','delete',connection_b)
            retired=apply()
            assert retired['native_cleanup_required'],retired
            assert any(item['connection_id']==connection_b and item['generation']==generation for item in control('routing','status')['data']['native_retained'])
            assert (state/f'{generation}.json').exists()
            traffic('10.220.0.10','10.211.0.1')
        finally:
            if table in ns('gateway','nft','-j','list','tables').stdout:
                ns('gateway','nft','delete','chain','inet',table,'retained_stand')
        cleaned=apply()
        assert not cleaned['native_cleanup_required'] and not control('routing','status')['data']['native_retained'],cleaned
        assert not (state/f'{generation}.json').exists()
        assert not list(state.glob(connection_b+'-*.auth'))
        print('Native retirement retains changed resources visibly, then confirms cleanup after reconciliation',flush=True)
        stand.checked('systemctl','stop',prefix+'.service')
        executable=Path('/usr/sbin/openvpn')
        mode=executable.stat().st_mode & 0o7777
        try:
            executable.chmod(mode | 0o020)
            result=stand.run('systemctl','start',unit.name,timeout=30)
            assert result.returncode!=0,'helper restart executed an unsafe native dependency'
        finally:
            executable.chmod(mode)
        stand.checked('systemctl','stop',prefix+'.service')
        print('Native helper refuses unsafe executable ownership on restored preparation',flush=True)
    except Exception:
        if context['events'].exists():
            print('Native resource evidence:', context['events'].read_text()[-3000:])
        raise
    finally:
        if authentication is not None:
            authentication.close()
        if helper is not None and helper.poll() is None:
            helper.terminate()
            try: helper.wait(timeout=15)
            except subprocess.TimeoutExpired: helper.kill(); helper.wait(timeout=5)
        if state.exists():
            stand.checked(installed, 'native-cleanup', '--socket', runtime/'control.sock', '--state-dir', state, '--service-user', prefix, '--xray-bin', xray)
        generations = [path.stem for path in state.glob('*.json')] if state.exists() else []
        links=json.loads(ns('gateway','ip','-j','link','show').stdout)
        tables=json.loads(ns('gateway','nft','-j','list','tables').stdout)['nftables']
        for generation in generations:
            assert not Path('/run/netns',f'wgates-{generation}').exists()
            assert all(link['ifname'] != 'wgn'+generation[:10] for link in links)
            assert all(table.get('table',{}).get('name') != 'wgates_'+generation for table in tables)
            record=json.loads((state/f'{generation}.json').read_text())
            assert record['namespace_identity'] is None and record['namespace_file'] is None and record['firewall_digest'] is None
        print('Native helper namespace, veth and nftables cleanup confirmed',flush=True)
        if helper_enabled: stand.checked('systemctl','disable','--runtime',unit.name)
        if unit.exists(): unit.unlink(); stand.checked('systemctl','daemon-reload')
        # These paths were absent before this fixture and belong only to its helper.
        for path in (runtime, state):
            if path.exists():
                assert not path.is_symlink() and path.stat().st_uid == 0
                shutil.rmtree(path)


if __name__ == '__main__':
    assert sys.argv[3:] in ([], ['--helper-outage']), 'unknown native stand option'
    stand.main(sys.argv[1], sys.argv[2], native_acceptance=lambda context: acceptance(context, only_helper_outage=bool(sys.argv[3:])))
