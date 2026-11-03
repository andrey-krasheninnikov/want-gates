#!/usr/bin/env python3
"""Exercise Forti through the public CLI on the disposable Linux stand."""
import json
import hashlib
import ssl
import os
import select
import signal
import shutil
import sys
import time
from pathlib import Path
import routing_smoke as stand


def acceptance(context, legacy=False):
    control, prefix = context['control'], context['prefix']
    runtime, state = Path('/run') / f'{prefix}-native', Path('/var/lib') / f'{prefix}-native'
    unit = Path('/run/systemd/system') / f'{prefix}-native.service'
    repo = Path(__file__).resolve().parent.parent
    forti_binary = '/usr/bin/openfortivpn' if legacy else '/opt/forti-1.24.1/bin/openfortivpn'
    bootstrap = Path('/run') / f'{prefix}-forti-bootstrap-hosts'
    assert not any(p.exists() for p in [runtime, state, unit, bootstrap])
    bootstrap.write_text('127.0.0.1 localhost\n10.213.0.2 forti-a.example.test wrong-name.example.test\n')
    bootstrap.chmod(0o644)
    template = (repo/'packaging/systemd/wgates-native.service').read_text().replace('wgates', prefix)
    template = template.replace('[Service]', '[Service]\nNetworkNamespacePath=/run/netns/'+context['names']['gateway']+'\nBindReadOnlyPaths='+str(bootstrap)+':/etc/hosts')
    template = '\n'.join(line+f' --xray-bin {context["xray"]} --openfortivpn-bin {forti_binary}' if line.startswith(('ExecStart=', 'ExecStopPost=')) else line for line in template.splitlines())+'\n'
    unit.write_text(template)
    tls = context['work']/'tls'
    stand.checked('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=Forti stand', '-keyout', str(tls/'forti.key'), '-out', str(tls/'forti.csr'))
    (tls/'forti.ext').write_text('subjectAltName=IP:10.213.0.2,IP:10.214.0.2,DNS:forti-a.example.test,DNS:10.213.0.2,DNS:10.214.0.2\nextendedKeyUsage=serverAuth\n')
    stand.checked('openssl', 'x509', '-req', '-in', str(tls/'forti.csr'), '-CA', str(tls/'ca.crt'), '-CAkey', str(tls/'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', str(tls/'forti.ext'), '-out', str(tls/'forti.crt'))
    mode = context['work']/'forti-mode.json'
    def set_mode(value):
        temporary=mode.with_suffix('.next')
        temporary.write_text(json.dumps(value));temporary.replace(mode)
    set_mode(dict(mode='password'))
    server = context['spawn']('a', ['python3', repo/'tests/forti_server.py', tls, '10.213.0.2', mode], 'forti-peer')
    context['ns']('a', 'nft', '-f', '-', input='table inet forti_stand { chain nat { type nat hook postrouting priority srcnat; ip saddr 10.231.0.0/24 oifname "w4211a" masquerade; }; }\n')
    context['ns']('resource', 'nft', '-f', '-', input='table inet forti_dns { chain dns { type nat hook prerouting priority dstnat; ip daddr 10.220.0.10 udp dport 53 dnat ip to 10.220.0.10:15353; ip daddr 10.220.0.10 tcp dport 53 dnat ip to 10.220.0.10:15353; }; }\n')
    deadline = time.monotonic()+5
    while not context['ns']('a','ss','-H','-lnt','sport = :10443').stdout.strip():
        assert server.poll() is None and time.monotonic()<deadline
        time.sleep(.05)
    frozen = []
    sshd = forwarding = None
    keys = Path('/run') / f'{prefix}-saml-ssh'
    assert not keys.exists()
    try:
        stand.checked('systemctl', 'daemon-reload')
        stand.checked('systemctl', 'start', unit.name)
        group = control('group', 'create', '--name', 'Forti company')['data']['id']
        profile = dict(protocol='forti', options=[['host','forti-a.example.test'],['port','10443']], inline={'ca-file':(tls/'ca.crt').read_text()})
        connection = control('connection', 'import', '--group', group, '--name', 'Forti native', '--protocol', 'forti', '--file', '-', payload=profile)['data']['id']
        control('group', 'update', group, '--primary', connection, '--probe-file', '-', payload=dict(tcp_ipv4=dict(url='http://10.220.0.10:18080/forti'),udp_ipv4=dict(server='10.220.0.10:15353',query_name='probe.example.test',query_type='A'),dns=dict(query_name='v4.corp.test',query_type='A')))
        control('rule','create','--group',group,'--destination','corp.test')
        control('rule','create','--group',group,'--destination','fd42:220::/64')
        control('rule', 'create', '--group', group, '--destination', '10.220.0.0/24')
        plan = control('routing', 'preview')['data']['plan_id']
        applied = control('routing', 'apply', plan)['data']
        assert applied['state'] == 'blocked', applied
        action = control('connection', 'login', connection)['data']
        assert action['method'] == 'password', action
        assert set(action['methods']) >= {'password', 'cookie'}, action
        assert ('saml' in action['methods']) != legacy,action
        assert action['challenge_id'], action
        print('Forti native preparation stays blocked pending explicit authentication', flush=True)
        def await_auth(expected, seconds=15):
            deadline = time.monotonic()+seconds
            while True:
                value = control('connection','show',connection)['data']
                if value['authentication']==expected:return value
                assert time.monotonic()<deadline,value
                time.sleep(.05)
        credentials = dict(challenge_id=action['challenge_id'], username='forti-user', password='forti-password-marker')
        control('connection','login',connection,'--file','-','--remember',payload=credentials)
        current = await_auth('authenticated')
        assert current['capabilities']==[],current
        assert current['native_runtime']['dns']=='udp://10.220.0.10:53',current
        control('connection','login',connection,'--file','-',payload=credentials,success=False)
        plan = control('routing','preview')['data']['plan_id']
        applied = control('routing','apply',plan)['data']
        assert applied['state']=='partial',applied
        assert applied['capabilities'][group]['tcp_ipv4']=='verified' and applied['capabilities'][group]['udp_ipv4']=='verified',applied
        for address in ['10.220.0.10','v4.corp.test']:
            result=context['ns']('client','curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','4','-fsS',f'http://{address}:18080/forti')
            assert json.loads(result.stdout)['peer']=='10.211.0.1',result.stdout
        reply=context['ns']('client','python3',Path(stand.__file__),'--udp','15354','forti-udp.example.test')
        assert json.loads(reply.stdout)['answer']=='198.18.1.1'
        for address in ['fd42:220::10']:
            result=stand.run('ip','netns','exec',context['names']['client'],'curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','2','-fsS',f'http://[{address}]:18080/forti')
            assert result.returncode!=0,'unsupported Forti IPv6 escaped'
        print('Real openfortivpn/pppd authentication, private DNS and VLESS TCP/UDP over IPv4 passed; IPv6 blocked',flush=True)
        control('connection','restart',connection)
        current = await_auth('authenticated')
        assert current['capabilities']==[], 'restart reused an earlier native admission'
        control('connection','forget-auth',connection)
        set_mode(dict(mode='otp'))
        control('connection','restart',connection)
        await_auth('credentials_required')
        action = control('connection','login',connection)['data']
        control('connection','login',connection,'--file','-','--remember',payload=dict(challenge_id=action['challenge_id'],username='forti-user',password='forti-password-marker'))
        await_auth('challenge_required')
        challenge = control('connection','login',connection)['data']
        assert challenge['method']=='text',challenge
        answer = dict(challenge_id=challenge['challenge_id'],response='forti-otp-marker')
        control('connection','login',connection,'--file','-','--remember',payload=answer,success=False)
        control('connection','login',connection,'--file','-',payload=answer)
        await_auth('authenticated')
        control('connection','login',connection,'--file','-',payload=answer,success=False)
        set_mode(dict(mode='otp401'))
        control('connection','restart',connection)
        await_auth('challenge_required')
        challenge=control('connection','login',connection)['data']
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=challenge['challenge_id'],response='forti-401-marker'))
        await_auth('authenticated')
        print('Native HTTP 401 form challenge completes through the same login interface',flush=True)
        set_mode(dict(mode='push'))
        control('connection','restart',connection)
        await_auth('authenticated')
        control('connection','forget-auth',connection)
        set_mode(dict(mode='cookie'))
        control('connection','restart',connection)
        await_auth('credentials_required')
        action = control('connection','login',connection)['data']
        cookie = dict(challenge_id=action['challenge_id'],method='cookie',cookie='forti-cookie-marker')
        control('connection','login',connection,'--file','-','--remember',payload=cookie,success=False)
        control('connection','login',connection,'--file','-',payload=cookie)
        current=await_auth('authenticated')
        assert current['capabilities']==[] and not current['native_runtime']['remembered'],current
        public = json.dumps(control('routing','status'))+json.dumps(current)
        for marker in ['forti-password-marker','forti-otp-marker','forti-cookie-marker']:
            assert marker not in public
            assert all(marker.encode() not in p.read_bytes() for p in state.glob('*.auth'))
        print('Remember/forget, fresh-session admission, native OTP/push, replay rejection and cookie SSO passed',flush=True)
        set_mode(dict(mode='saml'))
        control('connection','restart',connection)
        await_auth('credentials_required')
        action = control('connection','login',connection)['data']
        if legacy:
            rejected=control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],method='saml'),success=False)
            assert 'native SAML requires openfortivpn 1.23' in rejected.stderr
            print('Legacy client rejects native SAML explicitly while retaining cookie SSO',flush=True)
        else:
            web = control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],method='saml'))['data']
            assert web['authentication']=='browser_required' and web['method']=='web',web
            forward = web['ssh_forward']
            assert forward['local_host']==forward['remote_host']=='127.0.0.1' and forward['local_port']==8020,forward
            keys.mkdir(mode=0o700)
            for label in ['host','operator']:
                stand.checked('ssh-keygen','-q','-t','ed25519','-N','','-C','Forti acceptance','-f',str(keys/label))
            host_type, host_key = (keys/'host.pub').read_text().split()[:2]
            (keys/'known_hosts').write_text(f'[127.0.0.1]:22222 {host_type} {host_key}\n')
            configuration = keys/'sshd.conf'
            configuration.write_text(f'Port 22222\nListenAddress 127.0.0.1\nHostKey {keys}/host\nPidFile {keys}/sshd.pid\nAuthorizedKeysFile {keys}/operator.pub\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\nAllowTcpForwarding local\nGatewayPorts no\nPermitOpen 127.0.0.1:{forward["remote_port"]}\nLogLevel VERBOSE\n')
            Path('/run/sshd').mkdir(mode=0o755,exist_ok=True)
            sshd = context['spawn']('gateway',['/usr/sbin/sshd','-D','-e','-f',configuration],'saml-sshd')
            deadline=time.monotonic()+5
            while not context['ns']('gateway','ss','-H','-lnt','sport = :22222').stdout.strip():
                assert sshd.poll() is None and time.monotonic()<deadline
                time.sleep(.05)
            forwarding = context['spawn']('gateway',['ssh','-F','/dev/null','-N','-o','BatchMode=yes','-o','ExitOnForwardFailure=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={keys}/known_hosts','-i',keys/'operator','-p','22222','-L',f'127.0.0.1:8020:127.0.0.1:{forward["remote_port"]}','root@127.0.0.1'],'saml-forward')
            deadline=time.monotonic()+5
            while not context['ns']('gateway','ss','-H','-lnt','sport = :8020').stdout.strip():
                assert forwarding.poll() is None and time.monotonic()<deadline
                time.sleep(.05)
            context['ns']('gateway','curl','--noproxy','*','--max-time','5','--max-redirs','3','--cacert',tls/'ca.crt','--resolve','forti-a.example.test:10443:10.213.0.2','-fsSL',web['url'])
            current=await_auth('authenticated')
            assert not current['native_runtime']['remembered'] and current['capabilities']==[],current
            assert 'forti-saml-marker' not in json.dumps(current)
            replay=stand.run('ip','netns','exec',context['names']['gateway'],'curl','--noproxy','*','--max-time','2','-fsS','http://127.0.0.1:8020/?id=forti-saml-marker')
            assert replay.returncode!=0,'SAML callback remained open after completion'
            forwarding.terminate();forwarding.wait(timeout=3);forwarding=None
            sshd.terminate();sshd.wait(timeout=3);sshd=None
            print('Native SAML completes through an actual SSH loopback forward and closes its callback after use',flush=True)
            control('connection','restart',connection)
            await_auth('credentials_required')
            action=control('connection','login',connection)['data']
            pending_web=control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],method='saml'))['data']
            started=time.monotonic()
            while True:
                pending=control('connection','show',connection)['data']
                if pending['authentication']!='browser_required':break
                assert time.monotonic()-started<60,pending
                time.sleep(.1)
            assert time.monotonic()-started>=45 and pending['authentication'] in ('expired','unknown','failed'),pending
            closed=stand.run('ip','netns','exec',context['names']['gateway'],'python3','-c',f'import socket;socket.create_connection(("127.0.0.1",{pending_web["ssh_forward"]["remote_port"]}),timeout=.3)')
            assert closed.returncode!=0,'expired SAML callback is still open'
            control('connection','login',connection,'--file','-',payload=dict(challenge_id=pending_web['challenge_id'],method='saml'),success=False)
            action=control('connection','login',connection)['data']
            cancelled=control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],method='saml'))['data']
            stopped=control('connection','logout',connection)['data']
            assert stopped['authentication']=='stopped' and not stopped['resources_active'],stopped
            closed=stand.run('ip','netns','exec',context['names']['gateway'],'python3','-c',f'import socket;socket.create_connection(("127.0.0.1",{cancelled["ssh_forward"]["remote_port"]}),timeout=.3)')
            assert closed.returncode!=0,'cancelled SAML callback is still open'
            print('Native SAML deadline and logout close callbacks and reject stale responses',flush=True)

        stand.checked('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=Forti stand client','-keyout',str(tls/'client.key'),'-out',str(tls/'client.csr'))
        (tls/'client.ext').write_text('extendedKeyUsage=clientAuth\n')
        stand.checked('openssl','x509','-req','-in',str(tls/'client.csr'),'-CA',str(tls/'ca.crt'),'-CAkey',str(tls/'ca.key'),'-CAcreateserial','-days','1','-extfile',str(tls/'client.ext'),'-out',str(tls/'client.crt'))
        client_profile=json.loads(json.dumps(profile))
        client_profile['inline'].update({'user-cert':(tls/'client.crt').read_text(),'user-key':(tls/'client.key').read_text()})
        set_mode(dict(mode='password_certificate'))
        control('connection','update',connection,'--file','-',payload=client_profile)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        action=control('connection','login',connection)['data']
        assert action.get('method')=='password' and action.get('challenge_id'), 'a client certificate must not suppress account authentication: '+json.dumps(action)
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='forti-user',password='forti-password-marker'))
        await_auth('authenticated')
        print('Client certificate can accompany explicit native account authentication',flush=True)
        wrong_name=json.loads(json.dumps(profile));wrong_name['options'][0][1]='wrong-name.example.test'
        set_mode(dict(mode='password'))
        control('connection','update',connection,'--file','-',payload=wrong_name)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        action=control('connection','login',connection)['data']
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='forti-user',password='forti-password-marker'))
        failed=await_auth('unknown')
        assert failed['capabilities']==[] and failed['native_runtime']['reason']=='server_certificate_verification_failed',failed
        bad_profile=json.loads(json.dumps(profile))
        bad_profile['inline']['ca-file']=(repo/'tests/fixtures/health-ca.pem').read_text()
        set_mode(dict(mode='password'))
        control('connection','update',connection,'--file','-',payload=bad_profile)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        action=control('connection','login',connection)['data']
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='forti-user',password='forti-password-marker'))
        failed=await_auth('unknown')
        assert failed['capabilities']==[] and failed['native_runtime']['reason']=='server_certificate_verification_failed',failed
        pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert((tls/'forti.crt').read_text())).hexdigest()
        bad_profile['options'].append(['trusted-cert',pin])
        control('connection','update',connection,'--file','-',payload=bad_profile)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        action=control('connection','login',connection)['data']
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],username='forti-user',password='forti-password-marker'))
        await_auth('authenticated')
        print('Invalid CA fails closed; an explicit native certificate pin permits only the chosen certificate',flush=True)
        set_mode(dict(mode='certificate'))
        control('connection','update',connection,'--file','-',payload=client_profile)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        action=control('connection','login',connection)['data']
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],method='certificate'))
        await_auth('authenticated')
        stand.checked('openssl','pkey','-in',str(tls/'client.key'),'-aes-256-cbc','-passout','pass:forti-key-password-marker','-out',str(tls/'encrypted.key'))
        client_profile['inline']['user-key']=(tls/'encrypted.key').read_text()
        control('connection','update',connection,'--file','-',payload=client_profile)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        action=control('connection','login',connection)['data']
        set_mode(dict(mode='cookie'))
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],method='cookie',cookie='SVPNCOOKIE=forti-cookie-marker'),success=False)
        control('connection','login',connection,'--file','-',payload=dict(challenge_id=action['challenge_id'],method='cookie',cookie='SVPNCOOKIE=forti-cookie-marker',private_key_password='forti-key-password-marker'))
        current=await_auth('authenticated')
        assert not current['native_runtime']['remembered'],current
        control('connection','restart',connection)
        await_auth('credentials_required')
        action=control('connection','login',connection)['data']
        set_mode(dict(mode='certificate'))
        key_input=dict(challenge_id=action['challenge_id'],method='certificate',private_key_password='forti-key-password-marker')
        control('connection','login',connection,'--file','-','--remember',payload=key_input)
        await_auth('authenticated')
        control('connection','restart',connection)
        current=await_auth('authenticated')
        assert current['native_runtime']['remembered'] and current['capabilities']==[],current
        assert 'forti-key-password-marker' not in json.dumps(current)
        print('Native certificate-only login, encrypted key and explicit remembered key restart passed',flush=True)
        mode_b=context['work']/'forti-mode-b.json';mode_b.write_text(json.dumps(dict(mode='password')))
        context['spawn']('b',['python3',repo/'tests/forti_server.py',tls,'10.214.0.2',mode_b],'forti-peer-b')
        context['ns']('b','nft','-f','-',input='table inet forti_stand { chain nat { type nat hook postrouting priority srcnat; ip saddr 10.231.0.0/24 oifname "w4212a" masquerade; }; }\n')
        context['ns']('resource','nft','-f','-',input='add rule inet forti_dns dns ip daddr 10.221.0.10 udp dport 53 dnat ip to 10.221.0.10:15353\nadd rule inet forti_dns dns ip daddr 10.221.0.10 tcp dport 53 dnat ip to 10.221.0.10:15353\n')
        group_b=control('group','create','--name','Independent Forti company')['data']['id']
        profile_b=json.loads(json.dumps(profile));profile_b['options'][0][1]='10.214.0.2'
        connection_b=control('connection','import','--group',group_b,'--name','Forti B','--protocol','forti','--file','-','--dns','udp://10.221.0.10:53',payload=profile_b)['data']['id']
        probes_b=dict(tcp_ipv4=dict(url='http://10.221.0.10:18080/forti-b'),udp_ipv4=dict(server='10.221.0.10:15353',query_name='probe.example.test',query_type='A'),dns=dict(query_name='v4.dev.corp.test',query_type='A'))
        control('group','update',group_b,'--primary',connection_b,'--probe-file','-',payload=probes_b)
        control('rule','create','--group',group_b,'--destination','10.221.0.0/24')
        control('rule','create','--group',group_b,'--destination','dev.corp.test')
        reserve=control('connection','import','--group',group,'--name','Same-company VLESS reserve','--protocol','vless','--file','-','--dns','udp://10.220.0.10:53',payload=context['outbound']('10.214.0.2',19002,context['ids']['b']))['data']['id']
        policy=dict(target='http://health.corp.test:18080/health',required_capabilities=['tcp_ipv4','udp_ipv4'],interval_seconds=1,timeout_seconds=1,failure_threshold=2,recovery_threshold=3)
        control('group','update',group,'--fallbacks',reserve,'--healthcheck-file','-',payload=policy)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        action_b=control('connection','login',connection_b)['data']
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action_b['challenge_id'],username='forti-user',password='forti-password-marker'))
        deadline=time.monotonic()+15
        while control('connection','show',connection_b)['data']['authentication']!='authenticated':
            assert time.monotonic()<deadline
            time.sleep(.05)
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        def traffic(address,peer):
            response=context['ns']('client','curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','4','-fsS',f'http://{address}:18080/forti-isolation')
            assert json.loads(response.stdout)['peer']==peer,response.stdout
        traffic('v4.corp.test','10.211.0.1');traffic('v4.dev.corp.test','10.212.0.1')
        assert control('connection','show',connection_b)['data']['effective_dns']=='udp://10.221.0.10:53'
        def health():
            report=control('routing','status')['data']['health']
            assert not report['error'],report
            return next(g for g in report['groups'] if g['group_id']==group)
        def selected(expected):
            deadline=time.monotonic()+40
            while True:
                value=health()
                if value['selected_connection']==expected:return value
                assert time.monotonic()<deadline,value
                time.sleep(.1)
        selected(connection)
        set_mode(dict(mode='certificate',drop_data=True))
        selected(reserve)
        assert control('connection','show',connection)['data']['authentication']=='authenticated','the test must break resource access while keeping the native session up'
        traffic('v4.corp.test','10.212.0.1');traffic('v4.dev.corp.test','10.212.0.1')
        context['ns']('b','nft','-f','-',input='table inet forti_reserve_fault { chain input { type filter hook input priority -30; tcp dport 19002 reject; }; }\n')
        selected(None)
        blocked=stand.run('ip','netns','exec',context['names']['client'],'curl','--noproxy','','--socks5-hostname','127.0.0.1:10880','--max-time','2','-fsS','http://10.220.0.10:18080/forti-blocked-marker')
        assert blocked.returncode!=0,'all-down Forti traffic escaped'
        blocked=stand.run('ip','netns','exec',context['names']['client'],'python3',str(Path(stand.__file__)),'--udp','15360','forti-blocked-query.corp.test')
        assert blocked.returncode!=0,'all-down Forti DNS escaped'
        assert not any('forti-blocked' in json.loads(line).get('marker','') for line in context['events'].read_text().splitlines()),'protected data or DNS leaked'
        traffic('v4.dev.corp.test','10.212.0.1');traffic('1.1.1.1','10.210.0.1')
        context['ns']('b','nft','delete','table','inet','forti_reserve_fault')
        set_mode(dict(mode='certificate'))
        recovered=selected(connection)
        assert recovered['connections'][connection]['successes']>=3,recovered
        traffic('v4.corp.test','10.211.0.1');traffic('v4.dev.corp.test','10.212.0.1')
        print('Concurrent overlapping Forti networks, explicit DNS override, real-resource failover/failback, all-down blocking and independent company/direct traffic passed',flush=True)
        stand.checked('systemctl','restart',prefix+'.service')
        deadline=time.monotonic()+15
        while stand.run(str(context['installed']),'status','--socket',str(Path('/run')/prefix/'control.sock')).returncode:
            assert time.monotonic()<deadline,'control service did not restart'
            time.sleep(.05)
        await_auth('authenticated')
        deadline=time.monotonic()+40
        while True:
            recovered=health()
            if recovered['selected_connection']==connection and recovered['connections'][connection]['eligible'] and recovered['connections'][connection]['successes']>=3:break
            assert time.monotonic()<deadline,recovered
            time.sleep(.1)
        deadline=time.monotonic()+15
        while control('connection','show',connection_b)['data']['authentication']!='credentials_required':
            assert time.monotonic()<deadline
            time.sleep(.05)
        action_b=control('connection','login',connection_b)['data']
        control('connection','login',connection_b,'--file','-',payload=dict(challenge_id=action_b['challenge_id'],username='forti-user',password='forti-password-marker'))
        deadline=time.monotonic()+15
        while control('connection','show',connection_b)['data']['authentication']!='authenticated':
            assert time.monotonic()<deadline
            time.sleep(.05)
        observed=health()['connections'][connection]['observed_at']
        while health()['connections'][connection]['observed_at']<=observed+1:
            assert time.monotonic()<deadline
            time.sleep(.1)
        assert control('connection','show',connection_b)['data']['capabilities']==[],'another company healthcheck admitted an unverified restarted session'
        plan=control('routing','preview')['data']['plan_id'];control('routing','apply',plan)
        traffic('v4.corp.test','10.211.0.1');traffic('v4.dev.corp.test','10.212.0.1')
        print('Packaged restart restores remembered keys; another group cannot admit a fresh session without its own verification',flush=True)
        helper_pid = int(stand.checked('systemctl','show',unit.name,'--property=MainPID','--value').stdout)
        children = [int(v) for v in Path(f'/proc/{helper_pid}/task/{helper_pid}/children').read_text().split()]
        records=[json.loads(p.read_text()) for p in state.glob('*.json')]
        owned=[r for r in records if r['prepared']['id']==connection and not r['paused']]
        assert len(owned)==1
        identity=tuple(owned[0]['namespace_identity'])
        native = [pid for pid in children if Path(f'/proc/{pid}/comm').read_text().strip()=='openfortivpn' and (os.stat(f'/proc/{pid}/ns/net').st_dev,os.stat(f'/proc/{pid}/ns/net').st_ino)==identity]
        assert len(native)==1,native
        descendants = [int(v) for v in Path(f'/proc/{native[0]}/task/{native[0]}/children').read_text().split()]
        ppp = [pid for pid in descendants if Path(f'/proc/{pid}/comm').read_text().strip()=='pppd']
        assert len(ppp)==1,ppp
        native_descriptor = os.pidfd_open(native[0]); frozen.append(native_descriptor)
        signal.pidfd_send_signal(native_descriptor, signal.SIGSTOP)
        descriptor = os.pidfd_open(ppp[0]); frozen.append(descriptor)
        signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
        stopped = control('connection','logout',connection)['data']
        assert stopped['authentication']=='stopped' and not stopped['resources_active'],stopped
        assert select.select([descriptor],[],[],2)[0], 'logout left a stopped PPP descendant alive'
        print('Logout stops a PPP descendant even when its separate session ignores graceful termination',flush=True)

    finally:
        for process in [forwarding,sshd]:
            if process is not None and process.poll() is None:
                process.terminate();process.wait(timeout=3)
        if keys.exists(): shutil.rmtree(keys)
        for descriptor in frozen:
            if not select.select([descriptor],[],[],0)[0]:
                for action in (signal.SIGCONT,signal.SIGTERM):
                    try: signal.pidfd_send_signal(descriptor,action)
                    except ProcessLookupError: pass
                if not select.select([descriptor],[],[],2)[0]: signal.pidfd_send_signal(descriptor,signal.SIGKILL)
            os.close(descriptor)
        stand.checked('systemctl', 'stop', unit.name)
        result = stand.checked('systemctl','show',unit.name,'--property=Result','--value').stdout.strip()
        if result != 'success':
            print('Retained private runtime names:', sorted(str(p.relative_to(runtime)) for p in runtime.rglob('*')), flush=True)
            raise AssertionError('native cleanup failed; resources retained for inspection')
        if unit.exists(): unit.unlink()
        if bootstrap.exists(): bootstrap.unlink()
        stand.checked('systemctl', 'daemon-reload')
        for p in [runtime, state]:
            if p.exists(): shutil.rmtree(p)


if __name__ == '__main__':
    assert sys.argv[3:] in ([],['--legacy-client']), 'unknown Forti stand option'
    stand.main(sys.argv[1], sys.argv[2], native_acceptance=lambda context: acceptance(context,legacy=bool(sys.argv[3:])))
