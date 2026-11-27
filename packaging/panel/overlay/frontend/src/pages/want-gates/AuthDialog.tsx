import { Alert, Button, Checkbox, Form, Input, Modal, Popconfirm, Select, Space } from 'antd';
import { useState } from 'react';

import { operation, type AuthState } from './operations';

type Credential =
  | 'username'
  | 'password'
  | 'private_key_password'
  | 'response'
  | 'cookie'
  | 'setup_key';
type Values = Partial<Record<Credential, string>> & { remember?: boolean };

const fieldLabels: Record<Credential, string> = {
  username: 'Username',
  password: 'Password',
  private_key_password: 'Private key passphrase',
  response: 'Challenge response',
  cookie: 'Forti session cookie',
  setup_key: 'NetBird setup key',
};

export function challengeFields(
  protocol: string,
  auth?: AuthState,
  method = 'password',
): Credential[] {
  if (auth?.authentication === 'browser_required') return [];
  if (protocol === 'netbird') {
    return auth?.authentication === 'credentials_required' ? ['setup_key'] : [];
  }
  if (!auth?.challenge_id) return [];
  if (protocol === 'forti') {
    if (auth.method === 'text') return ['response'];
    if (method === 'certificate' || method === 'saml') return ['private_key_password'];
    if (method === 'cookie') return ['cookie'];
    return ['username', 'password', 'private_key_password'];
  }
  switch (auth.method) {
    case 'password':
      return ['username', 'password'];
    case 'private_key':
      return ['private_key_password'];
    case 'text':
      return ['response'];
    case 'dynamic':
      return ['username', 'response'];
    case 'static':
      return ['username', 'password', 'response'];
    default:
      return [];
  }
}

export function BrowserChallenge({ auth }: { auth: AuthState }) {
  if (auth.authentication !== 'browser_required') return null;
  if (auth.expires_at != null && auth.expires_at * 1000 <= Date.now()) {
    return (
      <Alert
        type="warning"
        title="This challenge expired. Check sign-in for a current challenge."
      />
    );
  }
  return (
    <Space orientation="vertical">
      {auth.ssh_forward && (
        <>
          <p>Start the forwarded callback on the computer that will open the sign-in link.</p>
          <code>
            ssh -N -L {auth.ssh_forward.local_host}:{auth.ssh_forward.local_port}:
            {auth.ssh_forward.remote_socket} YOUR_SERVER
          </code>
        </>
      )}
      {auth.url ? (
        <a
          href={auth.url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(event) => {
            if (auth.expires_at != null && auth.expires_at * 1000 <= Date.now()) {
              event.preventDefault();
            }
          }}
        >
          Open VPN sign-in
        </a>
      ) : (
        <Alert type="warning" title="The VPN did not return a supported sign-in link." />
      )}
      {auth.user_code && (
        <p>
          Device code <code>{auth.user_code}</code>
        </p>
      )}
    </Space>
  );
}

export default function AuthDialog({
  connection,
  close,
  refresh,
}: {
  connection: { id: string; name: string; protocol: string };
  close: () => void;
  refresh: () => void;
}) {
  const [auth, setAuth] = useState<AuthState>();
  const [method, setMethod] = useState('password');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const [form] = Form.useForm<Values>();
  const { id, protocol } = connection;
  const fields = challengeFields(protocol, auth, method);
  const showsMethods =
    protocol === 'forti' &&
    auth?.challenge_id &&
    auth.method !== 'text' &&
    auth.authentication !== 'browser_required' &&
    Boolean(auth.methods?.length);
  const expiresAt = auth?.expires_at;
  const expired = expiresAt != null && expiresAt * 1000 <= Date.now();
  const canRemember =
    protocol === 'openvpn'
      ? fields.includes('password') || fields.includes('private_key_password')
      : protocol === 'forti' &&
        (method === 'password' || method === 'certificate') &&
        auth?.method !== 'text';

  async function invoke(command: string, fields: Record<string, unknown> = {}) {
    setPending(true);
    setError('');
    try {
      const next = await operation<AuthState | null>(command, { id, ...fields });
      setAuth(next ?? undefined);
      refresh();
    } catch (error) {
      setError(error instanceof Error ? error.message : 'VPN sign-in failed.');
    } finally {
      form.resetFields();
      setPending(false);
    }
  }

  async function finish(values: Values) {
    if (expiresAt != null && expiresAt * 1000 <= Date.now()) {
      setError('This challenge expired. Check sign-in for a current challenge.');
      return;
    }
    const credentials: Record<string, unknown> = {};
    for (const field of fields) if (values[field]) credentials[field] = values[field];
    if (auth?.challenge_id && protocol !== 'netbird') credentials.challenge_id = auth.challenge_id;
    if (showsMethods) credentials.method = method;
    await invoke('connection.login', {
      credentials,
      ...(canRemember && values.remember ? { remember: true } : {}),
    });
  }

  return (
    <Modal
      open
      title={`VPN sign-in · ${connection.name}`}
      footer={
        <Button disabled={pending} onClick={close}>
          Close
        </Button>
      }
      onCancel={close}
      keyboard={!pending}
      mask={{ closable: !pending }}
      closable={!pending}
    >
      <Space orientation="vertical" size="middle" style={{ display: 'flex' }}>
        {error && <Alert type="error" title={error} />}
        {auth && (
          <>
            <p role="status">Authentication · {auth.authentication.replaceAll('_', ' ')}</p>
            {auth.remembered && <p>Saved credentials are available.</p>}
            {auth.prompt && <p>{auth.prompt}</p>}
            {expiresAt != null && (
              <p>Challenge expires {new Date(expiresAt * 1000).toLocaleTimeString()}.</p>
            )}
            <BrowserChallenge auth={auth} />
          </>
        )}
        <Space wrap>
          <Button disabled={pending} onClick={() => void invoke('connection.auth-status')}>
            Check sign-in
          </Button>
          {protocol !== 'wireguard' && (
            <Button disabled={pending} onClick={() => void invoke('connection.login')}>
              {protocol === 'netbird' ? 'Start browser sign-in' : 'Start or resume sign-in'}
            </Button>
          )}
          <Popconfirm
            title="Restart this VPN session?"
            onConfirm={() => invoke('connection.restart')}
          >
            <Button disabled={pending}>Restart VPN</Button>
          </Popconfirm>
          <Popconfirm
            title="Disconnect this VPN session?"
            onConfirm={() => invoke('connection.logout')}
          >
            <Button disabled={pending}>Disconnect</Button>
          </Popconfirm>
          {protocol !== 'wireguard' && (
            <Popconfirm
              title="Forget saved VPN credentials or enrollment?"
              onConfirm={() => invoke('connection.forget-auth')}
            >
              <Button disabled={pending}>Forget sign-in</Button>
            </Popconfirm>
          )}
        </Space>
        {showsMethods && (
          <label>
            Forti login method{' '}
            <Select
              aria-label="Forti login method"
              value={method}
              disabled={pending}
              options={auth.methods?.map((value) => ({ value, label: value }))}
              onChange={(value) => {
                form.resetFields();
                setMethod(value);
              }}
            />
          </label>
        )}
        {fields.length > 0 && (
          <Form<Values>
            form={form}
            layout="vertical"
            onFinish={finish}
            disabled={pending || expired}
          >
            {fields.map((field) => {
              const optional =
                (field === 'private_key_password' && protocol === 'forti') ||
                (field === 'username' && auth?.method === 'dynamic');
              return (
                <Form.Item
                  key={field}
                  name={field}
                  label={fieldLabels[field]}
                  rules={[{ required: !optional }]}
                >
                  {field === 'username' ? (
                    <Input autoComplete="off" />
                  ) : (
                    <Input.Password autoComplete="off" />
                  )}
                </Form.Item>
              );
            })}
            {canRemember && (
              <Form.Item name="remember" valuePropName="checked">
                <Checkbox>Remember base credentials on the gateway</Checkbox>
              </Form.Item>
            )}
            <Button type="primary" htmlType="submit" loading={pending}>
              Submit sign-in
            </Button>
          </Form>
        )}
      </Space>
    </Modal>
  );
}
