import {
  Alert,
  Button,
  Checkbox,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
} from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useRef, useState } from 'react';

import { adapterSchema, capabilities, operation, protocols } from './operations';
import type { WantGatesSnapshot } from './status';

export type Editor = {
  kind: 'group' | 'connection' | 'rule';
  id?: string;
  snapshot: WantGatesSnapshot;
};

interface Values {
  name?: string;
  group_id?: string;
  destination?: string;
  primary?: string;
  fallbacks?: string[];
  probes?: string;
  health_enabled?: boolean;
  target?: string;
  required_capabilities?: string[];
  interval_seconds?: number;
  timeout_seconds?: number;
  failure_threshold?: number;
  recovery_threshold?: number;
  expected_status?: number;
  ca_pem?: string;
  send_hex?: string;
  expect_hex?: string;
  protocol?: string;
  profile?: string;
  dns?: string;
  allowed_capabilities?: string[];
}

function objectField(text?: string): Record<string, unknown> {
  if (!text?.trim()) return {};
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Enter a JSON object.');
  return value as Record<string, unknown>;
}

const adapterGuides = {
  vless: {
    path: 'service.md#vless-import-and-limits',
    hint: 'Use a vless:// profile or one Xray VLESS outbound with the server address, port and client UUID.',
  },
  openvpn: {
    path: 'openvpn.md#import-and-apply',
    hint: 'Use a client .ovpn profile with dev tun, a remote server and the inline CA. Include any client certificate and key inline.',
  },
  forti: {
    path: 'forti.md#profiles-and-routing',
    hint: 'Use a client profile with the Forti gateway host and port. Include a configured client certificate and key inline.',
  },
  wireguard: {
    path: 'wireguard.md',
    hint: 'Use a WireGuard profile with interface private key and addresses and one peer with public key, endpoint and AllowedIPs.',
  },
  netbird: {
    path: 'netbird.md#configure-and-apply',
    hint: 'Use JSON with an HTTPS management_url and mode private or exit. Exit mode requires exit_network_id.',
  },
};

const capabilityOptions = capabilities.map((capability) => ({
  label: capability.replaceAll('_', ' ').toUpperCase(),
  value: capability,
}));

export default function ConfigEditor({
  editor,
  live,
  pending,
  locked,
  retryStatus,
  errorMessage,
  close,
  submit,
}: {
  editor: Editor;
  live: WantGatesSnapshot;
  pending: boolean;
  locked: boolean;
  retryStatus?: () => void;
  errorMessage: string;
  close: () => void;
  submit: (command: string, body: Record<string, unknown>) => Promise<void>;
}) {
  const { kind, id, snapshot } = editor;
  const group = kind === 'group' ? snapshot.groups.find((row) => row.id === id) : undefined;
  const connection =
    kind === 'connection' ? snapshot.connections.find((row) => row.id === id) : undefined;
  const rule = kind === 'rule' ? snapshot.rules.find((row) => row.id === id) : undefined;
  const current = group ?? connection ?? rule;
  const revision = current ? { id: current.id, expected_revision: current.revision } : {};
  const currentRows =
    kind === 'group' ? live.groups : kind === 'rule' ? live.rules : live.connections;
  const outdated =
    current && current.revision !== currentRows.find((row) => row.id === current.id)?.revision;
  const editingDisabled = locked || outdated;
  const [form] = Form.useForm<Values>();
  const [error, setError] = useState('');
  const [fileRead, setFileRead] = useState<'ready' | 'reading' | 'failed'>('ready');
  const fileSelection = useRef(0);
  const saveDisabled = editingDisabled || fileRead !== 'ready';
  const selectedProtocol = Form.useWatch('protocol', form) ?? connection?.protocol ?? 'vless';
  const healthEnabled = Form.useWatch('health_enabled', form) ?? Boolean(group?.healthcheck);
  const guide = adapterGuides[selectedProtocol as keyof typeof adapterGuides];
  const adapter = useQuery({
    queryKey: ['want-gates', 'adapter', selectedProtocol],
    queryFn: ({ signal }) =>
      operation(adapterSchema, 'connection.adapter', { protocol: selectedProtocol }, signal),
    enabled: kind === 'connection' && selectedProtocol !== 'vless',
    retry: false,
    staleTime: 15_000,
  });
  const groupOptions = snapshot.groups.map(({ id, name }) => ({ value: id, label: name }));
  const connectionOptions = snapshot.connections
    .filter((row) => row.group_id === id)
    .map(({ id, name }) => ({ value: id, label: name }));
  const initial = {
    name: group?.name ?? connection?.name,
    group_id: rule?.group_id ?? connection?.group_id ?? snapshot.groups[0]?.id,
    destination: rule?.destination,
    primary: group?.primary ?? undefined,
    fallbacks: group?.fallbacks,
    probes: group?.probes ? JSON.stringify(group.probes, null, 2) : '',
    health_enabled: Boolean(group?.healthcheck),
    target: group?.healthcheck?.target,
    required_capabilities: group?.healthcheck?.required_capabilities ?? ['tcp_ipv4'],
    interval_seconds: group?.healthcheck?.interval_seconds ?? 30,
    timeout_seconds: group?.healthcheck?.timeout_seconds ?? 5,
    failure_threshold: group?.healthcheck?.failure_threshold ?? 3,
    recovery_threshold: group?.healthcheck?.recovery_threshold ?? 5,
    expected_status: group?.healthcheck?.expected_status ?? undefined,
    ca_pem: group?.healthcheck?.ca_pem ?? undefined,
    send_hex: group?.healthcheck?.send_hex ?? undefined,
    expect_hex: group?.healthcheck?.expect_hex ?? undefined,
    protocol: connection?.protocol ?? 'vless',
    dns: connection?.dns ?? '',
    allowed_capabilities: connection?.allowed_capabilities ?? [...capabilities],
  };

  async function finish(values: Values) {
    if (saveDisabled) return;
    setError('');
    if (kind === 'group') {
      if (!group) {
        await submit('group.create', { name: values.name });
        return;
      }
      let probes: Record<string, unknown>;
      try {
        probes = objectField(values.probes);
      } catch {
        setError('Transport probes must be a JSON object.');
        return;
      }
      const healthcheck = values.health_enabled
        ? {
            target: values.target,
            required_capabilities: values.required_capabilities,
            interval_seconds: values.interval_seconds,
            timeout_seconds: values.timeout_seconds,
            failure_threshold: values.failure_threshold,
            recovery_threshold: values.recovery_threshold,
            expected_status: values.expected_status || undefined,
            ca_pem: values.ca_pem?.trim() || undefined,
            send_hex: values.send_hex?.trim() || undefined,
            expect_hex: values.expect_hex?.trim() || undefined,
          }
        : null;
      await submit('group.update', {
        ...revision,
        name: values.name,
        primary: values.primary || null,
        fallbacks: values.fallbacks ?? [],
        probes,
        healthcheck,
      });
      return;
    }
    if (kind === 'connection') {
      await submit(connection ? 'connection.update' : 'connection.import', {
        ...revision,
        name: values.name,
        group_id: values.group_id,
        ...(connection ? {} : { protocol: values.protocol }),
        ...(values.profile?.trim() ? { profile: values.profile } : {}),
        dns: values.dns?.trim() || null,
        allowed_capabilities: values.allowed_capabilities ?? [],
      });
      return;
    }
    await submit(rule ? 'rule.update' : 'rule.create', {
      ...revision,
      destination: values.destination,
      group_id: values.group_id,
    });
  }

  return (
    <Modal
      open
      title={`${current ? 'Edit' : kind === 'connection' ? 'Import' : 'Add'} ${kind}`}
      onCancel={close}
      keyboard={!pending}
      closable={!pending}
      mask={{ closable: !pending }}
      footer={
        <Space wrap>
          {current && (
            <Popconfirm
              title={`Remove this ${kind} from desired routing?`}
              onConfirm={() => {
                if (!editingDisabled) return submit(`${kind}.delete`, revision);
              }}
            >
              <Button danger disabled={editingDisabled}>
                Remove
              </Button>
            </Popconfirm>
          )}
          {retryStatus && (
            <Button disabled={pending} onClick={retryStatus}>
              Refresh status
            </Button>
          )}
          <Button onClick={close} disabled={pending}>
            Cancel
          </Button>
          <Button
            type="primary"
            loading={pending}
            disabled={saveDisabled}
            onClick={() => form.submit()}
          >
            Save desired configuration
          </Button>
        </Space>
      }
    >
      {(error || errorMessage) && <Alert title={error || errorMessage} type="error" role="alert" />}
      {outdated && (
        <Alert
          type="warning"
          title="This object changed. Close the form and reopen it with current settings."
        />
      )}
      <Form<Values>
        form={form}
        layout="vertical"
        initialValues={initial}
        onFinish={finish}
        disabled={editingDisabled}
      >
        {kind !== 'rule' && (
          <Form.Item label="Name" name="name" rules={[{ required: true, whitespace: true }]}>
            <Input maxLength={128} autoComplete="off" />
          </Form.Item>
        )}
        {kind !== 'group' && (
          <Form.Item label="Company group" name="group_id" rules={[{ required: true }]}>
            <Select options={groupOptions} />
          </Form.Item>
        )}
        {kind === 'rule' && (
          <Form.Item
            label="Destination"
            name="destination"
            extra="Use an IP address, CIDR, example.org for a domain and its subdomains, or full:example.org for an exact match."
            rules={[{ required: true, whitespace: true }]}
          >
            <Input autoComplete="off" />
          </Form.Item>
        )}
        {kind === 'connection' && (
          <>
            <Form.Item label="Protocol" name="protocol" rules={[{ required: true }]}>
              <Select
                disabled={Boolean(connection)}
                options={protocols.map((value) => ({ value, label: value }))}
              />
            </Form.Item>
            {adapter.isFetching && <p role="status">Checking native adapter</p>}
            {adapter.data?.available === false && (
              <Alert type="warning" title={adapter.data.reason} showIcon />
            )}
            {adapter.isError && (
              <Alert type="warning" title="Native adapter availability could not be checked." />
            )}
            <Form.Item
              label="Profile"
              name="profile"
              rules={[{ required: !connection, whitespace: true }]}
              extra={
                <>
                  <p>
                    {connection
                      ? 'Leave blank to keep the saved profile.'
                      : 'Paste a self-contained profile or choose a local file.'}
                  </p>
                  {guide && (
                    <>
                      <p>{guide.hint}</p>
                      <a
                        href={`https://github.com/andrey-krasheninnikov/want-gates/blob/main/docs/${guide.path}`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {selectedProtocol} profile guide
                      </a>
                    </>
                  )}
                </>
              }
            >
              <Input.TextArea
                autoComplete="off"
                autoSize={{ minRows: 3, maxRows: 8 }}
                disabled={editingDisabled || fileRead === 'reading'}
                onChange={() => {
                  if (fileRead === 'failed') {
                    setFileRead('ready');
                    setError('');
                  }
                }}
              />
            </Form.Item>
            <input
              type="file"
              aria-label="Connection profile file"
              disabled={editingDisabled}
              onChange={async (event) => {
                const file = event.currentTarget.files?.[0];
                event.currentTarget.value = '';
                if (!file) return;
                const selection = ++fileSelection.current;
                if (file.size > 1024 * 1024) {
                  setFileRead('failed');
                  setError('The profile exceeds 1 MiB. Choose another file or edit the profile.');
                  return;
                }
                setFileRead('reading');
                setError('');
                try {
                  const profile = await file.text();
                  if (selection !== fileSelection.current) return;
                  form.setFieldValue('profile', profile);
                  setFileRead('ready');
                } catch {
                  if (selection !== fileSelection.current) return;
                  setFileRead('failed');
                  setError(
                    'The profile file could not be read. Choose another file or edit the profile.',
                  );
                }
              }}
            />
            {fileRead === 'reading' && <p role="status">Reading selected profile</p>}
            <Form.Item label="Connection DNS" name="dns" extra="Use a UDP or TCP resolver URI.">
              <Input placeholder="udp://192.0.2.53:53" autoComplete="off" />
            </Form.Item>
            <Form.Item label="Allowed transport capabilities" name="allowed_capabilities">
              <Checkbox.Group options={capabilityOptions} />
            </Form.Item>
          </>
        )}
        {group && (
          <>
            <Form.Item label="Primary connection" name="primary">
              <Select allowClear options={connectionOptions} />
            </Form.Item>
            <Form.Item
              label="Ordered reserves"
              name="fallbacks"
              extra="Select in priority order. Remove and add a reserve to change its position."
            >
              <Select mode="multiple" options={connectionOptions} />
            </Form.Item>
            <Form.Item label="Transport and DNS probes (JSON)" name="probes">
              <Input.TextArea autoSize={{ minRows: 2, maxRows: 8 }} />
            </Form.Item>
            <Form.Item name="health_enabled" valuePropName="checked">
              <Checkbox>Enable automatic resource checks</Checkbox>
            </Form.Item>
            {healthEnabled && (
              <>
                <Form.Item label="Target resource URL" name="target" rules={[{ required: true }]}>
                  <Input placeholder="https://resource.example.org/check" autoComplete="off" />
                </Form.Item>
                <Form.Item
                  label="Required capabilities"
                  name="required_capabilities"
                  rules={[{ required: true }]}
                >
                  <Checkbox.Group options={capabilityOptions} />
                </Form.Item>
                <Form.Item label="Interval in seconds" name="interval_seconds">
                  <InputNumber min={1} max={86400} precision={0} />
                </Form.Item>
                <Form.Item label="Timeout in seconds" name="timeout_seconds">
                  <InputNumber min={1} max={60} precision={0} />
                </Form.Item>
                <Form.Item label="Consecutive failures for failover" name="failure_threshold">
                  <InputNumber min={1} precision={0} />
                </Form.Item>
                <Form.Item label="Consecutive successes for recovery" name="recovery_threshold">
                  <InputNumber min={1} precision={0} />
                </Form.Item>
                <Form.Item label="Expected HTTP status" name="expected_status">
                  <InputNumber min={200} max={599} precision={0} />
                </Form.Item>
                <Form.Item label="Trust certificate (PEM)" name="ca_pem">
                  <Input.TextArea autoSize />
                </Form.Item>
                <Form.Item label="TCP request bytes (hex)" name="send_hex">
                  <Input autoComplete="off" />
                </Form.Item>
                <Form.Item label="Expected TCP reply (hex)" name="expect_hex">
                  <Input autoComplete="off" />
                </Form.Item>
              </>
            )}
          </>
        )}
      </Form>
    </Modal>
  );
}
