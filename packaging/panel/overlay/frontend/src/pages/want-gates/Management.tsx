import { Alert, Button, Card, Modal, Popconfirm, Select, Space, Table, Typography } from 'antd';
import { useState } from 'react';

import AuthDialog from './AuthDialog';
import ConfigEditor, { type Editor } from './ConfigEditor';
import { operation, type Outcome, type Preview } from './operations';
import type { WantGatesSnapshot } from './status';

export default function Management({
  state,
  refresh,
}: {
  state: WantGatesSnapshot;
  refresh: () => void;
}) {
  const [editor, setEditor] = useState<Editor>();
  const [signIn, setSignIn] = useState<WantGatesSnapshot['connections'][number]>();
  const [preview, setPreview] = useState<Preview>();
  const [outcome, setOutcome] = useState<Outcome>();
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);
  const { routing } = state;
  const locked = pending || routing.busy;
  const currentPreview = preview?.desired_revision === routing.desired_revision;
  const groupNames = new Map(state.groups.map((group) => [group.id, group.name]));
  const connectionLabel = (connection: WantGatesSnapshot['connections'][number]) =>
    `${groupNames.get(connection.group_id) ?? connection.group_id} · ${connection.name}`;

  function open(kind: Editor['kind'], id?: string) {
    setError('');
    setEditor({ kind, id, snapshot: state });
  }

  async function run<T>(
    command: string,
    body: Record<string, unknown>,
    complete: (response: T) => void,
  ) {
    setPending(true);
    setError('');
    setNotice('');
    setOutcome(undefined);
    try {
      complete(await operation<T>(command, body));
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Want Gates rejected the operation.');
    } finally {
      refresh();
      setPending(false);
    }
  }

  async function save(command: string, body: Record<string, unknown>) {
    await run(command, body, () => {
      setEditor(undefined);
      setPreview(undefined);
      setNotice('Desired configuration saved. Review a new preview to apply routing.');
    });
  }

  const groups = [
    {
      label: 'Company groups',
      options: state.groups.map((row) => ({ value: `group:${row.id}`, label: row.name })),
    },
    {
      label: 'Connections',
      options: state.connections.map((row) => ({
        value: `connection:${row.id}`,
        label: connectionLabel(row),
      })),
    },
    {
      label: 'Destination rules',
      options: state.rules.map((row) => ({ value: `rule:${row.id}`, label: row.destination })),
    },
  ];
  const native = state.connections.filter((row) => row.protocol !== 'vless');

  return (
    <Card>
      <Typography.Title level={2}>Manage routing</Typography.Title>
      <Space orientation="vertical" size="middle" style={{ display: 'flex' }}>
        {error && !editor && !preview && <Alert type="error" title={error} />}
        {notice && <Alert type="success" title={notice} />}
        {outcome && (
          <Alert
            type={outcome.state === 'applied' && !outcome.mismatch ? 'success' : 'warning'}
            title={`Routing result · ${outcome.state.replaceAll('_', ' ')}`}
            description={[
              outcome.running_revision !== null
                ? `Last observed revision ${outcome.running_revision}.`
                : 'Running revision unavailable.',
              outcome.mismatch && 'Desired and observed routing differ.',
              outcome.native_cleanup_required && 'Native resources require inspection.',
            ]
              .filter(Boolean)
              .join(' ')}
          />
        )}
        <Space wrap>
          <Button disabled={locked} onClick={() => open('group')}>
            Add group
          </Button>
          <Button disabled={locked || !state.groups.length} onClick={() => open('connection')}>
            Import connection
          </Button>
          <Button disabled={locked || !state.groups.length} onClick={() => open('rule')}>
            Add rule
          </Button>
          <Select
            aria-label="Edit saved object"
            placeholder="Edit saved object"
            value={null}
            disabled={locked || !state.groups.length}
            options={groups}
            style={{ minWidth: 190 }}
            onChange={(value: string) => {
              const [kind, id] = value.split(':');
              if (kind === 'group' || kind === 'connection' || kind === 'rule') open(kind, id);
            }}
          />
          {native.length > 0 && (
            <Select
              aria-label="Manage VPN sign-in"
              placeholder="Manage VPN sign-in"
              value={null}
              disabled={locked}
              options={native.map((row) => ({ value: row.id, label: connectionLabel(row) }))}
              style={{ minWidth: 190 }}
              onChange={(id) => setSignIn(native.find((row) => row.id === id))}
            />
          )}
        </Space>
        <Space wrap>
          <Button
            type="primary"
            loading={pending && !editor && !preview}
            disabled={locked || routing.recovery_required}
            onClick={() => void run<Preview>('routing.preview', {}, setPreview)}
          >
            Preview routing
          </Button>
          {routing.recovery_required && routing.recovery_plan_id && (
            <Popconfirm
              title="Recover the previous working routing?"
              description="The service checks for intervening edits before restoring the previous plan."
              onConfirm={() =>
                run<Outcome>('routing.recover', { plan_id: routing.recovery_plan_id }, setOutcome)
              }
            >
              <Button disabled={locked}>Recover routing</Button>
            </Popconfirm>
          )}
        </Space>
      </Space>
      {editor && (
        <ConfigEditor
          editor={editor}
          pending={pending}
          errorMessage={error}
          close={() => {
            setEditor(undefined);
            setError('');
          }}
          submit={save}
        />
      )}
      {signIn && (
        <AuthDialog connection={signIn} close={() => setSignIn(undefined)} refresh={refresh} />
      )}
      {preview && (
        <Modal
          open
          title="Review routing change"
          onCancel={() => {
            setPreview(undefined);
            setError('');
          }}
          keyboard={!pending}
          mask={{ closable: !pending }}
          closable={!pending}
          width={800}
          footer={
            <Space>
              <Button
                disabled={pending}
                onClick={() => {
                  setPreview(undefined);
                  setError('');
                }}
              >
                Cancel
              </Button>
              <Button
                type="primary"
                loading={pending}
                disabled={locked || !currentPreview}
                onClick={() =>
                  void run<Outcome>('routing.apply', { plan_id: preview.plan_id }, (response) => {
                    setPreview(undefined);
                    setOutcome(response);
                  })
                }
              >
                Apply reviewed routing
              </Button>
            </Space>
          }
        >
          {error && <Alert type="error" title={error} />}
          {!currentPreview && (
            <Alert type="warning" title="Desired configuration changed. Create a new preview." />
          )}
          <p>Desired revision {preview.desired_revision}</p>
          {preview.sessions_may_interrupt && <p>Applying may interrupt active sessions.</p>}
          <p>Unmatched traffic · {preview.unmatched}</p>
          <p>Unverified paths · {preview.unverified}</p>
          <p>Ingress · {preview.ingress?.join(', ') || 'None'}</p>
          <p>Prepared connections · {preview.prepared_connections?.length ?? 0}</p>
          <Table
            rowKey="id"
            pagination={{ pageSize: 8, hideOnSinglePage: true }}
            dataSource={preview.rules ?? []}
            scroll={{ x: 480 }}
            columns={[
              { title: 'Destination', dataIndex: 'destination' },
              {
                title: 'Company group',
                render: (_, rule) => groupNames.get(rule.group_id) ?? rule.group_id,
              },
              {
                title: 'Desired primary',
                render: (_, rule) => {
                  if (!currentPreview) return 'Refresh required';
                  const group = state.groups.find((row) => row.id === rule.group_id);
                  const connection = state.connections.find((row) => row.id === group?.primary);
                  return connection?.name ?? 'None';
                },
              },
              {
                title: 'Eligibility',
                render: (_, rule) => (
                  <ul>
                    {Object.entries(preview.eligibility?.[rule.id] ?? {}).map(
                      ([capability, check]) => (
                        <li key={capability}>
                          {capability.replaceAll('_', ' ')} · {check.reason.replaceAll('_', ' ')}
                          {check.requires && ` · requires ${check.requires.replaceAll('_', ' ')}`}
                        </li>
                      ),
                    )}
                  </ul>
                ),
              },
            ]}
          />
        </Modal>
      )}
    </Card>
  );
}
