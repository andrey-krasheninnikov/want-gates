import { Alert, Button, Card, ConfigProvider, Empty, Layout, Space, Table, Typography } from 'antd';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';

import { useTheme } from '@/hooks/useTheme';
import AppSidebar from '@/layouts/AppSidebar';
import Management from './Management';
import { loadStatus, statusKey, type WantGatesSnapshot } from './status';

type Connection = WantGatesSnapshot['connections'][number];

function label(value: string) {
  return value.replaceAll('_', ' ');
}

function timestamp(seconds: number) {
  return new Date(seconds * 1000).toLocaleString();
}

function ConnectionStatus({ connection }: { connection: Connection }) {
  const { verification } = connection;
  return (
    <Space orientation="vertical" size={2}>
      <span>Authentication · {label(connection.authentication || 'unknown')}</span>
      <span>
        Health · {label(connection.health?.state ?? 'not checked')}
        {connection.health?.reason ? ` (${label(connection.health.reason)})` : ''}
      </span>
      <span>Routing · {label(connection.runtime_reason || connection.runtime || 'unknown')}</span>
      {verification.observed_at && <span>Checked · {timestamp(verification.observed_at)}</span>}
    </Space>
  );
}

function Capabilities({ connection }: { connection: Connection }) {
  const checks = connection.verification.capabilities;
  return (
    <Space orientation="vertical" size={2}>
      {(['tcp_ipv4', 'udp_ipv4', 'tcp_ipv6', 'udp_ipv6'] as const).map((capability) => (
        <span key={capability}>
          {label(capability).toUpperCase()} · {label(checks?.[capability]?.state ?? 'not checked')}
          {checks?.[capability]?.reason && ` (${label(checks[capability].reason)})`}
        </span>
      ))}
      <span>DNS · {label(connection.verification.dns.reason || 'not checked')}</span>
    </Space>
  );
}

export function WantGatesStatus({ state }: { state: WantGatesSnapshot }) {
  const { routing } = state;
  const last = routing.last_observation;
  const desiredChanged =
    last.running_revision !== null && last.running_revision !== routing.desired_revision;
  const groupNames = new Map(state.groups.map((group) => [group.id, group.name]));
  const connectionNames = new Map(
    state.connections.map((connection) => [connection.id, connection.name]),
  );
  const name = (id: string) => connectionNames.get(id) ?? id;

  return (
    <>
      <Card>
        <Typography.Title level={2}>Routing status</Typography.Title>
        <p>Desired revision {routing.desired_revision}</p>
        <p>
          {last.running_revision === null
            ? 'Running revision unavailable'
            : `Last observed revision ${last.running_revision}`}
          {' · '}
          {label(last.state)}
          {last.observed_at && ` · ${timestamp(last.observed_at)}`}
        </p>
        {routing.recovery_required && (
          <Alert type="error" title="Routing recovery required" showIcon />
        )}
        {routing.busy && <Alert type="info" title="Routing operation in progress" showIcon />}
        {routing.health_error && (
          <Alert
            type="warning"
            title="Health checks paused"
            description={`Last observed routing may be stale. ${label(routing.health_error)}.`}
            showIcon
          />
        )}
        {(desiredChanged || last.mismatch) && (
          <Alert type="warning" title="Desired and observed routing differ" showIcon />
        )}
      </Card>

      <Card>
        <Typography.Title level={2}>Company groups</Typography.Title>
        {state.groups.length === 0 ? (
          <Empty description="No company groups configured" />
        ) : (
          <Table
            rowKey="id"
            dataSource={state.groups}
            pagination={{ pageSize: 10, hideOnSinglePage: true }}
            scroll={{ x: 640 }}
            columns={[
              { title: 'Group', dataIndex: 'name' },
              {
                title: 'Desired primary',
                render: (_, row) => (row.primary ? name(row.primary) : 'None'),
              },
              {
                title: 'Desired reserves',
                render: (_, row) => row.fallbacks.map(name).join(', ') || 'None',
              },
              {
                title: 'Last observed selection',
                render: (_, row) => {
                  const selected = row.last_observed_selection;
                  return selected ? `${selected.name} (${selected.protocol})` : 'Unavailable';
                },
              },
            ]}
          />
        )}
      </Card>

      <Card>
        <Typography.Title level={2}>Connections</Typography.Title>
        {state.connections.length === 0 ? (
          <Empty description="No connections configured" />
        ) : (
          <Table
            rowKey="id"
            dataSource={state.connections}
            pagination={{ pageSize: 10, hideOnSinglePage: true }}
            scroll={{ x: 800 }}
            columns={[
              {
                title: 'Company group',
                render: (_, row) => groupNames.get(row.group_id) ?? row.group_id,
              },
              { title: 'Connection', dataIndex: 'name' },
              { title: 'Protocol', dataIndex: 'protocol' },
              {
                title: 'Capability observations',
                render: (_, row) => <Capabilities connection={row} />,
              },
              {
                title: 'Connection status',
                render: (_, row) => <ConnectionStatus connection={row} />,
              },
            ]}
          />
        )}
      </Card>

      <Card>
        <Typography.Title level={2}>Desired destination rules</Typography.Title>
        {state.rules.length === 0 ? (
          <Empty description="No destination rules configured" />
        ) : (
          <Table
            rowKey="id"
            dataSource={state.rules}
            pagination={{ pageSize: 10, hideOnSinglePage: true }}
            scroll={{ x: 400 }}
            columns={[
              { title: 'Destination', dataIndex: 'destination' },
              {
                title: 'Company group',
                render: (_, row) => groupNames.get(row.group_id) ?? row.group_id,
              },
            ]}
          />
        )}
      </Card>
    </>
  );
}

export default function WantGatesPage() {
  const { t } = useTranslation();
  const { isDark, isUltra, antdThemeConfig } = useTheme();
  const query = useQuery({ queryKey: statusKey, queryFn: loadStatus, retry: false });
  const pageClass = ['want-gates-page', isDark && 'is-dark', isUltra && 'is-ultra']
    .filter(Boolean)
    .join(' ');

  return (
    <ConfigProvider theme={antdThemeConfig}>
      <Layout className={pageClass}>
        <AppSidebar />
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area">
            <Space orientation="vertical" size="middle" style={{ display: 'flex' }}>
              <Typography.Title level={1}>Want Gates</Typography.Title>
              <Button loading={query.isFetching} onClick={() => void query.refetch()}>
                {t('refresh')}
              </Button>
              {query.isPending && <p role="status">Loading Want Gates status</p>}
              {query.isError && <Alert type="error" title={query.error.message} showIcon />}
              {!query.isError && query.data && (
                <>
                  <Management state={query.data} refresh={() => void query.refetch()} />
                  <WantGatesStatus state={query.data} />
                </>
              )}
            </Space>
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
