import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { WantGatesStatus } from '@/pages/want-gates/WantGatesPage';
import type { WantGatesSnapshot } from '@/pages/want-gates/status';

function emptyStatus(): WantGatesSnapshot {
  return {
    routing: {
      desired_revision: '3',
      busy: false,
      recovery_required: false,
      health_error: null,
      last_observation: {
        state: 'unapplied',
        running_revision: null,
        mismatch: false,
        observed_at: null,
      },
    },
    groups: [],
    connections: [],
    rules: [],
  };
}

describe('Want Gates status', () => {
  it('shows the empty objects and separates unapplied desired routing', () => {
    render(<WantGatesStatus state={emptyStatus()} />);
    expect(screen.getByText('Desired revision 3')).toBeTruthy();
    expect(screen.getByText(/Running revision unavailable/)).toBeTruthy();
    expect(screen.getByText('No company groups configured')).toBeTruthy();
    expect(screen.getByText('No connections configured')).toBeTruthy();
    expect(screen.getByText('No destination rules configured')).toBeTruthy();
  });

  it('labels an observed selection, capability checks, and a pending change with text', () => {
    const state = emptyStatus();
    state.groups.push({
      id: 'g1',
      revision: '2',
      name: 'Company',
      primary: 'c3',
      fallbacks: [],
      last_observed_selection: { id: 'c2', name: 'Previous VPN', protocol: 'vless' },
    });
    state.connections.push({
      id: 'c3',
      revision: '3',
      group_id: 'g1',
      name: 'Company VPN',
      protocol: 'vless',
      dns: null,
      allowed_capabilities: ['tcp_ipv4'],
      capabilities: [],
      authentication: 'credentials_required',
      runtime: 'pending_apply',
      runtime_reason: 'desired_state_changed',
      health: null,
      verification: {
        capabilities: { tcp_ipv4: { state: 'verified', reason: 'verified' } },
        dns: { state: 'unverified', reason: 'not_checked' },
        observed_at: null,
      },
    });
    state.routing.last_observation.running_revision = '2';
    state.routing.last_observation.state = 'applied';
    state.routing.health_error = 'panel_drift';
    render(<WantGatesStatus state={state} />);
    expect(screen.getByText('Desired and observed routing differ')).toBeTruthy();
    expect(screen.getByText('Previous VPN (vless)')).toBeTruthy();
    expect(screen.getByText('Health checks paused')).toBeTruthy();
    expect(screen.getByText(/Authentication · credentials required/)).toBeTruthy();
    expect(screen.getByText(/TCP IPV4 · verified/)).toBeTruthy();
  });
});
