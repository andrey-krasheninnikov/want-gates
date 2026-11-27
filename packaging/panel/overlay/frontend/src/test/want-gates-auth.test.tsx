import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { BrowserChallenge, challengeFields } from '@/pages/want-gates/AuthDialog';
import type { AuthState } from '@/pages/want-gates/operations';

const pending: AuthState = {
  authentication: 'challenge_required',
  challenge_id: 'current',
  expires_at: 2000000000,
  remembered: false,
};

describe('Want Gates native challenges', () => {
  it('uses adapter-specific inputs and leaves WireGuard keys in the profile', () => {
    expect(challengeFields('openvpn', { ...pending, method: 'static' })).toEqual([
      'username',
      'password',
      'response',
    ]);
    expect(challengeFields('openvpn', { ...pending, method: 'private_key' })).toEqual([
      'private_key_password',
    ]);
    expect(challengeFields('openvpn', { ...pending, method: 'dynamic' })).toEqual([
      'username',
      'response',
    ]);
    expect(challengeFields('forti', { ...pending, method: 'text' })).toEqual(['response']);
    expect(challengeFields('forti', pending, 'cookie')).toEqual(['cookie']);
    expect(challengeFields('forti', pending, 'certificate')).toEqual(['private_key_password']);
    expect(
      challengeFields('netbird', { ...pending, authentication: 'credentials_required' }),
    ).toEqual(['setup_key']);
    expect(challengeFields('wireguard')).toEqual([]);
  });

  it('renders provider links with the matching device code or forwarded callback', () => {
    const browser = {
      ...pending,
      authentication: 'browser_required',
      url: 'https://login.example.org/start',
    };
    const { rerender } = render(<BrowserChallenge auth={{ ...browser, user_code: 'M4FA-TEST' }} />);
    expect(screen.getByRole('link', { name: 'Open VPN sign-in' }).getAttribute('rel')).toBe(
      'noopener noreferrer',
    );
    expect(screen.getByText('M4FA-TEST')).toBeTruthy();
    rerender(
      <BrowserChallenge
        auth={{
          ...browser,
          ssh_forward: {
            local_host: '127.0.0.1',
            local_port: 8020,
            remote_socket: '/run/wgates-native/saml-fixture.sock',
          },
        }}
      />,
    );
    expect(
      screen.getByText(/127\.0\.0\.1:8020:\/run\/wgates-native\/saml-fixture\.sock/),
    ).toBeTruthy();
  });
});
