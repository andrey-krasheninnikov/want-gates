import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { httpRequest } from '@/api/http-init';
import AuthDialog, { BrowserChallenge, challengeFields } from '@/pages/want-gates/AuthDialog';
import type { AuthState } from '@/pages/want-gates/operations';

vi.mock('@/api/http-init', async (original) => ({
  ...(await original<typeof import('@/api/http-init')>()),
  httpRequest: vi.fn(),
}));

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
    expect(challengeFields('openvpn', { ...pending, method: 'dynamic' })).toEqual(['response']);
    expect(challengeFields('forti', { ...pending, method: 'text' })).toEqual(['response']);
    expect(challengeFields('forti', pending, 'cookie')).toEqual(['cookie', 'private_key_password']);
    expect(challengeFields('forti', pending, 'certificate')).toEqual(['private_key_password']);
    expect(
      challengeFields('netbird', { ...pending, authentication: 'credentials_required' }),
    ).toEqual(['setup_key']);
    expect(challengeFields('wireguard')).toEqual([]);
  });

  it('submits the dynamic response with the opened connection revision', async () => {
    const request = vi.mocked(httpRequest);
    const result = { ok: true, status: 200, statusText: 'OK' };
    request
      .mockResolvedValueOnce({
        ...result,
        data: { success: true, obj: { ...pending, method: 'dynamic' } },
      })
      .mockResolvedValueOnce({
        ...result,
        data: {
          success: true,
          obj: { authentication: 'authenticating', expires_at: null, remembered: false },
        },
      });
    render(
      <AuthDialog
        connection={{ id: 'c1', name: 'Test connection', protocol: 'openvpn', revision: '9' }}
        locked={false}
        close={() => undefined}
        refresh={() => undefined}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Check sign-in' }));
    fireEvent.change(await screen.findByLabelText('Challenge response'), {
      target: { value: 'TEST-OTP' },
    });
    expect(screen.queryByLabelText('Username')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Submit sign-in' }));
    await waitFor(() =>
      expect(request).toHaveBeenLastCalledWith(
        'POST',
        '/panel/api/want-gates/operations/connection.login',
        {
          id: 'c1',
          expected_revision: '9',
          credentials: { challenge_id: 'current', response: 'TEST-OTP' },
        },
        expect.anything(),
      ),
    );
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
