import { HttpError, httpRequest } from '@/api/http-init';

export const capabilities = ['tcp_ipv4', 'udp_ipv4', 'tcp_ipv6', 'udp_ipv6'] as const;
export const protocols = ['vless', 'openvpn', 'forti', 'wireguard', 'netbird'] as const;

export interface Preview {
  plan_id: string;
  desired_revision: string;
  ingress: string[] | null;
  rules: { id: string; destination: string; group_id: string }[] | null;
  eligibility: Record<string, Record<string, { reason: string; requires?: string }>> | null;
  prepared_connections: string[] | null;
  unmatched: string;
  unverified: string;
  sessions_may_interrupt: boolean;
}

export interface Outcome {
  plan_id: string;
  state: string;
  running_revision: string | null;
  mismatch: boolean;
  native_cleanup_required: boolean;
}

export interface AuthState {
  authentication: string;
  challenge_id?: string;
  method?: string;
  methods?: string[];
  prompt?: string;
  url?: string;
  user_code?: string;
  expires_at: number | null;
  remembered: boolean;
  ssh_forward?: { local_host: string; local_port: number; remote_socket: string };
}

export async function operation<T>(
  command: string,
  body: Record<string, unknown> = {},
  signal?: AbortSignal,
): Promise<T> {
  try {
    const { data } = await httpRequest(
      'POST',
      `/panel/api/want-gates/operations/${encodeURIComponent(command)}`,
      body,
      { headers: { 'Content-Type': 'application/json' }, timeout: 320_000, signal },
    );
    const reply = data as { success?: boolean; obj?: T } | null;
    if (!reply?.success || !Object.hasOwn(reply, 'obj')) {
      throw new Error('The service reply could not be confirmed. Refresh status before retrying.');
    }
    return reply.obj as T;
  } catch (error) {
    if (error instanceof HttpError) {
      const reply = error.response.data as { msg?: unknown } | null;
      if (typeof reply?.msg === 'string') throw new Error(reply.msg);
    }
    throw new Error('The operation could not be confirmed. Refresh status before retrying.');
  }
}
