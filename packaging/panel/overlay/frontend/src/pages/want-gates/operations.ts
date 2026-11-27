import { z } from 'zod';

import { HttpError, httpRequest } from '@/api/http-init';

export const capabilities = ['tcp_ipv4', 'udp_ipv4', 'tcp_ipv6', 'udp_ipv6'] as const;
export const protocols = ['vless', 'openvpn', 'forti', 'wireguard', 'netbird'] as const;

const revision = z.string().regex(/^\d+$/);
const nonempty = z.string().min(1);
const change = z.object({
  kind: z.enum(['rule', 'group', 'connection']),
  id: nonempty,
  before: z.array(z.string()).nullable(),
  after: z.array(z.string()).nullable(),
  notes: z.array(z.string()),
});

export const previewSchema = z.object({
  plan_id: nonempty,
  desired_revision: revision,
  base_revision: revision.nullable(),
  ingress: z.array(z.string()).nullable(),
  rules: z.array(z.object({ id: nonempty, destination: nonempty, group_id: nonempty })).nullable(),
  eligibility: z
    .record(
      z.string(),
      z.record(z.string(), z.object({ reason: nonempty, requires: nonempty.optional() })),
    )
    .nullable(),
  changes: z.array(change),
  prepared_connection_count: z.number().int().nonnegative(),
  unmatched: nonempty,
  unverified: nonempty,
  sessions_may_interrupt: z.boolean(),
});
export type Preview = z.infer<typeof previewSchema>;

export const outcomeSchema = z.object({
  plan_id: nonempty,
  state: nonempty,
  running_revision: revision.nullable(),
  mismatch: z.boolean(),
  native_cleanup_required: z.boolean(),
});
export type Outcome = z.infer<typeof outcomeSchema>;

export const authSchema = z.object({
  authentication: nonempty,
  challenge_id: nonempty.optional(),
  method: nonempty.optional(),
  methods: z.array(nonempty).optional(),
  prompt: z.string().optional(),
  url: z.url({ protocol: /^https$/ }).optional(),
  user_code: z.string().optional(),
  expires_at: z.number().nullable(),
  remembered: z.boolean(),
  ssh_forward: z
    .object({ local_host: nonempty, local_port: z.number().int(), remote_socket: nonempty })
    .optional(),
});
export type AuthState = z.infer<typeof authSchema>;

export const adapterSchema = z.object({ available: z.boolean(), reason: nonempty });

export class OperationError extends Error {
  constructor(
    message: string,
    readonly readbackRequired: boolean,
  ) {
    super(message);
  }
}

export async function operation<T>(
  schema: z.ZodType<T>,
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
    const reply = z.object({ success: z.literal(true), obj: schema }).safeParse(data);
    if (reply.success) return reply.data.obj as T;
  } catch (error) {
    if (error instanceof HttpError) {
      const reply = error.response.data as { msg?: unknown; readback_required?: unknown } | null;
      if (typeof reply?.msg === 'string') {
        throw new OperationError(
          reply.msg,
          error.status >= 500 || reply.readback_required === true,
        );
      }
    }
  }
  throw new OperationError(
    'The operation could not be confirmed. Refresh status before retrying.',
    true,
  );
}
