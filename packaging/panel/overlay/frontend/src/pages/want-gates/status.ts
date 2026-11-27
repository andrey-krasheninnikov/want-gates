import { z } from 'zod';

import { HttpError, httpRequest } from '@/api/http-init';

export const statusKey = ['want-gates', 'status'] as const;
const statusPath = '/panel/api/want-gates/status';
const object = z.object({ id: z.string(), revision: z.string() });
const check = z.object({ state: z.string(), reason: z.string() });
const names = z
  .array(z.string())
  .nullable()
  .transform((value) => value ?? []);

const group = object.extend({
  name: z.string(),
  primary: z.string().nullable(),
  fallbacks: names,
  last_observed_selection: z
    .object({ id: z.string(), name: z.string(), protocol: z.string() })
    .nullable(),
});

const connection = object.extend({
  group_id: z.string(),
  name: z.string(),
  protocol: z.string(),
  dns: z.string().nullable(),
  allowed_capabilities: names,
  capabilities: names,
  authentication: z.string(),
  runtime: z.string(),
  runtime_reason: z.string(),
  health: check.extend({ eligible: z.boolean(), observed_at: z.number() }).nullable(),
  verification: z.object({
    capabilities: z.record(z.string(), check).nullable(),
    dns: check,
    observed_at: z.number().nullable(),
  }),
});

const snapshot = z.object({
  routing: z.object({
    desired_revision: z.string(),
    busy: z.boolean(),
    recovery_required: z.boolean(),
    health_error: z.string().nullable(),
    last_observation: z.object({
      state: z.string(),
      running_revision: z.string().nullable(),
      mismatch: z.boolean(),
      observed_at: z.number().nullable(),
    }),
  }),
  groups: z.array(group),
  connections: z.array(connection),
  rules: z.array(object.extend({ group_id: z.string(), destination: z.string() })),
});

export type WantGatesSnapshot = z.infer<typeof snapshot>;
const response = z.object({ success: z.literal(true), obj: snapshot });

export async function loadStatus({ signal }: { signal: AbortSignal }): Promise<WantGatesSnapshot> {
  try {
    const result = await httpRequest('GET', statusPath, undefined, { signal, timeout: 12_000 });
    const parsed = response.safeParse(result.data);
    if (!parsed.success) throw new Error('Want Gates returned an invalid status response.');
    return parsed.data.obj;
  } catch (error) {
    if (error instanceof HttpError && error.status === 409) {
      throw new Error(
        'Configuration or routing observation changed while loading. Refresh Want Gates status.',
      );
    }
    if (error instanceof HttpError && error.status === 503) {
      throw new Error(
        'Want Gates service is unavailable. Check the local service and socket access.',
      );
    }
    throw error;
  }
}
