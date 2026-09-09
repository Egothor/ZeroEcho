/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

import { useQuery } from '@tanstack/react-query';
import { ApiRequestError, api, postRaw } from '@/api/client';
import type { OperationCatalogResponse, OperationDescriptor, OperationEnvelope, OperationRequest } from '@/api/types';
import type { FieldSpec, OperationSpec } from '@/api/operationSchema';

/** Fetch the operation descriptors the current principal may invoke. */
export function useOperationDescriptors() {
  return useQuery({
    queryKey: ['operations'],
    queryFn: () => api.get<OperationCatalogResponse>('/admin/v1/operations'),
    staleTime: 5 * 60_000,
  });
}

/** Index descriptors by operation id for quick lookup and discoverability checks. */
export function indexDescriptors(response: OperationCatalogResponse | undefined): Map<string, OperationDescriptor> {
  const map = new Map<string, OperationDescriptor>();
  for (const d of response?.operations ?? []) map.set(d.operation, d);
  return map;
}

/** A single form field value as held by the operation form. */
export type FieldValue = string | number | boolean | string[] | undefined;

function coerce(field: FieldSpec, value: FieldValue): unknown {
  switch (field.type) {
    case 'integer':
    case 'long': {
      if (value === '' || value === undefined) return undefined;
      const n = typeof value === 'number' ? value : Number(value);
      if (!Number.isFinite(n) || !Number.isInteger(n)) throw new Error(`${field.name} must be a whole number`);
      return n;
    }
    case 'boolean':
      return value === true || value === 'true';
    case 'enumSet':
    case 'stringSet':
      return Array.isArray(value) ? value : value ? String(value).split(',').map((s) => s.trim()).filter(Boolean) : [];
    case 'json': {
      if (value === '' || value === undefined) return undefined;
      if (typeof value === 'object') return value;
      return JSON.parse(String(value)) as unknown;
    }
    default: {
      if (value === '' || value === undefined) return undefined;
      return String(value);
    }
  }
}

/** Build the arguments object and top-level envelope for an operation execution. */
export function buildRequest(spec: OperationSpec, values: Record<string, FieldValue>, extra: ExecuteExtras = {}): {
  path: string;
  request: OperationRequest;
} {
  const args: Record<string, unknown> = {};
  for (const field of spec.fields) {
    const coerced = coerce(field, values[field.name]);
    if (coerced === undefined) {
      if (field.required) throw new Error(`${field.label ?? field.name} is required`);
      continue;
    }
    if ((field.type === 'enumSet' || field.type === 'stringSet') && Array.isArray(coerced) && coerced.length === 0) {
      if (field.required) throw new Error(`${field.label ?? field.name} is required`);
      continue;
    }
    args[field.name] = coerced;
  }

  const request: OperationRequest = { version: 1, arguments: args };
  if (spec.scope === 'authority') {
    const authorityId = spec.authorityFrom
      ? (args[spec.authorityFrom] as string | undefined)
      : (values['__authorityId'] as string | undefined)?.toString();
    if (!authorityId) throw new Error('An authority id is required for this operation');
    (request as { authorityId?: string }).authorityId = authorityId;
  }
  if (extra.approvalId) (request as { approvalId?: string }).approvalId = extra.approvalId;
  if (extra.deadline) (request as { deadline?: string }).deadline = extra.deadline;

  return { path: `/admin/v1/operations/${encodeURIComponent(spec.id)}`, request };
}

export interface ExecuteExtras {
  readonly approvalId?: string;
  readonly deadline?: string;
  /** Maximum time to keep polling a PENDING signing operation (ms). */
  readonly maxPendingWaitMs?: number;
}

export type ExecuteOutcome =
  | { readonly kind: 'succeeded'; readonly envelope: OperationEnvelope }
  | { readonly kind: 'failed'; readonly envelope: OperationEnvelope }
  | { readonly kind: 'approval-required'; readonly envelope: OperationEnvelope; readonly operationCommitment: string }
  | { readonly kind: 'pending'; readonly envelope: OperationEnvelope; readonly signingOperationId?: string };

function asEnvelope(body: unknown): OperationEnvelope {
  const b = (body ?? {}) as Partial<OperationEnvelope>;
  return {
    version: b.version ?? 1,
    requestId: b.requestId ?? '',
    operation: b.operation ?? '',
    status: b.status ?? 'FAILED',
    result: (b.result as Record<string, unknown> | null) ?? null,
    failure: (b.failure as OperationEnvelope['failure']) ?? null,
  };
}

function classify(status: number, envelope: OperationEnvelope, location?: string): ExecuteOutcome {
  if (envelope.status === 'APPROVAL_REQUIRED' || status === 409) {
    const commitment = (envelope.result?.['operationCommitment'] as string | undefined) ?? '';
    return { kind: 'approval-required', envelope, operationCommitment: commitment };
  }
  if (envelope.status === 'PENDING' || status === 202) {
    const id = location ? location.split('/').filter(Boolean).pop() : undefined;
    return id ? { kind: 'pending', envelope, signingOperationId: id } : { kind: 'pending', envelope };
  }
  if (envelope.status === 'SUCCEEDED' && status >= 200 && status < 300) return { kind: 'succeeded', envelope };
  return { kind: 'failed', envelope };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Execute an operation with the server's synchronous bounded-wait semantics.
 * A 202 PENDING signing hand-off is polled at `/admin/v1/signing-operations/{id}`
 * until it terminalizes or the pending-wait budget elapses.
 */
export async function executeOperation(
  spec: OperationSpec,
  values: Record<string, FieldValue>,
  extra: ExecuteExtras = {},
): Promise<ExecuteOutcome> {
  const { path, request } = buildRequest(spec, values, extra);
  const raw = await postRaw(path, request);
  let outcome = classify(raw.status, asEnvelope(raw.body), raw.headers['location']);

  if (outcome.kind === 'pending' && outcome.signingOperationId) {
    const deadline = Date.now() + (extra.maxPendingWaitMs ?? 30_000);
    const id = outcome.signingOperationId;
    while (Date.now() < deadline) {
      await sleep(1_000);
      let env: OperationEnvelope;
      try {
        env = await api.get<OperationEnvelope>(`/admin/v1/signing-operations/${encodeURIComponent(id)}`);
      } catch (e) {
        if (e instanceof ApiRequestError && e.body) {
          env = asEnvelope(e.body);
        } else {
          throw e;
        }
      }
      if (env.status !== 'PENDING') {
        outcome = classify(200, env);
        break;
      }
    }
  }
  return outcome;
}
