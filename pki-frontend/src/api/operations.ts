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
import { ApiRequestError, api, getRaw, postRaw, type RawResult } from '@/api/client';
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
  readonly signal?: AbortSignal;
  readonly approvalId?: string;
  readonly deadline?: string;
  /** Maximum time to keep polling a PENDING signing operation (ms). */
  readonly maxPendingWaitMs?: number;
}

export type PendingOutcome = {
  readonly kind: 'pending';
  readonly envelope: OperationEnvelope;
  readonly operationId: string;
  /** A local polling error does not change the last authoritative server outcome. */
  readonly pollingError?: string;
};

export type ExecuteOutcome =
  | { readonly kind: 'succeeded'; readonly envelope: OperationEnvelope }
  | { readonly kind: 'failed'; readonly envelope: OperationEnvelope }
  | { readonly kind: 'approval-required'; readonly envelope: OperationEnvelope; readonly operationCommitment: string }
  | PendingOutcome;

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function protocolError(status: number): never {
  throw new ApiRequestError({ status, code: 'invalid_operation_response', message: 'Invalid operation response from the server.' });
}

/** Decode the public envelope, without inferring success or approval from an HTTP code. */
function classify(raw: RawResult): ExecuteOutcome {
  const { status, body } = raw;
  if (!object(body) || body.version !== 1 || typeof body.requestId !== 'string'
      || typeof body.operation !== 'string' || !(body.result === null || object(body.result))) {
    return protocolError(status);
  }
  if (body.failure !== null && (!object(body.failure)
      || typeof body.failure.classification !== 'string' || typeof body.failure.code !== 'string'
      || typeof body.failure.messageKey !== 'string' || typeof body.failure.recoveryRequired !== 'boolean'
      || typeof body.failure.reconciliationRequired !== 'boolean')) return protocolError(status);
  const envelope = body as unknown as OperationEnvelope;
  if (body.status === 'APPROVAL_REQUIRED' && status === 409
      && envelope.failure?.code === 'APPROVAL_REQUIRED'
      && typeof envelope.result?.operationCommitment === 'string' && envelope.result.operationCommitment) {
    return { kind: 'approval-required', envelope, operationCommitment: envelope.result.operationCommitment };
  }
  if (body.status === 'PENDING' && status === 202 && body.failure === null) {
    const id = envelope.result?.operationId;
    if (typeof id !== 'string' || !id.trim() || id.length > 512 || id.includes('/')) return protocolError(status);
    return { kind: 'pending', envelope, operationId: id };
  }
  if (body.status === 'SUCCEEDED' && status >= 200 && status < 300 && body.failure === null) {
    return { kind: 'succeeded', envelope };
  }
  if (body.status === 'FAILED' && status >= 400 && envelope.failure) return { kind: 'failed', envelope };
  return protocolError(status);
}

function validateSigningCompletion(result: Record<string, unknown> | null, operationId: string): void {
  if (!result || result.operationId !== operationId
      || typeof result.kind !== 'string' || !['CA', 'ISSUANCE', 'STATUS'].includes(result.kind)
      || typeof result.encoding !== 'string' || !result.encoding
      || typeof result.resultSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(result.resultSha256)
      || (result.credentialId !== undefined && (typeof result.credentialId !== 'string' || !result.credentialId))
      || (result.statusObjectId !== undefined && (typeof result.statusObjectId !== 'string' || !result.statusObjectId))) {
    protocolError(200);
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Sequential, bounded polling. Keeps only the latest response, never replays submission. */
export async function pollOperation(initial: PendingOutcome, maxWaitMs = 30_000): Promise<ExecuteOutcome> {
  if (!Number.isFinite(maxWaitMs) || maxWaitMs < 0) throw new Error('Polling wait must be finite and non-negative');
  const deadline = Date.now() + maxWaitMs;
  let pending: PendingOutcome = { kind: 'pending', envelope: initial.envelope, operationId: initial.operationId };
  while (Date.now() < deadline) {
    await sleep(Math.min(1_000, deadline - Date.now()));
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);
    try {
      const outcome = classify(await getRaw(`/admin/v1/signing-operations/${encodeURIComponent(initial.operationId)}`, controller.signal));
      if (outcome.kind === 'approval-required') return protocolError(409);
      if (outcome.kind === 'succeeded') validateSigningCompletion(outcome.envelope.result, initial.operationId);
      if (outcome.kind !== 'pending') return outcome;
      if (outcome.operationId !== initial.operationId) return protocolError(202);
      pending = outcome;
    } catch (error) {
      return { ...pending, pollingError: controller.signal.aborted
        ? 'The local wait budget elapsed while checking the operation.'
        : error instanceof Error ? error.message : 'Unable to check the operation.' };
    } finally {
      clearTimeout(timer);
    }
  }
  return pending;
}

/** Submit once; accepted local and remote signing work both return PENDING. */
export async function executeOperation(
  spec: OperationSpec,
  values: Record<string, FieldValue>,
  extra: ExecuteExtras = {},
): Promise<ExecuteOutcome> {
  if (extra.maxPendingWaitMs !== undefined && (!Number.isFinite(extra.maxPendingWaitMs) || extra.maxPendingWaitMs < 0)) {
    throw new Error('Polling wait must be finite and non-negative');
  }
  const { path, request } = buildRequest(spec, values, extra);
  const outcome = classify(await postRaw(path, request, extra.signal));
  return outcome.kind === 'pending' ? pollOperation(outcome, extra.maxPendingWaitMs) : outcome;
}
