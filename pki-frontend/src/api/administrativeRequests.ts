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

import { z } from 'zod';
import { api, ApiRequestError, postRaw } from '@/api/client';
import type { OperationRequest } from '@/api/types';

/** Authoritative lifecycle states returned by the server-owned request coordinator. */
export const REQUEST_STATES = ['WAITING_APPROVAL', 'READY', 'DISPATCHING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'REJECTED', 'EXPIRED', 'RECONCILIATION_REQUIRED'] as const;
const projection = z.object({
  requestId: z.string().min(1), operation: z.string().min(1), state: z.enum(REQUEST_STATES),
  requesterPrincipalId: z.string().min(1), createdAt: z.string().min(1), updatedAt: z.string().min(1),
  summary: z.string().optional(), executionTimeout: z.string().optional(), approvalId: z.string().optional(), signingOperationId: z.string().optional(),
  result: z.record(z.unknown()).optional(), failureCode: z.string().optional(),
  target: z.object({ authorityId: z.string().optional(), arguments: z.record(z.unknown()) }).optional(),
});

/** Authorized projection of one durable administrative request; list rows omit sensitive target data. */
export type AdministrativeRequest = z.infer<typeof projection>;
/** One immutable intent submitted once, before any required human approval. */
export interface AdministrativeRequestSubmission {
  readonly version: 1;
  readonly requestId: string;
  readonly operation: string;
  readonly authorityId?: string;
  readonly arguments: Record<string, unknown>;
  /** ISO-8601 execution budget applied after approval, not a deadline for human review. */
  readonly deadline?: string;
}
/** Bounded server worklist page. */
export interface AdministrativeRequestPage {
  readonly requests: AdministrativeRequest[];
  readonly nextOffset: number;
  readonly hasMore: boolean;
}

function envelope(operation: string, result: z.ZodTypeAny) {
  return z.object({ version: z.literal(1), requestId: z.string(), operation: z.literal(operation),
    status: z.enum(['SUCCEEDED', 'PENDING']), result, failure: z.null() });
}

/**
 * Creates the stable identity retained before the first submission attempt.
 * @returns A browser-generated request ID containing no operation arguments.
 */
export function newAdministrativeRequestId(): string { return `request-${crypto.randomUUID()}`; }

/**
 * Builds a durable intent from the existing typed operation request.
 * @param requestId Stable identity generated before submitting the operation.
 * @param operation Exact catalog operation ID.
 * @param request Existing typed arguments, scope and optional execution budget.
 * @returns The immutable wire intent; approval requirements remain server decisions.
 */
export function administrativeSubmission(requestId: string, operation: string, request: OperationRequest): AdministrativeRequestSubmission {
  return { version: 1, requestId, operation, arguments: request.arguments,
    ...(request.authorityId ? { authorityId: request.authorityId } : {}), ...(request.deadline ? { deadline: request.deadline } : {}) };
}

/**
 * Submits one intent without retries; a lost response must be resolved by GET using its ID.
 * @param intent Immutable operation intent, including its already generated request ID.
 * @returns The durable server projection after an HTTP 202 acknowledgement.
 * @throws ApiRequestError When submission is rejected or its acknowledgement is invalid.
 */
export async function submitAdministrativeRequest(intent: AdministrativeRequestSubmission): Promise<AdministrativeRequest> {
  const raw = await postRaw('/admin/v1/requests', intent);
  if (raw.status !== 202) {
    const failed = raw.body !== null && typeof raw.body === 'object' ? raw.body as Record<string, unknown> : undefined;
    const failure = failed?.failure !== null && typeof failed?.failure === 'object' ? failed.failure as Record<string, unknown> : undefined;
    const code = typeof failure?.code === 'string' && /^[A-Z0-9_]{1,128}$/.test(failure.code) ? failure.code : 'administrative_request_not_acknowledged';
    throw new ApiRequestError({ status: raw.status, code,
      message: `Submission rejected: ${code} (HTTP ${raw.status}). No durable acknowledgement was received.` });
  }
  const decoded = envelope('administrative.request.submit', projection).parse(raw.body).result as AdministrativeRequest;
  if (decoded.requestId !== intent.requestId || decoded.operation !== intent.operation) throw new ApiRequestError({
    status: raw.status, code: 'invalid_request_acknowledgement', message: 'The server acknowledgement does not match this request. Inspect the retained ID.' });
  return decoded;
}

/**
 * Reads one request; observing it never dispatches or repeats its operation from the browser.
 * @param requestId Retained durable request identity.
 * @param signal Optional cancellation of this read only.
 * @returns The latest authorized projection.
 */
export async function inspectAdministrativeRequest(requestId: string, signal?: AbortSignal): Promise<AdministrativeRequest> {
  return envelope('administrative.request.inspect', projection).parse(
    await api.get<unknown>(`/admin/v1/requests/${encodeURIComponent(requestId)}`, { signal })).result as AdministrativeRequest;
}

/**
 * Reads a bounded worklist page without persisting operation arguments in browser storage.
 * @param offset Zero-based server pagination offset.
 * @param state Optional authoritative lifecycle state filter.
 * @param signal Optional cancellation of the list read.
 * @param operation Optional exact operation filter applied by the server.
 * @returns Server-selected rows and pagination state.
 */
export async function listAdministrativeRequests(offset = 0, state?: string, signal?: AbortSignal, operation?: string): Promise<AdministrativeRequestPage> {
  const page = z.object({ requests: z.array(projection), nextOffset: z.number().int().nonnegative(), hasMore: z.boolean() });
  return envelope('administrative.request.list', page).parse(await api.get<unknown>('/admin/v1/requests', {
    query: { offset, limit: 25, ...(state ? { state } : {}), ...(operation ? { operation } : {}) }, signal,
  })).result as AdministrativeRequestPage;
}

/**
 * Indicates whether observation can stop automatically.
 * @param state Current server lifecycle state.
 * @returns True for an authoritative terminal state.
 */
export function administrativeRequestTerminal(state: AdministrativeRequest['state']): boolean {
  return ['SUCCEEDED', 'FAILED', 'REJECTED', 'EXPIRED', 'RECONCILIATION_REQUIRED'].includes(state);
}

/**
 * Returns the stable browser detail route for one request.
 * @param requestId Durable request identity.
 * @returns Same-origin application route.
 */
export function administrativeRequestPath(requestId: string): string { return `/administrative-requests/${encodeURIComponent(requestId)}`; }
