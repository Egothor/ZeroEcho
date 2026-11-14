/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
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

import { afterEach, expect, it, vi } from 'vitest';
import { setTransport, resetTransport } from '@/api/transport';
import { administrativeSubmission, inspectAdministrativeRequest, listAdministrativeRequests, submitAdministrativeRequest } from '@/api/administrativeRequests';

afterEach(resetTransport);
const record = { requestId: 'request-stable', operation: 'ca.create', state: 'WAITING_APPROVAL', requesterPrincipalId: 'admin',
  createdAt: '2026-11-13T12:00:00Z', updatedAt: '2026-11-13T12:00:00Z', approvalId: 'approval-linked', executionTimeout: 'PT30S' };
const envelope = (operation: string, result: unknown, status = 'SUCCEEDED') => ({ version: 1, requestId: 'transport-id', operation, status, result, failure: null });
it('preserves the execution budget and typed target without a manually chosen approval', async () => {
  const transport = vi.fn(async () => ({ status: 202, headers: {}, body: JSON.stringify(envelope('administrative.request.submit', record, 'PENDING')) }));
  setTransport(transport);
  const intent = administrativeSubmission('request-stable', 'ca.create', { version: 1, authorityId: 'ca:parent', approvalId: 'must-not-be-forwarded', deadline: 'PT30S', arguments: { subjectRef: 'CN=Root', nested: { unchanged: true } } });
  expect(intent).toEqual({ version: 1, requestId: 'request-stable', operation: 'ca.create', authorityId: 'ca:parent', deadline: 'PT30S', arguments: { subjectRef: 'CN=Root', nested: { unchanged: true } } });
  expect(await submitAdministrativeRequest(intent)).toEqual(record);
  expect(transport).toHaveBeenCalledOnce();
});
it('rejects an acknowledgement for another intent and never retries', async () => {
  const transport = vi.fn(async () => ({ status: 202, headers: {}, body: JSON.stringify(envelope('administrative.request.submit', { ...record, requestId: 'different' }, 'PENDING')) }));
  setTransport(transport);
  await expect(submitAdministrativeRequest({ version: 1, requestId: 'request-stable', operation: 'ca.create', arguments: {} })).rejects.toThrow(/does not match/);
  expect(transport).toHaveBeenCalledOnce();
});
it('observes a lost submission response by the same stable ID without another POST', async () => {
  const transport = vi.fn(async request => {
    if (request.method === 'POST') throw new Error('Connection lost after acceptance');
    return { status: 200, headers: {}, body: JSON.stringify(envelope('administrative.request.inspect', record)) };
  });
  setTransport(transport);
  const intent = { version: 1 as const, requestId: 'request-stable', operation: 'ca.create', arguments: {} };
  await expect(submitAdministrativeRequest(intent)).rejects.toThrow(/Connection lost/);
  expect(await inspectAdministrativeRequest(intent.requestId)).toEqual(record);
  expect(transport.mock.calls.map(([request]) => request.method)).toEqual(['POST', 'GET']);
});
it('validates paged worklist responses and forwards the state filter', async () => {
  const transport = vi.fn(async request => {
    expect(request.query).toMatchObject({ offset: 25, limit: 25, state: 'WAITING_APPROVAL' });
    return { status: 200, headers: {}, body: JSON.stringify(envelope('administrative.request.list', { requests: [record], nextOffset: 50, hasMore: true })) };
  });
  setTransport(transport);
  expect((await listAdministrativeRequests(25, 'WAITING_APPROVAL')).requests[0]?.requestId).toBe('request-stable');
});
