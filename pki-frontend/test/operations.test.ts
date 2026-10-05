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

import { afterEach, describe, expect, it, vi } from 'vitest';
import { executeOperation, loadOperationDescriptors } from '@/api/operations';
import { operationSpec } from '@/api/operationCatalog';
import { resetTransport, setTransport, type Transport } from '@/api/transport';

const spec = operationSpec('credential.issue')!;
const values = { issuerCaId: 'ca-1', requestId: 'csr-1', profileId: 'tls' };
const envelope = (status: string, result: unknown = null, failure: unknown = null) => ({
  version: 1, requestId: 'req-1', operation: 'credential.issue', status, result, failure,
});
const response = (status: number, body: unknown, headers = {}) => ({ status, headers, body: JSON.stringify(body) });
const failure = (classification: string) => ({ classification, code: classification, messageKey: classification,
  recoveryRequired: classification === 'RECOVERY_REQUIRED', reconciliationRequired: classification === 'EXTERNAL_OUTCOME_UNKNOWN' });
const pending = response(202, envelope('PENDING', { operationId: 'sign:1' }));

function transport(...responses: ReturnType<typeof response>[]) {
  const mock = vi.fn<Transport>();
  for (const res of responses) mock.mockResolvedValueOnce(res);
  setTransport(mock);
  return mock;
}

afterEach(() => { resetTransport(); vi.useRealTimers(); });

describe('Authenticated operation discovery', () => {
  const descriptor = { operation: 'ca.create', family: 'SIGNING_OPERATION', mutating: true,
    resourceType: 'AUTHORITY', approval: 'HIGH_RISK', dataView: 'METADATA_REDACTED' };
  const discovery = (result: unknown) => ({ version: 1, requestId: 'discovery', operation: 'operation.list',
    status: 'SUCCEEDED', failure: null, result });

  it('unwraps the real server envelope and preserves a successfully empty result', async () => {
    transport(response(200, discovery({ count: 1, operations: [descriptor] })),
      response(200, discovery({ count: 0, operations: [] })));
    expect(await loadOperationDescriptors()).toEqual({ count: 1, operations: [descriptor] });
    expect(await loadOperationDescriptors()).toEqual({ count: 0, operations: [] });
  });

  it.each([
    { count: 1, operations: [descriptor] },
    discovery({ count: 2, operations: [descriptor] }),
    discovery({ count: 2, operations: [descriptor, descriptor] }),
    discovery({ count: 1, operations: [{ ...descriptor, mutating: 'true' }] }),
    discovery({ count: 1, operations: [{ ...descriptor, family: ['PKI_OPERATION'] }] }),
    { ...discovery({ count: 1, operations: [descriptor] }), status: 'FAILED' },
    { ...discovery({ count: 1, operations: [descriptor] }), operation: 'unrelated.list' },
  ])('rejects malformed or unsuccessful discovery without a static fallback', async (body) => {
    transport(response(200, body));
    await expect(loadOperationDescriptors()).rejects.toMatchObject({ code: 'invalid_operation_response' });
  });

  it('does not accept denied discovery', async () => {
    transport(response(403, { ...discovery(null), status: 'FAILED', failure: failure('AUTHORIZATION_DENIED') }));
    await expect(loadOperationDescriptors()).rejects.toBeDefined();
  });
});

describe('Asynchronous signing operation contract', () => {
  it.each(['CONFLICT', 'EXTERNAL_OUTCOME_UNKNOWN'])('does not turn HTTP 409 %s into approval', async (code) => {
    const mock = transport(response(409, envelope('FAILED', null, failure(code))));
    expect(await executeOperation(spec, values)).toMatchObject({ kind: 'failed', envelope: { failure: failure(code) } });
    expect(mock).toHaveBeenCalledOnce();
  });

  it('accepts only explicit approval and its commitment', async () => {
    transport(response(409, envelope('APPROVAL_REQUIRED', { operationCommitment: 'abc' }, failure('APPROVAL_REQUIRED'))));
    expect(await executeOperation(spec, values)).toMatchObject({ kind: 'approval-required', operationCommitment: 'abc' });
  });

  it.each([{}, { location: '/admin/v1/signing-operations/wrong' }])('uses body identity regardless of Location %j', async (headers) => {
    vi.useFakeTimers();
    const result = { operationId: 'sign:1', kind: 'ISSUANCE', encoding: 'DER', resultSha256: 'a'.repeat(64), credentialId: 'cred-1' };
    const mock = transport({ ...pending, headers }, pending, response(200, envelope('SUCCEEDED', result)));
    const task = executeOperation(spec, values);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await task).toMatchObject({ kind: 'succeeded', envelope: { result } });
    expect(mock.mock.calls.map(([req]) => [req.method, req.path])).toEqual([
      ['POST', '/admin/v1/operations/credential.issue'],
      ['GET', '/admin/v1/signing-operations/sign%3A1'],
      ['GET', '/admin/v1/signing-operations/sign%3A1'],
    ]);
  });

  it.each([undefined, 123, '', 'bad/id'])('rejects malformed pending identity %s', async (operationId) => {
    const mock = transport(response(202, envelope('PENDING', { operationId }), { location: '/admin/v1/signing-operations/fallback' }));
    await expect(executeOperation(spec, values)).rejects.toMatchObject({ code: 'invalid_operation_response' });
    expect(mock).toHaveBeenCalledOnce();
  });

  it.each([[404, 'NOT_FOUND'], [422, 'POLICY_REJECTION'], [429, 'OVERLOADED'], [503, 'RECOVERY_REQUIRED'], [504, 'CANCELLED']] as const)(
    'preserves polling failure %s %s', async (status, classification) => {
      vi.useFakeTimers();
      transport(pending, response(status, envelope('FAILED', null, failure(classification))));
      const task = executeOperation(spec, values);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(await task).toMatchObject({ kind: 'failed', envelope: { failure: failure(classification) } });
    });

  it.each([
    { operationId: 'other', kind: 'CA', encoding: 'DER', resultSha256: 'a'.repeat(64) },
    { operationId: 'sign:1', kind: ['CA'], encoding: 'DER', resultSha256: 'a'.repeat(64) },
    { operationId: 'sign:1', encoding: 'DER', resultSha256: 'a'.repeat(64) },
    { operationId: 'sign:1', kind: 'CA', encoding: 'DER', resultSha256: 'invalid' },
    { operationId: 'sign:1', kind: 'CA', resultSha256: 'a'.repeat(64) },
  ])('rejects malformed or mismatched terminal projection %j', async (result) => {
    vi.useFakeTimers();
    transport(pending, response(200, envelope('SUCCEEDED', result)));
    const task = executeOperation(spec, values);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await task).toMatchObject({ kind: 'pending', operationId: 'sign:1', pollingError: expect.any(String) });
  });

  it('retains the latest pending response when local waiting ends', async () => {
    vi.useFakeTimers();
    const latest = { ...envelope('PENDING', { operationId: 'sign:1' }), requestId: 'latest' };
    const mock = transport(pending, response(202, latest));
    const task = executeOperation(spec, values, { maxPendingWaitMs: 1_500 });
    await vi.advanceTimersByTimeAsync(1_500);
    expect(await task).toMatchObject({ kind: 'pending', operationId: 'sign:1', envelope: latest });
    expect(mock).toHaveBeenCalledTimes(2);
  });

  it('retains the accepted identity on a polling network error without resubmission', async () => {
    vi.useFakeTimers();
    const mock = transport(pending);
    mock.mockRejectedValueOnce(new Error('Connection lost'));
    const task = executeOperation(spec, values);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await task).toMatchObject({ kind: 'pending', operationId: 'sign:1', pollingError: 'Connection lost' });
    expect(mock).toHaveBeenCalledTimes(2);
  });

  it('bounds an in-flight polling request by aborting it at the local deadline', async () => {
    vi.useFakeTimers();
    const mock = transport(pending);
    mock.mockImplementationOnce((req) => new Promise((_, reject) => {
      req.signal?.addEventListener('abort', () => reject(new Error('aborted')));
    }));
    const task = executeOperation(spec, values, { maxPendingWaitMs: 2_000 });
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await task).toMatchObject({ kind: 'pending', operationId: 'sign:1', pollingError: expect.stringContaining('wait budget') });
  });

  it('does not interpret a malformed polling response as terminal failure', async () => {
    vi.useFakeTimers();
    transport(pending, response(503, 'proxy unavailable'));
    const task = executeOperation(spec, values);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await task).toMatchObject({ kind: 'pending', operationId: 'sign:1', pollingError: expect.any(String) });
  });
});
