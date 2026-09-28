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

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { expect, it, vi } from 'vitest';
import type * as Operations from '@/api/operations';
import { buildRequest, executeOperation, type FieldValue, type ExecuteExtras } from '@/api/operations';
import type { OperationSpec } from '@/api/operationSchema';
import { OperationRunner } from '@/components/operation/OperationRunner';

vi.mock('@/api/operations', async (original) => ({
  ...await original<typeof Operations>(), executeOperation: vi.fn(),
}));
// Isolate runner handoff from selector fetching; the real typed request builder remains in use.
vi.mock('@/components/operation/OperationForm', () => ({
  OperationForm: ({ spec, initialValues, onSubmit }: {
    spec: OperationSpec;
    initialValues: Record<string, FieldValue>;
    onSubmit: (values: Record<string, FieldValue>, extra: ExecuteExtras) => void;
  }) => <button onClick={() => onSubmit({ ...initialValues, response: 'AQID' }, {})}>Submit {spec.id}</button>,
}));

it('carries exact server confirmation preconditions and submitted authority into Complete proof', async () => {
  const challenge = {
    credentialId: 'credential:confirmed-by-server', expectedLifecycleRevision: 17,
    expectedLifecycleRecordCommitment: 'ab'.repeat(32), expectedChallengeRecordCommitment: 'cd'.repeat(32),
    challenge: 'server-owned-challenge',
  };
  vi.mocked(executeOperation).mockResolvedValue({ kind: 'succeeded', envelope: {
    version: 1, requestId: 'request:challenge', operation: 'credential.confirmation.challenge.issue',
    status: 'SUCCEEDED', failure: null, result: challenge,
  } });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><OperationRunner operationId="credential.confirmation.challenge.issue"
    initialValues={{ __authorityId: 'ca:selected', credentialId: 'credential:submitted' }} /></QueryClientProvider>);
  fireEvent.click(screen.getByRole('button', { name: 'Submit credential.confirmation.challenge.issue' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Complete proof' }));
  fireEvent.click(screen.getByRole('button', { name: 'Submit credential.confirmation.proof.complete' }));
  await waitFor(() => expect(executeOperation).toHaveBeenCalledTimes(2));
  const [spec, values] = vi.mocked(executeOperation).mock.calls[1]!;
  expect(buildRequest(spec, values)).toEqual({
    path: '/admin/v1/operations/credential.confirmation.proof.complete',
    request: { version: 1, authorityId: 'ca:selected', arguments: {
      credentialId: challenge.credentialId, expectedLifecycleRevision: 17,
      expectedLifecycleRecordCommitment: challenge.expectedLifecycleRecordCommitment,
      expectedChallengeRecordCommitment: challenge.expectedChallengeRecordCommitment, response: 'AQID',
    } },
  });
  client.clear();
});
