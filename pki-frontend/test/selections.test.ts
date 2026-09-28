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

import type * as Operations from '@/api/operations';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { loadEntityOptions } from '@/hooks/useEntityOptions';
import { REF_SOURCES } from '@/api/entityRefs';
import { changeFormValue, selectionFields } from '@/api/formSelections';
import { operationSpec } from '@/api/operationCatalog';
import { buildRequest, executeOperation } from '@/api/operations';
vi.mock('@/api/operations', async (original) => ({ ...await original<typeof Operations>(), executeOperation: vi.fn() }));
const execute = vi.mocked(executeOperation);
function success(result: Record<string, unknown>) {
  return { kind: 'succeeded' as const, envelope: { version: 1 as const, requestId: 'r', operation: 'list', status: 'SUCCEEDED' as const, result, failure: null } };
}
beforeEach(() => vi.clearAllMocks());

describe('authorized selection pages', () => {
  it('continues through empty filtered offset pages and preserves exact ids', async () => {
    execute.mockResolvedValueOnce(success({ value: { items: [], hasMore: true, nextOffset: 100 } }))
      .mockResolvedValueOnce(success({ value: { items: [{ principalId: 'id-2', displayName: 'Alice' }], hasMore: false } }));
    const page = await loadEntityOptions(REF_SOURCES.principal!, {}, 'alice');
    expect(page.items[0]).toMatchObject({ id: 'id-2', label: 'Alice' });
    expect(execute.mock.calls[1]?.[1]).toMatchObject({ offset: 100 });
  });
  it('searches later cursor pages and exposes the remaining continuation', async () => {
    execute.mockResolvedValueOnce(success({ profiles: [{ profileId: 'a', displayName: 'Root' }], truncated: true, nextCursor: 'a' }))
      .mockResolvedValueOnce(success({ profiles: [{ profileId: 'b', displayName: 'TLS server' }], truncated: true, nextCursor: 'b' }));
    const page = await loadEntityOptions(REF_SOURCES.profile!, {}, 'TLS');
    expect(page.items.map((item) => item.id)).toEqual(['b']); expect(page.next).toBe('b');
  });
  it('rejects a repeated cursor instead of looping', async () => {
    execute.mockResolvedValue(success({ profiles: [], truncated: true, nextCursor: 'a' }));
    await expect(loadEntityOptions(REF_SOURCES.profile!, {}, '', 'a')).rejects.toThrow('continuation');
  });
  it('never hides an authorization failure as an empty list', async () => {
    execute.mockResolvedValue({ kind: 'failed', envelope: { ...success({}).envelope, status: 'FAILED', result: null, failure: { code: 'DENIED', classification: 'DENIED', messageKey: 'NO_MATCHING_GRANT', recoveryRequired: false, reconciliationRequired: false } } });
    await expect(loadEntityOptions(REF_SOURCES.profile!, {})).rejects.toThrow('NO_MATCHING_GRANT');
  });
  it('requires scope before fetching certificates', async () => {
    await expect(loadEntityOptions(REF_SOURCES.credential!, {})).rejects.toThrow('authority');
    expect(execute).not.toHaveBeenCalled();
  });
});

describe('dependent forms', () => {
  it('clears certificate selections when authority changes', () => {
    const next = changeFormValue(operationSpec('credential.renew')!, { __authorityId: 'a', credentialId: 'c' }, '__authorityId', 'b');
    expect(next.credentialId).toBe('');
  });
  it('keeps child scope separate from the parent chain scope', () => {
    const spec = operationSpec('issuer.path.register')!;
    expect(selectionFields(spec, {}).map((f) => f.name)).toContain('__parentAuthorityId');
    const next = changeFormValue(spec, { caId: 'child', issuerId: 'child-generation', __parentAuthorityId: 'a', __parentIssuerId: 'i', parentPathId: 'p' }, '__parentAuthorityId', 'b');
    expect(next).toMatchObject({ issuerId: 'child-generation', __parentIssuerId: '', parentPathId: '' });
    expect(buildRequest(spec, { ...next, __parentIssuerId: 'new-i', parentPathId: 'new-p' }).request.arguments).toEqual({ caId: 'child', issuerId: 'child-generation', parentPathId: 'new-p' });
  });
  it('clears carried confirmation values on credential change', () => {
    const next = changeFormValue(operationSpec('credential.confirmation.proof.complete')!, { credentialId: 'a', expectedLifecycleRevision: 3, expectedLifecycleRecordCommitment: 'old', expectedChallengeRecordCommitment: 'old' }, 'credentialId', 'b');
    expect(next.expectedLifecycleRevision).toBe(''); expect(next.expectedChallengeRecordCommitment).toBe('');
  });
  it('clears prepared approval arguments when target operation changes', () => {
    const next = changeFormValue(operationSpec('security.approval.request')!, { targetArguments: '{"caId":"a"}' }, 'targetOperation', 'ca.rotate');
    expect(next.targetArguments).toBe('');
  });
});
