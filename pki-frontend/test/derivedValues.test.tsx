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
import { describe, expect, it, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { operationSpec } from '@/api/operationCatalog';
import { executeOperation } from '@/api/operations';
import { useDerivedValues, profileValidityMillis } from '@/hooks/useDerivedValues';
import { changeFormValue } from '@/api/formSelections';
vi.mock('@/api/operations', async (original) => ({ ...await original<typeof Operations>(), executeOperation: vi.fn() }));
const spec = operationSpec('acme.directory.register')!;
function wrapper({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{children}</QueryClientProvider>;
}
describe('profile-derived ACME policy', () => {
  it('converts Java durations and applies the existing ACME ceiling', () => {
    expect(profileValidityMillis('PT24H')).toBe(86400000);
    expect(profileValidityMillis('PT1H2M3.123456S')).toBe(3723123);
    expect(profileValidityMillis('PT20000H')).toBe(398 * 86400000);
    for (const invalid of ['PT', 'PT0S', '-PT1H', 'junk', 'PT9999999999999999999H']) expect(() => profileValidityMillis(invalid)).toThrow();
  });
  it('supplies policy sets/default validity but preserves an explicit shorter policy', async () => {
    vi.mocked(executeOperation).mockImplementation(async (operation) => ({ kind: 'succeeded', envelope: { version: 1, requestId: 'r', operation: operation.id, status: 'SUCCEEDED', failure: null,
      result: operation.id === 'profile.list' ? { activeVersion: 3 } : { maximumValidity: 'PT24H', publicKeyAlgorithms: ['EC'], x509BindingPolicies: ['binding'] } } }));
    const { result, rerender } = renderHook(({ mode }) => useDerivedValues(spec, { authorityId: 'ca', profileId: 'profile', __validityMode: mode, maximumValidityMillis: 3600000 }), { wrapper, initialProps: { mode: 'PROFILE_MAXIMUM' } });
    await waitFor(() => expect(result.current.values.maximumValidityMillis).toBe(86400000));
    expect(result.current.values.publicKeyAlgorithms).toEqual(['EC']);
    rerender({ mode: 'CUSTOM' });
    await waitFor(() => expect(result.current.values.__profileMaximumValidityMillis).toBe(86400000));
    expect(result.current.values.maximumValidityMillis).toBeUndefined();
  });
  it('invalidates custom validity and algorithm sets on profile change', () => {
    const next = changeFormValue(spec, { profileId: 'a', maximumValidityMillis: 1000, publicKeyAlgorithms: ['EC'], x509BindingPolicies: ['old'] }, 'profileId', 'b');
    expect(next).toMatchObject({ maximumValidityMillis: '', publicKeyAlgorithms: [], x509BindingPolicies: [] });
  });
});
