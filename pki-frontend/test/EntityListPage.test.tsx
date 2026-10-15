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

import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { EntityListPage } from '@/pages/EntityListPage';
import { DOMAIN_LISTINGS } from '@/app/domainListings';
import type { OperationCatalogResponse } from '@/api/types';
import type * as Operations from '@/api/operations';

const discovery = vi.hoisted(() => ({
  data: undefined as OperationCatalogResponse | undefined,
  isLoading: false,
  isError: false,
}));
const execute = vi.hoisted(() => vi.fn());
vi.mock('@/api/operations', async (original) => ({
  ...await original<typeof Operations>(),
  useOperationDescriptors: () => discovery,
  executeOperation: execute,
}));

afterEach(() => { execute.mockClear(); });

it.each(['pending', 'failed', 'empty'])('does not expose certificate search when discovery is %s', (state) => {
  discovery.data = state === 'empty' ? { count: 0, operations: [] } : undefined;
  discovery.isLoading = state === 'pending';
  discovery.isError = state === 'failed';
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}>
    <EntityListPage navId="issuance" title="Certificates" listings={DOMAIN_LISTINGS.issuance!} />
  </QueryClientProvider>);
  expect(screen.getByText('Certificate search is unavailable for this deployment or identity.')).toBeVisible();
  expect(screen.queryByRole('button', { name: 'Load' })).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/Credential ID prefix/)).not.toBeInTheDocument();
  expect(execute).not.toHaveBeenCalled();
});

