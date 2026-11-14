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
import type * as Operations from '@/api/operations';
import { RealmPage } from '@/pages/RealmPage';
import { setTransport, resetTransport } from '@/api/transport';
vi.mock('@/api/operations', async original => ({ ...await original<typeof Operations>(),
  useOperationDescriptors: () => ({ data: { count: 0, operations: [] }, isLoading: false, isError: false }) }));
afterEach(() => resetTransport());
const realm = { realmId: 'trial', displayName: 'Trial Realm', authorityExposure: 'ALL_REALM_AUTHORITIES', authorityCreationPermitted: true };
const envelope = { version: 1, requestId: 'request:realm', operation: 'realm.inspect', status: 'SUCCEEDED', result: realm, failure: null };
it('unwraps the production realm envelope before displaying metadata', async () => {
  setTransport(async () => ({ status: 200, headers: {}, body: JSON.stringify(envelope) }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><RealmPage /></QueryClientProvider>);
  expect(await screen.findByText('realm: trial')).toBeVisible();
  expect(screen.getByText('authority exposure: ALL_REALM_AUTHORITIES')).toBeVisible();
  expect(screen.getByText('authority creation permitted')).toBeVisible();
  client.clear();
});
it.each([null, { ...realm, realmId: undefined }, { ...realm, authorityCreationPermitted: 'true' }])('rejects malformed realm result %j', async result => {
  setTransport(async () => ({ status: 200, headers: {}, body: JSON.stringify({ ...envelope, result }) }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><RealmPage /></QueryClientProvider>);
  expect(await screen.findByText(/Realm metadata is unavailable/)).toBeVisible();
  expect(screen.queryByText('realm: undefined')).not.toBeInTheDocument();
  client.clear();
});
