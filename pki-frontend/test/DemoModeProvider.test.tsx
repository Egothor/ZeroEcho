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

import { StrictMode, useEffect } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { currentTransport, fetchTransport, resetTransport } from '@/api/transport';
import type { TransportResponse } from '@/api/transport';
import { useRealm } from '@/hooks/useRealm';
import { useOperationDescriptors } from '@/api/operations';
import { useDemoMode } from '@/demo/demoModeContext';
import { discoverableOperations } from '@/demo/roles';
import { DemoModeProvider } from '@/demo/DemoModeProvider';

const observe = vi.fn<(response: TransportResponse) => void>();

function MountedRequest() {
  useEffect(() => {
    void currentTransport()({ method: 'GET', path: '/admin/v1/realm', headers: {} }).then(observe);
  }, []);
  return null;
}

afterEach(() => {
  observe.mockReset();
  resetTransport();
  window.history.replaceState({}, '', '/');
  localStorage.clear();
  vi.unstubAllGlobals();
});

it('keeps descendant mount requests on the demo transport through StrictMode replay', async () => {
  window.history.replaceState({}, '', '/?demo=1');
  const liveFetch = vi.fn(async () => new Response('{"realmId":"live"}', { status: 200 }));
  vi.stubGlobal('fetch', liveFetch);
  const client = new QueryClient();
  render(<StrictMode><QueryClientProvider client={client}>
    <DemoModeProvider><MountedRequest /></DemoModeProvider>
  </QueryClientProvider></StrictMode>);
  await waitFor(() => expect(observe).toHaveBeenCalledTimes(2));
  expect(liveFetch).not.toHaveBeenCalled();
  for (const [response] of observe.mock.calls) {
    expect(JSON.parse(response.body).realmId).toBe('demo');
  }
});

function QueriedPersona() {
  const realm = useRealm();
  const catalog = useOperationDescriptors();
  const demo = useDemoMode();
  return <>
    <span>{realm.data?.realmId}</span>
    <span data-testid="catalog-count">{catalog.data?.count}</span>
    <span>{demo.role}</span>
    <button onClick={() => demo.setRole('PUBLIC_USER')}>Switch persona</button>
  </>;
}

it('installs before actual query hooks, refetches as the new persona and restores live transport', async () => {
  window.history.replaceState({}, '', '/?demo=1');
  const liveFetch = vi.fn(async () => new Response('{"realmId":"live"}', { status: 200 }));
  vi.stubGlobal('fetch', liveFetch);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<StrictMode><QueryClientProvider client={client}>
    <DemoModeProvider><QueriedPersona /></DemoModeProvider>
  </QueryClientProvider></StrictMode>);
  expect(await screen.findByText('demo')).toBeVisible();
  await waitFor(() => expect(screen.getByTestId('catalog-count').textContent)
    .toBe(String(discoverableOperations('ADMINISTRATOR').length)));
  fireEvent.click(screen.getByRole('button', { name: 'Switch persona' }));
  expect(screen.getByText('PUBLIC_USER')).toBeVisible();
  await waitFor(() => expect(screen.getByTestId('catalog-count').textContent)
    .toBe(String(discoverableOperations('PUBLIC_USER').length)));
  expect(liveFetch).not.toHaveBeenCalled();
  view.unmount();
  expect(currentTransport()).toBe(fetchTransport);
});
