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

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it } from 'vitest';
import { InProgressRequests } from '@/components/InProgressRequests';
import { resetTransport, setTransport, type TransportRequest } from '@/api/transport';
afterEach(resetTransport);
it('shows pending CA intents separately, pages filtered reads and refreshes issued entities on success', async () => {
  const calls: TransportRequest[] = [];
  let state = 'WAITING_APPROVAL';
  setTransport(async request => {
    calls.push(request);
    return { status: 200, headers: {}, body: JSON.stringify({ version: 1, requestId: 'wire', operation: 'administrative.request.list', status: 'SUCCEEDED', failure: null,
      result: { requests: [{ requestId: 'pending-ca', operation: 'ca.create', state, summary: 'CN=Pending Root', requesterPrincipalId: 'admin', createdAt: 'now', updatedAt: 'now', approvalId: 'approval-one' }], nextOffset: 25, hasMore: true } }) };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['domainList', 'authorities'], []);
  const view = render(<QueryClientProvider client={client}><MemoryRouter><InProgressRequests navId="authorities" /></MemoryRouter></QueryClientProvider>);
  expect(await screen.findByRole('link', { name: 'CN=Pending Root' })).toHaveAttribute('href', '/administrative-requests/pending-ca');
  expect(screen.getByText('In progress — not issued')).toBeVisible();
  expect(screen.getByText('WAITING_APPROVAL')).toBeVisible();
  expect(calls[0]!.query).toMatchObject({ operation: 'ca.create', offset: 0, limit: 25 });
  state = 'RUNNING';
  fireEvent.click(screen.getByRole('button', { name: 'Next request page' }));
  await screen.findByText('RUNNING');
  expect(calls.some(call => call.query?.offset === 25)).toBe(true);
  state = 'SUCCEEDED';
  await client.invalidateQueries({ queryKey: ['administrativeRequests', 'inProgress'] });
  await waitFor(() => expect(screen.queryByText('CN=Pending Root')).not.toBeInTheDocument());
  await waitFor(() => expect(client.getQueryState(['domainList', 'authorities'])?.isInvalidated).toBe(true));
  expect(calls.every(call => call.method === 'GET')).toBe(true);
  view.unmount();
});
