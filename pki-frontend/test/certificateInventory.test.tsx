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
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, expect, it } from 'vitest';
import { ColorModeProvider } from '@/theme/ColorMode';
import { AppLayout } from '@/components/AppLayout';
import { DomainPage } from '@/pages/DomainPage';
import { NAV_ITEMS } from '@/app/navigation';
import { REF_SOURCES } from '@/api/entityRefs';
import { resetTransport, setTransport, type TransportRequest } from '@/api/transport';
afterEach(resetTransport);
const envelope = (operation: string, result: unknown) => ({ version: 1, requestId: 'wire', operation, status: 'SUCCEEDED', failure: null, result });
it('opens scoped mandatory inventory from its CA row and downloads without an optional search index or copied IDs', async () => {
  const calls: TransportRequest[] = [];
  setTransport(async request => {
    calls.push(request);
    let body: unknown;
    if (request.path === '/admin/v1/operations') body = envelope('operation.list', { count: 2, operations: ['ca.list', 'credential.list'].map(operation => ({ operation, family: 'PKI_OPERATION', mutating: false, resourceType: operation === 'ca.list' ? 'AUTHORITY' : 'CERTIFICATE', approval: 'NONE', dataView: 'METADATA_REDACTED' })) });
    else if (request.path.endsWith('/operations/ca.list')) body = envelope('ca.list', { authorities: [{ caId: 'ca:one', displayName: 'One Root', kind: 'ROOT', state: 'ACTIVE' }], count: 1, truncated: false });
    else if (request.path.endsWith('/operations/credential.list')) body = envelope('credential.list', { credentials: [{ credentialId: 'cert:leaf', authorityId: 'ca:one', formatId: 'provider-format', subjectRef: 'Example leaf', status: 'ISSUED' }], count: 1, truncated: false });
    else if (request.path === '/admin/v1/authorities/ca%3Aone/certificate' || request.path === '/admin/v1/certificate-artifacts/cert%3Aleaf') {
      const credentialId = request.path.includes('/authorities/') ? 'cert:root' : 'cert:leaf';
      body = envelope('certificate.artifact.inspect', { value: { credentialId, authorityId: 'ca:one', formatId: 'provider-format', representations: [{ id: 'original', label: 'Original binary', mediaType: 'application/octet-stream', fileName: 'certificate.bin', href: `/admin/v1/certificate-artifacts/${encodeURIComponent(credentialId)}/content?representation=original` }] } });
    } else return { status: 404, headers: {}, body: '{}' };
    return { status: 200, headers: {}, body: JSON.stringify(body) };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/authorities']}><Routes><Route path="*" element={<DomainPage />} /></Routes></MemoryRouter></QueryClientProvider>);
  const linked = await screen.findByRole('link', { name: 'View certificates' });
  expect(linked).toHaveAttribute('href', '/issuance?authorityId=ca%3Aone');
  expect(calls.some(call => call.path.includes('certificate-artifacts') || call.path.endsWith('/certificate'))).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Download CA certificate' }));
  expect(await screen.findByRole('link', { name: 'Download CA certificate — Original binary' })).toHaveAttribute('href', '/admin/v1/certificate-artifacts/cert%3Aroot/content?representation=original');
  fireEvent.click(linked);
  expect(await screen.findByRole('heading', { name: 'Certificates' })).toBeVisible();
  await screen.findByText('Example leaf');
  const listed = calls.find(call => call.path.endsWith('/operations/credential.list'))!;
  expect(JSON.parse(listed.body!)).toMatchObject({ authorityId: 'ca:one', arguments: { limit: 100 } });
  fireEvent.click(screen.getByRole('button', { name: 'Download certificate' }));
  expect(await screen.findByRole('link', { name: 'Download certificate — Original binary' })).toHaveAttribute('href', '/admin/v1/certificate-artifacts/cert%3Aleaf/content?representation=original');
  expect(calls.some(call => call.path.endsWith('/operations/credential.search'))).toBe(false);
  expect(REF_SOURCES.credential?.operationId).toBe('credential.list');
  expect(NAV_ITEMS.find(item => item.id === 'issuance')?.label).toBe('Certificates');
  await waitFor(() => expect(calls.every(call => !call.path.endsWith('/content'))).toBe(true));
  view.unmount(); client.clear();
});

it('shows Certificates navigation to a list-only principal without advanced-search discovery', async () => {
  setTransport(async request => ({ status: 200, headers: {}, body: JSON.stringify(request.path === '/admin/v1/operations'
    ? envelope('operation.list', { count: 1, operations: [{ operation: 'credential.list', family: 'PKI_OPERATION', mutating: false, resourceType: 'CERTIFICATE', approval: 'NONE', dataView: 'METADATA_REDACTED' }] })
    : envelope('realm.inspect', { realmId: 'one', displayName: 'One', authorityExposure: 'PRIVATE', authorityCreationPermitted: false, publicRepository: { available: false } })) }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><ColorModeProvider><MemoryRouter><AppLayout /></MemoryRouter></ColorModeProvider></QueryClientProvider>);
  expect(await screen.findByRole('link', { name: 'Certificates' })).toHaveAttribute('href', '/issuance');
  expect(screen.getByRole('link', { name: 'Requests' })).toHaveAttribute('href', '/administrative-requests');
  view.unmount(); client.clear();
});
