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
import { afterEach, expect, it, vi } from 'vitest';
import { OperationRunner } from '@/components/operation/OperationRunner';
import { OperationDialog } from '@/components/operation/OperationDialog';
import { AdministrativeRequestPage } from '@/pages/AdministrativeRequestPage';
import { AdministrativeRequestsPage } from '@/pages/AdministrativeRequestsPage';
import { setTransport, resetTransport, type TransportRequest } from '@/api/transport';
import { NAV_ITEMS } from '@/app/navigation';
vi.mock('@/hooks/useDerivedValues', () => ({ useDerivedValues: () => ({ values: {}, loading: false }) }));
vi.mock('@/hooks/useSubjectInput', () => ({ useSubjectInput: () => ({ metadata: undefined, invalid: false, loading: false, error: null }) }));
vi.mock('@/components/operation/OperationField', () => ({ OperationField: ({ field, value, onChange, disabled }: {
  field: { name: string; readOnly?: boolean }; value: unknown; onChange: (value: string) => void; disabled?: boolean;
}) => <label>{field.name}<input aria-label={field.name} value={String(value ?? '')} disabled={disabled} readOnly={field.readOnly}
  onChange={event => onChange(event.target.value)} /></label> }));
afterEach(resetTransport);
const now = '2026-11-13T12:00:00Z';
const envelope = (operation: string, result: unknown, status = 'SUCCEEDED') => ({ version: 1, requestId: 'wire', operation, status, result, failure: null });
function fixture(lost = false, rejected = false) {
  const calls: TransportRequest[] = [];
  let stored: Record<string, unknown> | undefined;
  let phase = 'WAITING_APPROVAL';
  let observed = 0;
  setTransport(async request => {
    calls.push(request);
    if (request.path === '/admin/v1/operations') return { status: 200, headers: {}, body: JSON.stringify(envelope('operation.list', { count: 1, operations: [{ operation: 'ca.create', family: 'SIGNING_OPERATION', mutating: true, resourceType: 'AUTHORITY', approval: 'HIGH_RISK', dataView: 'METADATA_REDACTED', durableRequest: true }] })) };
    if (request.path === '/admin/v1/requests' && request.method === 'POST') {
      const body = JSON.parse(request.body!);
      if (rejected) { rejected = false; return { status: 400, headers: {}, body: JSON.stringify({ failure: { code: 'CA_SUBJECT_INVALID' } }) }; }
      stored = { requestId: body.requestId, operation: body.operation, state: phase, requesterPrincipalId: 'root-admin', createdAt: now, updatedAt: now,
        approvalId: 'approval-linked', executionTimeout: body.deadline, target: { arguments: body.arguments } };
      if (lost) throw new Error('Submission response lost');
      return { status: 202, headers: {}, body: JSON.stringify(envelope('administrative.request.submit', stored, 'PENDING')) };
    }
    if (request.path === '/admin/v1/operations/security.approval.approve') {
      phase = 'RUNNING';
      return { status: 200, headers: {}, body: JSON.stringify(envelope('security.approval.approve', { value: { approvalId: 'approval-linked', state: 'APPROVED' } })) };
    }
    if (request.path.startsWith('/admin/v1/requests/')) {
      if (!stored) return { status: 404, headers: {}, body: JSON.stringify({ error: 'REQUEST_NOT_FOUND' }) };
      if (phase === 'RUNNING' && observed++ > 0) phase = 'SUCCEEDED';
      return { status: 200, headers: {}, body: JSON.stringify(envelope('administrative.request.inspect', { ...stored, state: phase,
        ...(phase === 'RUNNING' || phase === 'SUCCEEDED' ? { signingOperationId: 'sign:one' } : {}),
        ...(phase === 'SUCCEEDED' ? { result: { credentialId: 'certificate:root' } } : {}), ...(phase === 'FAILED' ? { failureCode: 'CA_SUBJECT_INVALID' } : {}) })) };
    }
    if (request.path === '/admin/v1/requests') return { status: 200, headers: {}, body: JSON.stringify(envelope('administrative.request.list', { requests: stored ? [{ ...stored, state: phase, target: undefined }] : [], nextOffset: 25, hasMore: false })) };
    return { status: 404, headers: {}, body: '{}' };
  });
  return { calls, setPhase: (value: string) => { phase = value; }, requestId: () => String(stored?.requestId) };
}
function mount(path = '/authorities', closed = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  const rendered = render(<QueryClientProvider client={client}><MemoryRouter initialEntries={[path]}><Routes>
    <Route path="/authorities" element={<OperationDialog operationId="ca.create" open onClose={closed} initialValues={{ formatId: 'x509', subjectRef: 'CN=One Root', profileId: 'root-ca', keyRef: 'zeroecho-lib:root.prv' }} />} />
    <Route path="/administrative-requests" element={<AdministrativeRequestsPage />} />
    <Route path="/administrative-requests/:requestId" element={<AdministrativeRequestPage />} />
  </Routes></MemoryRouter></QueryClientProvider>);
  return { ...rendered, client, closed };
}
it('submits once, closes the dialog and observes automatic execution after explicit approval', async () => {
  const server = fixture();
  const view = mount();
  const submit = await screen.findByRole('button', { name: 'Submit request' });
  expect(screen.queryByLabelText('approvalId')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Prepare approval request' })).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Execution timeout (optional)'), { target: { value: 'PT30S' } });
  fireEvent.click(submit);
  await screen.findByText('WAITING_APPROVAL', { selector: '.MuiChip-label' });
  expect(view.closed).toHaveBeenCalledOnce();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  const sent = server.calls.filter(call => call.method === 'POST' && call.path === '/admin/v1/requests');
  expect(sent).toHaveLength(1);
  expect(JSON.parse(sent[0]!.body!)).toMatchObject({ operation: 'ca.create', deadline: 'PT30S', arguments: { subjectRef: 'CN=One Root' } });
  fireEvent.change(screen.getByLabelText('justification'), { target: { value: 'Reviewed exact root intent.' } });
  fireEvent.click(screen.getByRole('button', { name: 'Approve request' }));
  await screen.findByText('RUNNING', { selector: '.MuiChip-label' });
  await screen.findByText('Operation completed.', {}, { timeout: 3000 });
  expect(screen.getByText(/certificate:root/)).toBeVisible();
  expect(screen.getByRole('link', { name: 'View certificate authorities' })).toBeVisible();
  expect(server.calls.filter(call => call.path === '/admin/v1/requests' && call.method === 'POST')).toHaveLength(1);
  expect(server.calls.filter(call => call.path === '/admin/v1/operations/ca.create')).toHaveLength(0);
  expect(screen.queryByRole('button', { name: 'Use approved request' })).not.toBeInTheDocument();
  view.client.clear();
}, 10000);
it('retains the same ID after a lost response and resumes through GET across a browser remount', async () => {
  const server = fixture(true);
  const first = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Submit request' }));
  await screen.findByText('WAITING_APPROVAL', { selector: '.MuiChip-label' });
  const id = server.requestId();
  first.unmount(); first.client.clear();
  server.setPhase('RUNNING');
  const second = mount(`/administrative-requests/${encodeURIComponent(id)}`);
  await screen.findByText('RUNNING', { selector: '.MuiChip-label' });
  await screen.findByText('Operation completed.', {}, { timeout: 3000 });
  expect(server.calls.filter(call => call.method === 'POST' && call.path === '/admin/v1/requests')).toHaveLength(1);
  expect(server.calls.filter(call => call.method === 'GET' && call.path.endsWith(encodeURIComponent(id))).length).toBeGreaterThanOrEqual(3);
  second.client.clear();
}, 10000);
it('renders a terminal failure and refreshes status without replaying the command', async () => {
  const server = fixture();
  const first = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Submit request' }));
  await screen.findByText('WAITING_APPROVAL', { selector: '.MuiChip-label' });
  first.unmount(); first.client.clear(); server.setPhase('FAILED');
  const second = mount(`/administrative-requests/${server.requestId()}`);
  expect(await screen.findByText(/CA_SUBJECT_INVALID/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
  await waitFor(() => expect(server.calls.filter(call => call.method === 'GET').length).toBeGreaterThanOrEqual(3));
  expect(server.calls.filter(call => call.method === 'POST' && call.path === '/admin/v1/requests')).toHaveLength(1);
  second.client.clear();
});
it('keeps Requests navigation visible and lists only metadata with a stable detail link', async () => {
  const server = fixture();
  const first = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Submit request' }));
  await screen.findByText('WAITING_APPROVAL', { selector: '.MuiChip-label' });
  first.unmount(); first.client.clear();
  const view = mount('/administrative-requests');
  expect(await screen.findByRole('link', { name: server.requestId() })).toHaveAttribute('href', `/administrative-requests/${server.requestId()}`);
  expect(screen.queryByText('CN=One Root')).not.toBeInTheDocument();
  expect(NAV_ITEMS.find(item => item.id === 'administrative-requests')?.operationPrefixes).toEqual([]);
  view.client.clear();
});

it('keeps rejected preflight values editable without navigating or automatically repeating submission', async () => {
  const server = fixture(false, true);
  const view = mount();
  fireEvent.click(await screen.findByRole('button', { name: 'Submit request' }));
  expect(await screen.findByText(/Submission rejected: CA_SUBJECT_INVALID/)).toBeVisible();
  expect(view.closed).not.toHaveBeenCalled();
  expect(screen.getByLabelText('subjectRef')).toHaveValue('CN=One Root');
  expect(server.calls.filter(call => call.method === 'POST' && call.path === '/admin/v1/requests')).toHaveLength(1);
  fireEvent.change(screen.getByLabelText('subjectRef'), { target: { value: 'CN=Corrected Root' } });
  fireEvent.click(screen.getByRole('button', { name: 'Submit request' }));
  await screen.findByText('WAITING_APPROVAL', { selector: '.MuiChip-label' });
  const posts = server.calls.filter(call => call.method === 'POST' && call.path === '/admin/v1/requests');
  expect(posts).toHaveLength(2);
  expect(JSON.parse(posts[0]!.body!).requestId).toBe(JSON.parse(posts[1]!.body!).requestId);
  expect(JSON.parse(posts[1]!.body!).arguments.subjectRef).toBe('CN=Corrected Root');
  view.client.clear();
});

it('does not fall back to legacy target or manual approval when durable capability is unavailable', async () => {
  const server = fixture();
  const client = new QueryClient();
  const view = render(<QueryClientProvider client={client}><MemoryRouter><OperationRunner operationId="ca.create" descriptor={{ operation: 'ca.create', family: 'SIGNING_OPERATION', mutating: true, resourceType: 'AUTHORITY', approval: 'HIGH_RISK', dataView: 'METADATA_REDACTED', durableRequest: false }} /></MemoryRouter></QueryClientProvider>);
  expect(screen.getByText(/not supported by the server’s durable request workflow/)).toBeVisible();
  expect(screen.queryByRole('button', { name: /Submit request|Prepare approval|Run operation/ })).not.toBeInTheDocument();
  expect(server.calls).toHaveLength(0);
  view.unmount(); client.clear();
});
