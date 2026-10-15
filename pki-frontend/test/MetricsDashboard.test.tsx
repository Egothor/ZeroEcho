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

import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { beforeEach, expect, it, vi } from 'vitest';
import { MetricsDashboard } from '@/components/MetricsDashboard';
import type { OperationCatalogResponse } from '@/api/types';
import type { ExecuteOutcome } from '@/api/operations';
import type * as Operations from '@/api/operations';

const discovery = vi.hoisted(() => ({ data: undefined as OperationCatalogResponse | undefined, isLoading: false, isError: false }));
const execute = vi.hoisted(() => vi.fn());
vi.mock('@/api/operations', async (original) => ({
  ...await original<typeof Operations>(), useOperationDescriptors: () => discovery, executeOperation: execute,
}));
vi.mock('@/hooks/useEntityOptions', () => ({ useEntityOptions: () => ({ data: { items: [
  { id: 'ca-a', label: 'Authority A', description: 'ca-a', record: {} },
  { id: 'ca-b', label: 'Authority B', description: 'ca-b', record: {} },
] }, isFetching: false, isError: false }) }));

const ids = ['dashboard.server', 'dashboard.authority', 'dashboard.certificate', 'dashboard.revocation', 'dashboard.publication'];
function available(operations = ids) {
  discovery.data = { count: operations.length, operations: operations.map((operation) => ({ operation, mutating: false,
    family: 'PKI_OPERATION', resourceType: 'AUTHORITY', approval: 'NONE', dataView: 'METADATA_REDACTED' })) };
}
function success(result: Record<string, unknown>): ExecuteOutcome {
  return { kind: 'succeeded', envelope: { version: 1, requestId: 'test', operation: 'dashboard.server', status: 'SUCCEEDED', result, failure: null } };
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const tree = <QueryClientProvider client={client}><MetricsDashboard /></QueryClientProvider>;
  return { ...render(tree), tree, client };
}
async function choose(name = 'Authority A') {
  const user = userEvent.setup();
  await user.click(screen.getByRole('combobox', { name: 'Metrics authority' }));
  await user.click(screen.getByRole('option', { name: new RegExp(name) }));
}
function metric(panel: string, label: string) {
  return within(screen.getByRole('region', { name: panel })).getByText(label, { selector: 'dt' }).nextElementSibling;
}

beforeEach(() => {
  execute.mockReset();
  discovery.isLoading = false;
  discovery.isError = false;
  available();
  execute.mockImplementation((_spec, args) => Promise.resolve(success({ ...args, computedAt: '2026-10-15T10:00:00Z' })));
});

it.each(['pending', 'failed', 'empty'])('requests no measurements when discovery is %s', (state) => {
  discovery.data = state === 'empty' ? { count: 0, operations: [] } : undefined;
  discovery.isLoading = state === 'pending';
  discovery.isError = state === 'failed';
  mount();
  expect(execute).not.toHaveBeenCalled();
  expect(screen.getByRole('combobox')).toBeDisabled();
  expect(screen.queryByRole('button', { name: /Refresh/ })).not.toBeInTheDocument();
});

it('distinguishes measured zero, failed collection, missing and invalid values', async () => {
  available(['dashboard.server']);
  execute.mockResolvedValue(success({ approvalPendingTotal: 0, auditProjectionFailureTotal: 7,
    adminRequestsTotal: Number.MAX_SAFE_INTEGER + 1, jvmHeapUsedBytes: -1, statusScheduleWorkerRunning: 0,
    metricStates: { approvalPendingTotal: { state: 'AVAILABLE' }, auditProjectionFailureTotal: { state: 'FAILED' } },
    computedAt: '2026-10-15T10:00:00Z' }));
  mount();
  await screen.findByText('Computed at 2026-10-15T10:00:00.000Z');
  expect(metric('Server metrics', 'Pending approvals')).toHaveTextContent(/^0$/);
  expect(metric('Server metrics', 'Audit projection failures')).toHaveTextContent('Collection failed');
  expect(metric('Server metrics', 'Status schedule failures')).toHaveTextContent('Unavailable');
  expect(metric('Server metrics', 'Administration requests')).toHaveTextContent('Invalid measurement');
  expect(metric('Server metrics', 'JVM heap used')).toHaveTextContent('Invalid measurement');
  expect(metric('Server metrics', 'Status schedule worker')).toHaveTextContent('Stopped');
  expect(execute).toHaveBeenCalledTimes(1);
});

it('graphs only reported counts for one CA, labels partial and cumulative counts, and never infers missing CRLs', async () => {
  execute.mockImplementation((spec, args) => Promise.resolve(success({ ...args, countCapped: true,
    ...(spec.id === 'dashboard.certificate' ? { certificatesTotal: 120, activeTotal: 100,
      expiring7dTotal: 0, expiring30dTotal: 3, expiring90dTotal: 7, pendingRequestsTotal: 99,
      metricStates: { pendingRequestsTotal: { state: 'UNAVAILABLE' } } } : {}) })));
  mount();
  await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));
  await choose();
  await screen.findByText(/Partial counts:/);
  expect(screen.getByText(/Expiration windows are cumulative and overlap/)).toBeVisible();
  expect(screen.getByRole('meter', { name: 'Active certificates' })).toHaveAttribute('value', '100');
  expect(screen.getByRole('meter', { name: 'Active certificates' })).toHaveAttribute('max', '120');
  expect(screen.getByRole('meter', { name: 'Expiring within 7 days' })).toHaveAttribute('value', '0');
  expect(metric('Certificate metrics', 'Pending certificate requests')).toHaveTextContent('Unavailable');
  expect(metric('Revocation metrics', 'Latest CRL generated')).toHaveTextContent('Unavailable');
  expect(execute).toHaveBeenCalledTimes(5);
  for (const [spec, args, options] of execute.mock.calls) {
    expect(args).toEqual(spec.id === 'dashboard.server' ? {} : { caId: 'ca-a' });
    expect(options.maxPendingWaitMs).toBe(0);
  }
});

it('shows authorization denial and clears prior measurements after a failed manual refresh', async () => {
  available(['dashboard.server']);
  execute.mockResolvedValueOnce(success({ adminRequestsTotal: 42 })).mockResolvedValue({ kind: 'failed', envelope: {
    failure: { classification: 'DENIED', code: 'AUTHORIZATION_DENIED' },
  } });
  mount();
  await screen.findByText('42');
  await userEvent.click(screen.getByRole('button', { name: 'Refresh server metrics' }));
  await screen.findByText('Access denied.');
  expect(screen.queryByText('42')).not.toBeInTheDocument();
  expect(execute).toHaveBeenCalledTimes(2);
});

it('fails safely on transport failure without displaying backend details', async () => {
  available(['dashboard.server']);
  const { ApiRequestError } = await import('@/api/client');
  execute.mockRejectedValue(new ApiRequestError({ status: 0, code: 'network_error', message: 'private transport detail' }));
  mount();
  await screen.findByText('Metrics request failed.');
  expect(screen.queryByText('private transport detail')).not.toBeInTheDocument();
  expect(execute).toHaveBeenCalledTimes(1);
});

it('cancels the previous authority, ignores its late response and aborts remaining requests on unmount', async () => {
  available(['dashboard.certificate']);
  let finishA: (outcome: ExecuteOutcome) => void = () => {};
  execute.mockImplementation((_spec, args) => args.caId === 'ca-a'
    ? new Promise<ExecuteOutcome>((resolve) => { finishA = resolve; })
    : Promise.resolve(success({ caId: 'ca-b', certificatesTotal: 3, countCapped: false })));
  const view = mount();
  await choose();
  const signalA = execute.mock.calls[0]![2].signal as AbortSignal;
  await choose('Authority B');
  await screen.findByText('3');
  expect(signalA.aborted).toBe(true);
  await act(async () => { finishA(success({ caId: 'ca-a', certificatesTotal: 99, countCapped: false })); });
  expect(screen.queryByText('99')).not.toBeInTheDocument();
  execute.mockImplementation(() => new Promise(() => {}));
  await userEvent.click(screen.getByRole('button', { name: 'Refresh certificate metrics' }));
  const pendingSignal = execute.mock.calls.at(-1)![2].signal as AbortSignal;
  view.unmount();
  expect(pendingSignal.aborted).toBe(true);
});

it('drops measurements when discovery ceases to advertise the operation', async () => {
  available(['dashboard.server']);
  execute.mockResolvedValue(success({ adminRequestsTotal: 42 }));
  const view = mount();
  await screen.findByText('42');
  available([]);
  view.rerender(<QueryClientProvider client={view.client}><MetricsDashboard /></QueryClientProvider>);
  expect(screen.queryByText('42')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Refresh/ })).not.toBeInTheDocument();
});

it('does not refresh on focus or reconnect', async () => {
  available(['dashboard.server']);
  mount();
  await screen.findByText('Computed at 2026-10-15T10:00:00.000Z');
  await waitFor(() => expect(execute).toHaveBeenCalledTimes(1));
  fireEvent(window, new Event('focus'));
  fireEvent(window, new Event('online'));
  await act(async () => {});
  expect(execute).toHaveBeenCalledTimes(1);
});
