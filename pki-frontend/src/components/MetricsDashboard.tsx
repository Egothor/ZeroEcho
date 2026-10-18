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

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Alert, Box, Button, Card, CardContent, Stack, Typography } from '@mui/material';
import { ApiRequestError } from '@/api/client';
import { operationSpec, type OperationId } from '@/api/operationCatalog';
import { executeOperation, indexDescriptors, useOperationDescriptors } from '@/api/operations';
import { EntityAutocomplete } from '@/components/operation/EntityAutocomplete';

interface MetricField {
  readonly key: string;
  readonly label: string;
  readonly unit?: 'bytes' | 'seconds' | 'time' | 'worker';
  readonly chart?: string;
}

interface MetricGroup {
  readonly id: OperationId;
  readonly title: string;
  readonly fields: readonly MetricField[];
}

// Presentation only: operation identities, inputs and scope come from the generated catalog.
const GROUPS: readonly MetricGroup[] = [
  { id: 'dashboard.server', title: 'Server metrics', fields: [
    { key: 'approvalPendingTotal', label: 'Pending approvals' },
    { key: 'auditProjectionFailureTotal', label: 'Audit projection failures' },
    { key: 'adminRequestsTotal', label: 'Administration requests' },
    { key: 'jvmHeapUsedBytes', label: 'JVM heap used', unit: 'bytes' },
    { key: 'statusScheduleFailureTotal', label: 'Status schedule failures' },
    { key: 'statusScheduleWorkerRunning', label: 'Status schedule worker', unit: 'worker' },
  ] },
  { id: 'dashboard.authority', title: 'Authority metrics', fields: [
    { key: 'issuerGenerationsTotal', label: 'Issuer generations', chart: 'generations' },
    { key: 'issuerGenerationsActive', label: 'Active issuer generations', chart: 'generations' },
    { key: 'issuanceChainDepth', label: 'Issuance chain depth' },
  ] },
  { id: 'dashboard.certificate', title: 'Certificate metrics', fields: [
    { key: 'certificatesTotal', label: 'Certificates counted', chart: 'inventory' },
    { key: 'activeTotal', label: 'Active certificates', chart: 'inventory' },
    { key: 'revokedTotal', label: 'Revoked certificates', chart: 'inventory' },
    { key: 'expiredTotal', label: 'Expired certificates', chart: 'inventory' },
    { key: 'expiring7dTotal', label: 'Expiring within 7 days', chart: 'expiration' },
    { key: 'expiring30dTotal', label: 'Expiring within 30 days', chart: 'expiration' },
    { key: 'expiring90dTotal', label: 'Expiring within 90 days', chart: 'expiration' },
    { key: 'pendingRequestsTotal', label: 'Pending certificate requests' },
  ] },
  { id: 'dashboard.revocation', title: 'Revocation metrics', fields: [
    { key: 'revokedTotal', label: 'Revoked certificates' },
    { key: 'crlLastGeneratedEpoch', label: 'Latest CRL generated', unit: 'time' },
    { key: 'crlNextUpdateEpoch', label: 'Latest CRL next update', unit: 'time' },
    { key: 'crlFreshnessSeconds', label: 'Latest CRL age', unit: 'seconds' },
    { key: 'crlSizeBytes', label: 'Latest CRL size', unit: 'bytes' },
  ] },
  { id: 'dashboard.publication', title: 'Publication metrics', fields: [
    { key: 'publicationsPendingTotal', label: 'Pending publications', chart: 'publication' },
    { key: 'publicationsTerminalFailureTotal', label: 'Terminal publication failures', chart: 'publication' },
    { key: 'crlLastGeneratedEpoch', label: 'Latest CRL generated', unit: 'time' },
    { key: 'crlNextUpdateEpoch', label: 'Latest CRL next update', unit: 'time' },
  ] },
];

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function measurement(data: Record<string, unknown>, field: MetricField): { text: string; value?: number } {
  const states = data.metricStates;
  if (states !== undefined && !record(states)) return { text: 'Invalid measurement state' };
  const state = record(states) ? states[field.key] : undefined;
  if (state !== undefined) {
    if (!record(state)) return { text: 'Invalid measurement state' };
    if (state.state === 'UNAVAILABLE') return { text: 'Unavailable' };
    if (state.state === 'FAILED') return { text: 'Collection failed' };
    if (state.state !== 'AVAILABLE') return { text: 'Invalid measurement state' };
  }
  const value = data[field.key];
  if (value === undefined || value === null) return { text: 'Unavailable' };
  if (typeof value !== 'number' || !Number.isSafeInteger(value)
      || value < 0 && field.unit !== 'seconds' && field.unit !== 'time') return { text: 'Invalid measurement' };
  if (field.unit === 'time') {
    const date = new Date(value * 1000);
    return { text: Number.isNaN(date.getTime()) ? 'Invalid measurement' : date.toISOString() };
  }
  if (field.unit === 'worker') return { text: value === 1 ? 'Running' : value === 0 ? 'Stopped' : 'Invalid measurement' };
  return { text: `${value.toLocaleString()}${field.unit ? ` ${field.unit}` : ''}`, value };
}

function MetricValues({ group, data }: { group: MetricGroup; data: Record<string, unknown> }) {
  const values = group.fields.map((field) => ({ field, ...measurement(data, field) }));
  const maxima = new Map<string, number>();
  for (const { field, value } of values) {
    if (field.chart && value !== undefined) maxima.set(field.chart, Math.max(1, maxima.get(field.chart) ?? 1, value));
  }
  const computedAt = typeof data.computedAt === 'string' ? new Date(data.computedAt) : undefined;
  return <Stack spacing={1.5}>
    <Typography variant="caption" color="text.secondary">
      {computedAt && !Number.isNaN(computedAt.getTime()) ? `Computed at ${computedAt.toISOString()}` : 'Computation time unavailable'}
    </Typography>
    {group.id === 'dashboard.authority' && <Typography variant="body2">
      Authority state: {typeof data.caState === 'string' ? data.caState : 'Unavailable'}
    </Typography>}
    {group.id === 'dashboard.certificate' && <>
      {data.countCapped === true && <Alert severity="warning">Partial counts: the server scan limit was reached. Counts are lower bounds.</Alert>}
      {typeof data.countCapped !== 'boolean' && <Alert severity="info">Count completeness is unavailable.</Alert>}
      <Typography variant="caption">Expiration windows are cumulative and overlap. Inventory and expiration bars use separate scales.</Typography>
    </>}
    {maxima.size > 0 && <Typography variant="caption" color="text.secondary">Bars compare reported counts within each group; they are not percentages.</Typography>}
    <Box component="dl" sx={{ m: 0 }}>
      {values.map(({ field, text, value }) => <Box key={field.key} sx={{ mb: 1.5 }}>
        <Typography component="dt" variant="body2">{field.label}</Typography>
        <Typography component="dd" variant="h3" sx={{ m: 0, overflowWrap: 'anywhere' }}>{text}</Typography>
        {field.chart && value !== undefined && <Box component="meter" aria-label={field.label}
          min={0} max={maxima.get(field.chart)} value={value} sx={{ width: '100%', height: 12 }} />}
      </Box>)}
    </Box>
  </Stack>;
}

function MetricQuery({ group, authorityId }: { group: MetricGroup; authorityId: string }) {
  const spec = operationSpec(group.id)!;
  const query = useQuery({
    queryKey: ['dashboardMetrics', group.id, authorityId],
    retry: false,
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    queryFn: async ({ signal }) => {
      const controller = new AbortController();
      const abort = () => controller.abort();
      signal.addEventListener('abort', abort, { once: true });
      if (signal.aborted) controller.abort();
      const timer = setTimeout(abort, 30_000);
      try {
        const outcome = await executeOperation(spec, authorityId ? { caId: authorityId } : {},
          { signal: controller.signal, maxPendingWaitMs: 0 });
        if (outcome.kind !== 'succeeded') {
          throw new Error(outcome.envelope.failure?.classification === 'DENIED'
            || outcome.envelope.failure?.code === 'AUTHORIZATION_DENIED' ? 'Access denied.' : 'Metrics request failed.');
        }
        const result = outcome.envelope.result;
        if (!record(result) || authorityId && result.caId !== authorityId) throw new Error('Invalid metrics response.');
        return result;
      } catch (error) {
        if (error instanceof ApiRequestError) throw new Error(error.status === 401 || error.status === 403 ? 'Access denied.' : 'Metrics request failed.', { cause: error });
        throw error;
      } finally {
        clearTimeout(timer);
        signal.removeEventListener('abort', abort);
      }
    },
  });
  return <Stack spacing={2}>
    <Button size="small" onClick={() => void query.refetch()} disabled={query.isFetching}>Refresh {group.title.toLowerCase()}</Button>
    {query.isFetching ? <Typography role="status">Loading metrics…</Typography>
      : query.isError ? <Alert severity="warning">{query.error.message}</Alert>
        : query.data ? <MetricValues group={group} data={query.data} /> : <Typography>Metrics unavailable.</Typography>}
  </Stack>;
}

/** Current snapshots only; at most four authority queries and one server query, without background polling. */
export function MetricsDashboard() {
  const discovery = useOperationDescriptors();
  const descriptors = indexDescriptors(discovery.data);
  const [authorityId, setAuthorityId] = useState('');
  const discovered = !discovery.isError && !discovery.isLoading && !!discovery.data;
  const available = (group: MetricGroup) => discovered && descriptors.has(group.id) && operationSpec(group.id)?.available;
  return <Stack spacing={2} sx={{ mb: 4 }}>
    <Typography variant="h2">Operational metrics</Typography>
    <Typography variant="body2" color="text.secondary">Current snapshots, loaded once. Refresh a panel to collect a new snapshot.</Typography>
    {discovery.isLoading ? <Typography role="status">Loading metric availability…</Typography>
      : discovery.isError ? <Alert severity="warning">Metric discovery failed. No measurements were requested.</Alert> : null}
    <Box sx={{ maxWidth: 480 }}>
      <EntityAutocomplete field={{ name: 'caId', label: 'Metrics authority', type: 'pkiId', required: true, ref: 'authority' }}
        value={authorityId} onChange={(value) => setAuthorityId(typeof value === 'string' ? value : '')}
        disabled={!GROUPS.slice(1).some(available)} />
    </Box>
    <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))', xl: 'repeat(3, minmax(0, 1fr))' } }}>
      {GROUPS.map((group) => <Card component="section" aria-label={group.title} key={group.id} variant="outlined">
        <CardContent>
          <Typography variant="h3" component="h3" sx={{ mb: 2 }}>{group.title}</Typography>
          {!available(group) ? <Typography>Unavailable for this deployment or identity.</Typography>
            : group.id !== 'dashboard.server' && !authorityId ? <Typography>Select an authority to load these metrics.</Typography>
              : <MetricQuery key={group.id === 'dashboard.server' ? group.id : authorityId} group={group}
                authorityId={group.id === 'dashboard.server' ? '' : authorityId} />}
        </CardContent>
      </Card>)}
    </Box>
  </Stack>;
}
