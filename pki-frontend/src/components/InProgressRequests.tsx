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

import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link as RouterLink } from 'react-router-dom';
import { Alert, Button, Link, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material';
import { administrativeRequestPath, administrativeRequestTerminal, listAdministrativeRequests } from '@/api/administrativeRequests';

const operations: Record<string, readonly string[]> = {
  authorities: ['ca.create', 'ca.intermediate.create', 'ca.intermediate.issue'],
  issuance: ['credential.issue', 'credential.renew', 'credential.replace'],
  credentials: ['credential.issue', 'credential.renew', 'credential.replace'],
};

/**
 * Shows bounded, server-filtered request pages beside issued entities.
 * @param props Navigation domain whose pending business intents should be visible.
 * @returns Pending intents with stable links, never fabricated certificate or CA records.
 */
export function InProgressRequests({ navId }: { readonly navId: string }) {
  const choices = operations[navId];
  return choices ? <RequestPanel key={navId} operations={choices} /> : null;
}

function RequestPanel({ operations: choices }: { readonly operations: readonly string[] }) {
  const [operation, setOperation] = useState(choices[0]);
  const [offset, setOffset] = useState(0);
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['administrativeRequests', 'inProgress', operation, offset],
    queryFn: ({ signal }) => listAdministrativeRequests(offset, undefined, signal, operation), retry: false,
    refetchInterval: 2000, refetchOnWindowFocus: true });
  const completed = query.data?.requests.filter(request => request.state === 'SUCCEEDED').map(request => request.requestId).join('|');
  useEffect(() => {
    if (completed) {
      void client.invalidateQueries({ queryKey: ['domainList'] });
      void client.invalidateQueries({ queryKey: ['entityOptions'] });
    }
  }, [client, completed]);
  const pending = query.data?.requests.filter(request => !administrativeRequestTerminal(request.state)) ?? [];
  return <Paper variant="outlined" component="section" aria-label="In-progress issuance requests" sx={{ p: 2, mb: 2 }}>
    <Typography variant="h6">In progress — not issued</Typography>
    <Typography variant="body2">These are submitted requests, not issued certificates or authorities. Completed and failed requests remain in the Requests worklist.</Typography>
    <Stack direction="row" spacing={2} sx={{ my: 1 }}>
      <TextField select label="Requested operation" size="small" value={operation} onChange={event => { setOperation(event.target.value); setOffset(0); }}>
        {choices.map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}
      </TextField>
      <Link component={RouterLink} to="/administrative-requests">All requests</Link>
    </Stack>
    {query.isError && <Alert severity="error">Pending requests could not be read. <Button onClick={() => void query.refetch()}>Retry</Button></Alert>}
    {query.isLoading && <Typography role="status">Loading pending requests…</Typography>}
    {query.data && pending.length === 0 && <Typography>No in-progress requests on this page.</Typography>}
    {pending.map(request => <Stack key={request.requestId} direction="row" spacing={2} sx={{ my: 1 }}>
      <Link component={RouterLink} to={administrativeRequestPath(request.requestId)}>{request.summary || request.requestId}</Link>
      <Typography>{request.state}</Typography>
      {request.approvalId && <Link component={RouterLink} to={administrativeRequestPath(request.requestId)}>Approval {request.approvalId}</Link>}
    </Stack>)}
    {query.data && <Stack direction="row" spacing={1}>
      <Button disabled={offset === 0 || query.isFetching} onClick={() => setOffset(0)}>First request page</Button>
      <Button disabled={!query.data.hasMore || query.isFetching} onClick={() => setOffset(query.data.nextOffset)}>Next request page</Button>
    </Stack>}
  </Paper>;
}
