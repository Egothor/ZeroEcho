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

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link as RouterLink } from 'react-router-dom';
import { Alert, Button, Link, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { REQUEST_STATES, administrativeRequestPath, listAdministrativeRequests } from '@/api/administrativeRequests';
import { operationSpec } from '@/api/operationCatalog';
import { PageHeader } from '@/components/PageHeader';

/**
 * Lists durable business requests with server pagination and lifecycle filtering.
 * @returns Always-addressable worklist; no business mutations are sent by this screen.
 */
export function AdministrativeRequestsPage() {
  const [offset, setOffset] = useState(0);
  const [state, setState] = useState('');
  const query = useQuery({ queryKey: ['administrativeRequests', 'list', offset, state],
    queryFn: ({ signal }) => listAdministrativeRequests(offset, state || undefined, signal), retry: false });
  return <>
    <PageHeader title="Requests" description="Track submitted operations, required approvals and server execution across browser sessions." />
    <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
      <TextField select size="small" label="Request state" value={state} onChange={(event) => { setState(event.target.value); setOffset(0); }} sx={{ minWidth: 230 }}>
        <MenuItem value="">All states</MenuItem>{REQUEST_STATES.map(value => <MenuItem key={value} value={value}>{value}</MenuItem>)}
      </TextField>
      <Button onClick={() => void query.refetch()} disabled={query.isFetching}>Refresh requests</Button>
    </Stack>
    {query.isLoading && <Typography role="status">Loading requests…</Typography>}
    {query.isError && <Alert severity="error">Requests could not be read: {query.error.message}. Refresh after checking your connection and identity.</Alert>}
    {query.data && <Paper variant="outlined">
      <Table size="small" aria-label="Administrative requests"><TableHead><TableRow>
        <TableCell>Request</TableCell><TableCell>Operation</TableCell><TableCell>Summary</TableCell><TableCell>State</TableCell><TableCell>Requester</TableCell><TableCell>Updated</TableCell>
      </TableRow></TableHead><TableBody>
        {query.data.requests.map(request => <TableRow key={request.requestId}>
          <TableCell><Link component={RouterLink} to={administrativeRequestPath(request.requestId)}>{request.requestId}</Link></TableCell>
          <TableCell>{operationSpec(request.operation)?.title ?? request.operation}</TableCell><TableCell>{request.summary ?? '—'}</TableCell><TableCell>{request.state}</TableCell>
          <TableCell>{request.requesterPrincipalId}</TableCell><TableCell><time dateTime={request.updatedAt}>{request.updatedAt}</time></TableCell>
        </TableRow>)}
        {query.data.requests.length === 0 && <TableRow><TableCell colSpan={6}>No requests match this view.</TableCell></TableRow>}
      </TableBody></Table>
      <Stack direction="row" spacing={1} sx={{ p: 1 }}>
        <Button onClick={() => setOffset(0)} disabled={offset === 0 || query.isFetching}>First requests</Button>
        <Button onClick={() => setOffset(query.data.nextOffset)} disabled={!query.data.hasMore || query.isFetching}>Next requests</Button>
      </Stack>
    </Paper>}
  </>;
}
