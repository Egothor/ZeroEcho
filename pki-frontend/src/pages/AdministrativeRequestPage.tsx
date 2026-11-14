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

import { useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link as RouterLink, useLocation, useParams } from 'react-router-dom';
import { Alert, Button, Chip, Link, Paper, Stack, Typography } from '@mui/material';
import { administrativeRequestTerminal, inspectAdministrativeRequest } from '@/api/administrativeRequests';
import { operationSpec } from '@/api/operationCatalog';
import { OperationRunner } from '@/components/operation/OperationRunner';
import { JsonView } from '@/components/operation/JsonView';
import { ResultView } from '@/components/ResultView';
import { PageHeader } from '@/components/PageHeader';

/**
 * Observes one server-owned operation and exposes explicit human approval decisions.
 * @returns Durable status and result; polling performs GET only and never replays the target.
 */
export function AdministrativeRequestPage() {
  const { requestId = '' } = useParams();
  const location = useLocation();
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['administrativeRequests', 'detail', requestId], enabled: !!requestId,
    queryFn: ({ signal }) => inspectAdministrativeRequest(requestId, signal), retry: false,
    refetchInterval: current => current.state.data && !administrativeRequestTerminal(current.state.data.state) ? 1500 : false,
    refetchOnWindowFocus: true });
  const request = query.data;
  useEffect(() => {
    if (request && administrativeRequestTerminal(request.state)) {
      void client.invalidateQueries({ queryKey: ['domainList'] });
      void client.invalidateQueries({ queryKey: ['entityOptions'] });
    }
  }, [client, request]);
  const submissionMessage = location.state && typeof location.state === 'object' && 'submissionMessage' in location.state && typeof location.state.submissionMessage === 'string' ? location.state.submissionMessage : undefined;
  const unconfirmed = !!(location.state && typeof location.state === 'object' && 'submissionUnconfirmed' in location.state);
  return <>
    <PageHeader title={request ? operationSpec(request.operation)?.title ?? request.operation : 'Request status'} description="The server retains this operation and continues execution independently of this browser." />
    <Stack direction="row" spacing={2} sx={{ mb: 2 }}><Link component={RouterLink} to="/administrative-requests">All requests</Link><Button onClick={() => void query.refetch()} disabled={query.isFetching}>Refresh status</Button></Stack>
    <Typography sx={{ overflowWrap: 'anywhere', mb: 2 }}>Request ID: {requestId}</Typography>
    {query.isLoading && <Typography role="status">Reading request status…</Typography>}
    {query.isError && <Alert severity="warning">
      {unconfirmed ? 'The submission response was not confirmed. ' : ''}{submissionMessage ? `${submissionMessage} ` : ''}This request could not be read: {query.error.message}.
      Keep this ID and refresh status after checking the connection or identity. No operation is resubmitted from this page.
    </Alert>}
    {request && <Stack spacing={2}>
      <Paper variant="outlined" sx={{ p: 2 }}><Stack spacing={1}>
        <Chip label={request.state} color={request.state === 'SUCCEEDED' ? 'success' : ['FAILED', 'REJECTED', 'RECONCILIATION_REQUIRED'].includes(request.state) ? 'error' : 'info'} sx={{ alignSelf: 'flex-start' }} />
        <Typography>Requested by {request.requesterPrincipalId}</Typography>
        <ol aria-label="Request timeline"><li>Submitted <time dateTime={request.createdAt}>{request.createdAt}</time></li>
          <li>Current state: {request.state} · <time dateTime={request.updatedAt}>{request.updatedAt}</time></li>
          {request.approvalId && <li>Approval: {request.approvalId} · <Link component={RouterLink} to="/approvals">Open Approvals</Link></li>}
          {request.signingOperationId && <li>Signing receipt: {request.signingOperationId}</li>}
        </ol>
        {request.executionTimeout && <Typography>Execution budget after approval: {request.executionTimeout}</Typography>}
      </Stack></Paper>
      {request.target && <Paper variant="outlined" sx={{ p: 2 }}><Typography variant="h3">Requested operation</Typography><JsonView value={{ operation: request.operation, ...request.target }} /></Paper>}
      {request.state === 'WAITING_APPROVAL' && <Alert severity="info">Waiting for an eligible human approval. After approval, the server executes this exact request automatically; closing this page does not cancel it.</Alert>}
      {request.state === 'WAITING_APPROVAL' && request.approvalId && <OperationRunner operationId="security.approval.approve" initialValues={{ approvalId: request.approvalId }} />}
      {['READY', 'DISPATCHING', 'RUNNING'].includes(request.state) && <Alert severity="info">The server is processing this request. Progress checks only read its status.</Alert>}
      {request.failureCode && <Alert severity="error">{request.failureCode}{request.failureCode === 'CA_SUBJECT_INVALID' ? ': Review the selected credential format’s subject input rules.' : ''}</Alert>}
      {request.state === 'RECONCILIATION_REQUIRED' && <Alert severity="warning">An operator must reconcile the retained operation before another submission. Keep the request and signing receipt IDs.</Alert>}
      {request.state === 'SUCCEEDED' && <Alert severity="success">Operation completed.</Alert>}
      {request.result && <Paper variant="outlined" sx={{ p: 2 }}><Typography variant="h3">Operation result</Typography><ResultView value={request.result} /></Paper>}
      {request.state === 'SUCCEEDED' && request.operation.startsWith('credential.') && <Link component={RouterLink} to="/issuance">View issued certificates</Link>}
      {request.state === 'SUCCEEDED' && request.operation.startsWith('ca.') && <Link component={RouterLink} to="/authorities">View certificate authorities</Link>}
    </Stack>}
  </>;
}
