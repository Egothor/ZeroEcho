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
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Alert, Box, Divider, Paper, Stack, Typography } from '@mui/material';
import { ApiRequestError } from '@/api/client';
import { executeOperation, pollOperation, type ExecuteExtras, type ExecuteOutcome, type FieldValue, useOperationDescriptors } from '@/api/operations';
import { operationSpec } from '@/api/operationCatalog';
import type { OperationDescriptor } from '@/api/types';
import { OperationForm } from '@/components/operation/OperationForm';
import { OperationBadges } from '@/components/operation/OperationBadges';
import { AdministrativeRequestRunner } from '@/components/operation/AdministrativeRequestRunner';
import { OutcomeView } from '@/components/operation/OutcomeView';

interface Props {
  readonly operationId: string;
  readonly descriptor?: OperationDescriptor | undefined;
  /** When false, the operation is not discoverable for this identity (server-side authorization). */
  readonly permitted?: boolean;
  /** Pre-filled field values (e.g. the id of the row this action was invoked from). */
  readonly initialValues?: Partial<Record<string, FieldValue>>;
  /** Notified with the operation result (used by entity screens to refresh lists). */
  readonly onCompleted?: (outcome: ExecuteOutcome) => void;
  /** Closes a business form after its stable request ID is transferred to the worklist. */
  readonly onRequestSubmitted?: (requestId: string, acknowledged: boolean) => void;
}

/**
 * Runs a single operation: a typed form plus execution with the server's
 * acceptance / pending / approval semantics, rendered as an outcome. UI never
 * grants authority — a hidden or disabled control is not an authorization
 * boundary; the server decides on every request.
 * @param props Operation identity, optional initial values and notification callback.
 * @returns Supported durable business form or direct read/approval decision form.
 */
export function OperationRunner(props: Props) {
  const spec = operationSpec(props.operationId);
  const business = !!spec && !spec.read && !spec.id.startsWith('security.approval.');
  const discovery = useOperationDescriptors(business && !props.descriptor);
  const descriptor = props.descriptor ?? discovery.data?.operations.find((item) => item.operation === props.operationId);
  if (business) {
    if (props.permitted === false) return <Alert severity="warning">This operation is unavailable for the current identity.</Alert>;
    if (descriptor?.durableRequest === true) return <AdministrativeRequestRunner spec={spec!} initialValues={props.initialValues} onSubmitted={props.onRequestSubmitted} />;
    return <Alert severity={discovery.isError ? 'error' : 'info'}>
      {discovery.isLoading ? 'Reading durable request capabilities…' : 'This operation is not supported by the server’s durable request workflow. Use its dedicated protocol or streaming page where available; no operation was submitted.'}
    </Alert>;
  }
  if (spec?.id === 'security.approval.request') return <Alert severity="info">Approval requests are created automatically when you submit a business operation in Requests. Legacy approval-only records do not queue or execute their targets.</Alert>;
  return <LegacyOperationRunner {...props} />;
}

function LegacyOperationRunner(props: Props) {
  const { operationId, descriptor, permitted = true, initialValues, onCompleted } = props;
  const spec = operationSpec(operationId);
  const client = useQueryClient();
  const [outcome, setOutcome] = useState<ExecuteOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const complete = (result: ExecuteOutcome) => {
    setOutcome(result); setError(null);
    if (result.kind === 'succeeded' && !spec?.read) {
      for (const key of ['domainList', 'entityOptions', 'administrativeRequests']) void client.invalidateQueries({ queryKey: [key] });
    }
    onCompleted?.(result);
  };
  const mutation = useMutation({
    mutationFn: ({ values, extra }: { values: Record<string, FieldValue>; extra: ExecuteExtras }) => {
      if (!spec) throw new Error('Unknown operation');
      return executeOperation(spec, values, extra);
    },
    onSuccess: complete,
    onError: (failure) => { setOutcome(null); setError(failure instanceof ApiRequestError ? `${failure.code}: ${failure.message}` : failure instanceof Error ? failure.message : 'Execution failed'); },
  });
  const statusMutation = useMutation({
    mutationFn: () => { if (outcome?.kind !== 'pending') throw new Error('No retained operation'); return pollOperation(outcome); },
    onSuccess: complete, onError: failure => setError(failure instanceof Error ? failure.message : 'Unable to read status.'),
  });
  if (!spec) return <Alert severity="info">Operation <code>{operationId}</code> is unavailable in the guided catalog.</Alert>;
  return <Paper component="section" aria-label={spec.title} variant="outlined" sx={{ p: 3 }}><Stack spacing={2}>
    <Box><Typography variant="h3" component="h2">{spec.title}</Typography><Typography>{spec.summary}</Typography></Box>
    <OperationBadges spec={spec} descriptor={descriptor} />
    {!permitted && <Alert severity="info">The server authorizes every operation for the current identity.</Alert>}
    <Divider />
    <OperationForm spec={spec} initialValues={initialValues} showApproval={!spec.id.startsWith('security.approval.')} busy={mutation.isPending || statusMutation.isPending || outcome?.kind === 'pending'} onSubmit={(values, extra) => mutation.mutate({ values, extra })} />
    {error && <Alert severity="error">{error}</Alert>}
    {outcome && <OutcomeView outcome={outcome} onCheckStatus={() => statusMutation.mutate()} checkingStatus={statusMutation.isPending} />}
  </Stack></Paper>;
}
