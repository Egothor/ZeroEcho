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
import { useMutation } from '@tanstack/react-query';
import { Alert, Button, Box, Divider, Paper, Stack, Typography } from '@mui/material';
import { ApiRequestError } from '@/api/client';
import { buildRequest, executeOperation, pollOperation, type ExecuteExtras, type ExecuteOutcome, type FieldValue } from '@/api/operations';
import { operationSpec } from '@/api/operationCatalog';
import type { OperationDescriptor } from '@/api/types';
import { OperationForm } from '@/components/operation/OperationForm';
import { OperationBadges } from '@/components/operation/OperationBadges';
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
}

/**
 * Runs a single operation: a typed form plus execution with the server's
 * acceptance / pending / approval semantics, rendered as an outcome. UI never
 * grants authority — a hidden or disabled control is not an authorization
 * boundary; the server decides on every request.
 */
export function OperationRunner({
  operationId,
  descriptor,
  permitted = true,
  initialValues,
  onCompleted,
}: Props) {
  const spec = operationSpec(operationId);
  const [outcome, setOutcome] = useState<ExecuteOutcome | null>(null);
  const [followup, setFollowup] = useState<{ id: string; values: Record<string, FieldValue> } | null>(null);
  const [submitted, setSubmitted] = useState<Record<string, FieldValue>>({});
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: ({ values, extra }: { values: Record<string, FieldValue>; extra: ExecuteExtras }) => {
      if (!spec) throw new Error('Unknown operation');
      return executeOperation(spec, values, extra);
    },
    onSuccess: (result) => {
      setOutcome(result);
      setError(null);
      onCompleted?.(result);
    },
    onError: (e) => {
      setOutcome(null);
      if (e instanceof ApiRequestError) {
        setError(`${e.code}: ${e.message}`);
      } else {
        setError(e instanceof Error ? e.message : 'Execution failed');
      }
    },
  });

  const statusMutation = useMutation({
    mutationFn: async () => {
      if (outcome?.kind !== 'pending') throw new Error('No pending operation');
      return pollOperation(outcome);
    },
    onSuccess: (result) => {
      setOutcome(result);
      setError(null);
      onCompleted?.(result);
    },
    onError: (e) => setError(e instanceof Error ? e.message : 'Unable to check the operation.'),
  });

  if (!spec) {
    return (
      <Alert severity="info">
        Operation <code>{operationId}</code> is not in the guided catalog. Use the Operations Explorer raw mode to
        invoke it.
      </Alert>
    );
  }

  return (
    <Paper variant="outlined" sx={{ p: 3 }}>
      <Stack spacing={1} sx={{ mb: 2 }}>
        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
          <Box>
            <Typography variant="h3" component="h2">
              {spec.title}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {spec.summary}
            </Typography>
          </Box>
        </Stack>
        <OperationBadges spec={spec} descriptor={descriptor} />
        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'Roboto Mono, monospace' }}>
          {spec.id}
        </Typography>
      </Stack>

      {!permitted && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Your identity is not currently authorized to invoke this operation. You may still attempt it; the server
          decides.
        </Alert>
      )}

      <Divider sx={{ mb: 2 }} />

      {spec.id === 'credential.confirmation.proof.complete' && !initialValues?.expectedChallengeRecordCommitment && <Alert severity="info" sx={{ mb: 2 }} action={<Button onClick={() => setFollowup({ id: 'credential.confirmation.challenge.issue', values: { ...initialValues } })}>Issue challenge</Button>}>
        Issue a fresh confirmation challenge, then use Complete proof to carry its server-provided preconditions.
      </Alert>}
      <OperationForm
        spec={spec}
        busy={mutation.isPending || statusMutation.isPending}
        initialValues={initialValues}
        onSubmit={(values, extra) => { setSubmitted(values); setFollowup(null); mutation.mutate({ values, extra }); }}
      />

      {outcome?.kind === 'succeeded' && spec.id === 'credential.confirmation.challenge.issue' && <Button onClick={() => {
        const result = outcome.envelope.result ?? {};
        const values: Record<string, FieldValue> = { __authorityId: submitted.__authorityId };
        for (const key of ['credentialId', 'expectedLifecycleRevision', 'expectedLifecycleRecordCommitment', 'expectedChallengeRecordCommitment']) {
          const value = result[key]; if (typeof value === 'string' || typeof value === 'number') values[key] = value;
        }
        setFollowup({ id: 'credential.confirmation.proof.complete', values });
      }}>Complete proof</Button>}
      {outcome?.kind === 'approval-required' && <Button onClick={() => {
        const { request } = buildRequest(spec, submitted);
        setFollowup({ id: 'security.approval.request', values: { targetOperation: spec.id, targetArguments: JSON.stringify(request.arguments), targetAuthorityId: request.authorityId ?? '' } });
      }}>Prepare approval request</Button>}
      {followup && <OperationRunner key={followup.id} operationId={followup.id} initialValues={followup.values} />}

      {(outcome || error) && (
        <Box sx={{ mt: 3 }}>
          {error && <Alert severity="error">{error}</Alert>}
          {outcome && (
            <OutcomeView
              outcome={outcome}
              onCheckStatus={() => statusMutation.mutate()}
              checkingStatus={mutation.isPending || statusMutation.isPending}

            />
          )}
        </Box>
      )}
    </Paper>
  );
}
