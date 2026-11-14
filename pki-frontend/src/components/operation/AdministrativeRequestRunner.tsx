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

import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ApiRequestError } from '@/api/client';
import { useNavigate } from 'react-router-dom';
import { Alert, Paper, Stack, Typography } from '@mui/material';
import type { OperationSpec } from '@/api/operationSchema';
import { buildRequest, type FieldValue } from '@/api/operations';
import { type AdministrativeRequestSubmission, administrativeRequestPath, administrativeSubmission, newAdministrativeRequestId, submitAdministrativeRequest } from '@/api/administrativeRequests';
import { OperationForm } from '@/components/operation/OperationForm';

interface Props {
  readonly spec: OperationSpec;
  readonly initialValues?: Partial<Record<string, FieldValue>>;
  readonly onSubmitted?: (requestId: string, acknowledged: boolean) => void;
}

/**
 * Submits one durable intent, then transfers observation to its persisted detail route.
 * @param props Supported operation schema, initial arguments and optional dialog-close callback.
 * @returns The one-submit business form; approval and execution are server-owned.
 */
export function AdministrativeRequestRunner(props: Props) {
  const { spec, initialValues, onSubmitted } = props;
  const navigate = useNavigate();
  const client = useQueryClient();
  const [requestId] = useState(newAdministrativeRequestId);
  const [attempted, setAttempted] = useState(false);
  const submitted = useRef(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const mutation = useMutation({
    retry: false,
    mutationFn: (intent: AdministrativeRequestSubmission) => submitAdministrativeRequest(intent),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['administrativeRequests'] });
      onSubmitted?.(requestId, true);
      navigate(administrativeRequestPath(requestId));
    },
    onError: (error) => {
      if (error instanceof ApiRequestError && [400, 422].includes(error.status)) {
        submitted.current = false; setAttempted(false); setLocalError(error.message);
        return;
      }
      onSubmitted?.(requestId, false);
      navigate(administrativeRequestPath(requestId), { state: { submissionUnconfirmed: true,
        submissionMessage: error instanceof Error ? error.message : 'The submission response was lost.' } });
    },
  });
  return <Paper component="section" aria-label={spec.title} variant="outlined" sx={{ p: 3 }}>
    <Stack spacing={2}>
      <Typography variant="h3" component="h2">{spec.title}</Typography>
      <Typography>{spec.summary}</Typography>
      <Alert severity="info">Submit this operation once. The server creates any required approval request and executes when its policy is satisfied. Track progress in Requests.</Alert>
      {localError && <Alert severity="error">{localError}</Alert>}
      <Typography variant="caption">Request ID: {requestId}</Typography>
      <OperationForm spec={spec} initialValues={initialValues} managedRequest busy={attempted || mutation.isPending}
        onEdited={() => setLocalError(null)} onSubmit={(values, extra) => {
          if (submitted.current) return;
          try {
            const intent = administrativeSubmission(requestId, spec.id, buildRequest(spec, values, extra).request);
            submitted.current = true; setAttempted(true); mutation.mutate(intent);
          } catch (error) { setLocalError(error instanceof Error ? error.message : 'Invalid operation arguments.'); }
        }} />
    </Stack>
  </Paper>;
}
