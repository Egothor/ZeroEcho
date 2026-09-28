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

import { Alert, AlertTitle, Button, Chip, Stack, Typography } from '@mui/material';
import { lazy, Suspense } from 'react';
import type { ExecuteOutcome } from '@/api/operations';
import { JsonView } from '@/components/operation/JsonView';

const ResultView = lazy(() => import('@/components/ResultView').then((m) => ({ default: m.ResultView })));

interface Props {
  readonly outcome: ExecuteOutcome;
  readonly onCheckStatus?: () => void;
  readonly checkingStatus?: boolean;
  /** Invoked when the operator chooses to create an approval for a HIGH_RISK operation. */
}

/** Renders the terminal (or pending) outcome of an operation execution. */
export function OutcomeView({ outcome, onCheckStatus, checkingStatus }: Props) {
  switch (outcome.kind) {
    case 'succeeded':
      return (
        <Alert severity="success">
          <AlertTitle>Succeeded</AlertTitle>
          {outcome.envelope.result && Object.keys(outcome.envelope.result).length > 0 ? (
            <Suspense fallback={<JsonView value={outcome.envelope.result} />}>
              <ResultView value={outcome.envelope.result} />
            </Suspense>
          ) : (
            <Typography variant="body2">The operation completed with no result payload.</Typography>
          )}
        </Alert>
      );

    case 'failed': {
      const f = outcome.envelope.failure;
      return (
        <Alert severity="error">
          <AlertTitle>Failed{f?.code ? `: ${f.code}` : ''}</AlertTitle>
          <Stack direction="row" spacing={1} sx={{ mb: 1, flexWrap: 'wrap', gap: 0.5 }}>
            {f?.classification && <Chip size="small" color="error" variant="outlined" label={f.classification} />}
            {f?.recoveryRequired && <Chip size="small" color="warning" label="recovery required" />}
            {f?.reconciliationRequired && <Chip size="small" color="warning" label="reconciliation required" />}
          </Stack>
          {f?.messageKey && <Typography variant="body2">{f.messageKey}</Typography>}
        </Alert>
      );
    }

    case 'approval-required':
      return (
        <Alert
          severity="warning"

        >
          <AlertTitle>Approval required</AlertTitle>
          <Typography variant="body2" sx={{ mb: 1 }}>
            This operation is HIGH_RISK or grant-conditioned. Create a durable approval, have it approved by a
            separate principal, then re-run with the approval id.
          </Typography>
          {outcome.operationCommitment && (
            <Typography variant="caption" sx={{ fontFamily: 'Roboto Mono, monospace' }}>
              operationCommitment: {outcome.operationCommitment}
            </Typography>
          )}
        </Alert>
      );

    case 'pending':
      return (
        <Alert severity="info">
          <AlertTitle>Pending</AlertTitle>
          <Typography variant="body2">
            The server accepted this operation. Signing or publication is still in progress.
            Ending this local wait does not cancel the operation.
          </Typography>
          <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>
            Operation: {outcome.operationId}
          </Typography>
          {outcome.pollingError && <Typography variant="body2">{outcome.pollingError}</Typography>}
          {onCheckStatus && (
            <Button onClick={onCheckStatus} disabled={checkingStatus} color="inherit" size="small">
              {checkingStatus ? 'Checking…' : 'Check status'}
            </Button>
          )}
          <Typography variant="caption">
            Check this operation before submitting another request.
          </Typography>
        </Alert>
      );
  }
}
