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

import { useMemo, useState } from 'react';
import {
  Alert,
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import type { OperationSpec } from '@/api/operationSchema';
import { buildRequest, type ExecuteExtras, type FieldValue } from '@/api/operations';
import { changeFormValue, selectionFields, selectionContextKey, hasValue } from '@/api/formSelections';
import { displayLabel } from '@/api/labels';
import { operationSpec } from '@/api/operationCatalog';
import { useSubjectInput } from '@/hooks/useSubjectInput';
import { useDerivedValues } from '@/hooks/useDerivedValues';
import { OperationField } from '@/components/operation/OperationField';
import { JsonView } from '@/components/operation/JsonView';

interface Props {
  readonly spec: OperationSpec;
  readonly embedded?: boolean;
  /** Durable business requests never accept a manually supplied approval ID. */
  readonly managedRequest?: boolean;
  readonly showApproval?: boolean;
  readonly onEdited?: () => void;
  readonly busy?: boolean;
  readonly initialApprovalId?: string;
  readonly initialDeadline?: string;
  /** Pre-filled field values (e.g. the id of the row an action was invoked from). */
  readonly initialValues?: Partial<Record<string, FieldValue>>;
  readonly onSubmit: (values: Record<string, FieldValue>, extra: ExecuteExtras) => void;
}

function initialValues(spec: OperationSpec, prefill?: Partial<Record<string, FieldValue>>): Record<string, FieldValue> {
  const v: Record<string, FieldValue> = { __objectKind: 'credential', __validityMode: 'PROFILE_MAXIMUM' };
  for (const f of spec.fields) {
    if (f.type === 'boolean') v[f.name] = false;
    else if (f.type === 'enumSet' || f.type === 'stringSet') v[f.name] = [];
    else v[f.name] = '';
  }
  if (spec.scope === 'authority' && !spec.authorityFrom) v['__authorityId'] = '';
  if (prefill) {
    for (const [k, val] of Object.entries(prefill)) {
      if (val !== undefined) v[k] = val;
    }
  }
  return v;
}

function decodePreparedArguments(value: FieldValue): object | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const decoded: unknown = JSON.parse(value);
    return decoded !== null && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : undefined;
  } catch { return undefined; }
}

/**
 * Renders typed operation fields or an immutable prepared approval target.
 * @param props Operation schema, optional prepared values and explicit submission callback.
 * @returns Accessible operation form; prepared arguments are submitted only on operator action.
 */
export function OperationForm(props: Props) {
  const { spec, embedded, managedRequest, showApproval = true, onEdited, busy, initialApprovalId, initialDeadline, initialValues: prefill, onSubmit } = props;
  const [enteredValues, setValues] = useState<Record<string, FieldValue>>(() => initialValues(spec, prefill));
  const [approvalId, setApprovalId] = useState(initialApprovalId ?? '');
  const [deadline, setDeadline] = useState(initialDeadline ?? '');

  const derived = useDerivedValues(spec, enteredValues);
  const subjectInput = useSubjectInput(spec, enteredValues);
  const values = { ...enteredValues, ...derived.values };
  const set = (name: string, value: FieldValue) => { if (initialApprovalId) setApprovalId(''); onEdited?.(); setValues((prev) => changeFormValue(spec, prev, name, value)); };

  const needsAuthorityInput = spec.scope === 'authority' && !spec.authorityFrom;

  const submit = () => {
    const extra: ExecuteExtras = {};
    if (approvalId.trim()) (extra as { approvalId?: string }).approvalId = approvalId.trim();
    if (deadline.trim()) (extra as { deadline?: string }).deadline = deadline.trim();
    if (!ready || subjectError || validityError || derived.loading || derived.error || subjectInput.loading || subjectInput.error || busy) return;
    onSubmit(values, extra);
  };

  const target = spec.id === 'security.approval.request' ? operationSpec(String(values.targetOperation ?? '')) : undefined;
  const targetPrepared = spec.id === 'security.approval.request' && hasValue(values.targetArguments);
  const preparedArguments = targetPrepared ? decodePreparedArguments(values.targetArguments) : undefined;
  const contextFields = selectionFields(spec, values);
  const subjectError = subjectInput.invalid;
  const validityError = spec.id === 'acme.directory.register' && values.__validityMode === 'CUSTOM' && !derived.loading
    && (!Number.isSafeInteger(Number(values.maximumValidityMillis)) || Number(values.maximumValidityMillis) <= 0
      || Number(values.maximumValidityMillis) > Number(values.__profileMaximumValidityMillis));
  const ready = spec.fields.filter((f) => f.required && !f.hidden).every((f) => hasValue(values[f.name]))
    && contextFields.filter((f) => f.required).every((f) => hasValue(values[f.name]))
    && (!needsAuthorityInput || hasValue(values['__authorityId']))
    && (!targetPrepared || preparedArguments !== undefined) && !subjectError;

  const hasFields = spec.fields.length > 0 || needsAuthorityInput;
  const authorityHint = useMemo(
    () => (spec.authorityFrom ? `Authority is taken from “${displayLabel(spec.authorityFrom)}”.` : undefined),
    [spec.authorityFrom],
  );

  return (
    <Box component={embedded ? 'div' : 'form'} onSubmit={(e: React.FormEvent) => { e.preventDefault(); submit(); }}>
      <Stack spacing={2}>
        {validityError && <Alert severity="error">Choose a positive validity no greater than {String(values.__profileMaximumValidityMillis ?? 'the profile maximum')} milliseconds.</Alert>}
        {derived.error && <Alert severity="error">{derived.error.message}</Alert>}
        {subjectInput.error && <Alert severity="error">{subjectInput.error.message}</Alert>}
        {subjectInput.loading && <Alert severity="info">Reading selected format input rules…</Alert>}
        {derived.loading && <Alert severity="info">Reading selected record…</Alert>}
        {needsAuthorityInput && (
          <OperationField
            field={{ name: '__authorityId', type: 'pkiId', required: true, label: 'Authority', ref: 'authority' }}
            value={values['__authorityId']} context={values} disabled={busy}
            onChange={(value) => set('__authorityId', value)}
          />
        )}

        {[...contextFields, ...spec.fields.filter((field) => !field.hidden && !(spec.id === 'security.approval.request' &&
          ['targetArguments', 'targetAuthorityId', ...(targetPrepared ? ['targetOperation'] : [])].includes(field.name)))].map((field) => (
          <OperationField
            key={`${field.name}:${selectionContextKey(field, values)}`}
            error={field.name === 'subjectRef' && subjectError}
            field={field.name === 'approvalId' && spec.id.startsWith('security.approval.') && !!prefill?.approvalId ? { ...field, readOnly: true } : field.name === 'subjectRef' && subjectInput.metadata ? { ...field, ...subjectInput.metadata } : field.name === 'maximumValidityMillis' && spec.id === 'acme.directory.register' ? { ...field, readOnly: values.__validityMode !== 'CUSTOM', help: `Profile / ACME upper bound: ${String(values.__profileMaximumValidityMillis ?? 'loading')} milliseconds.` } : field}
            context={values}
            value={values[field.name]}
            onChange={(v) => set(field.name, v)}
            disabled={busy}
          />
        ))}

        {targetPrepared && <Box role="region" aria-label="Prepared approval target" sx={{ borderLeft: 2, borderColor: 'divider', pl: 2 }}>
          <Typography variant="subtitle2">Prepared target: {target?.title ?? String(values.targetOperation)}</Typography>
          {preparedArguments === undefined ? <Alert severity="error">Prepared arguments are invalid. Prepare the approval again from the original operation.</Alert> :
            <JsonView value={{ operation: values.targetOperation, ...(values.targetAuthorityId ? { authorityId: values.targetAuthorityId } : {}), arguments: preparedArguments }} />}
          <Typography variant="body2">Review these exact arguments, choose an approval ID, then create the approval request.</Typography>
        </Box>}
        {!targetPrepared && target && target.id !== 'security.approval.request' && <Box sx={{ borderLeft: 2, borderColor: 'divider', pl: 2 }}>
          <Typography variant="subtitle2">Prepare {target.title}</Typography>
          <OperationForm key={target.id} spec={target} embedded busy={busy} onEdited={() => setValues((prev) => ({ ...prev, targetArguments: '', targetAuthorityId: '' }))} onSubmit={(targetValues) => {
            const { request } = buildRequest(target, targetValues);
            setValues((prev) => ({ ...prev, targetArguments: JSON.stringify(request.arguments), targetAuthorityId: request.authorityId ?? '' }));
          }} />
          {values.targetArguments && <Alert severity="success">Target arguments prepared. You can now request approval.</Alert>}
        </Box>}

        {authorityHint && (
          <Typography variant="caption" color="text.secondary">
            {authorityHint}
          </Typography>
        )}

        {!hasFields && (
          <Typography variant="body2" color="text.secondary">
            This operation takes no arguments.
          </Typography>
        )}

        <Accordion disableGutters elevation={0} sx={{ bgcolor: 'transparent', '&:before': { display: 'none' } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ px: 0 }}>
            <Typography variant="body2" color="text.secondary">
              {managedRequest ? 'Execution settings' : 'Advanced (approval, deadline)'}
            </Typography>
          </AccordionSummary>
          <AccordionDetails sx={{ px: 0 }}>
            <Stack spacing={2}>
              {!managedRequest && showApproval && <OperationField
                field={{ name: 'approvalId', type: 'text', required: false, ref: 'approval', label: 'Approval' }}
                value={approvalId} onChange={(value) => setApprovalId(String(value ?? ''))} disabled={busy}
              />}
              <TextField
                fullWidth
                size="small"
                label={managedRequest ? 'Execution timeout (optional)' : 'Deadline (optional)'}
                value={deadline}
                onChange={(e) => setDeadline(e.target.value)}
                placeholder="PT30S"
                helperText={managedRequest ? 'ISO-8601 execution budget starting after approval (for example PT30S). Approval review has its own expiry.' : 'ISO-8601 duration; capped by the server maximum.'}
                disabled={busy}
              />
            </Stack>
          </AccordionDetails>
        </Accordion>

        <Box>
          <Button type={embedded ? 'button' : 'submit'} onClick={embedded ? submit : undefined} variant="contained" startIcon={<PlayArrowIcon />} disabled={busy || !ready || derived.loading || !!derived.error || subjectInput.loading || !!subjectInput.error || validityError}>
            {busy ? 'Running…' : managedRequest ? 'Submit request' : spec.id === 'security.approval.approve' ? 'Approve request' : spec.id === 'security.approval.reject' ? 'Reject request' : embedded ? 'Use these arguments' : spec.id === 'security.approval.request' ? 'Create approval request' : 'Run operation'}
          </Button>
        </Box>
      </Stack>
    </Box>
  );
}
