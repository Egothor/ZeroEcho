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
import type { ExecuteExtras, FieldValue } from '@/api/operations';
import { OperationField } from '@/components/operation/OperationField';

interface Props {
  readonly spec: OperationSpec;
  readonly busy?: boolean;
  readonly initialApprovalId?: string;
  /** Pre-filled field values (e.g. the id of the row an action was invoked from). */
  readonly initialValues?: Partial<Record<string, FieldValue>>;
  readonly onSubmit: (values: Record<string, FieldValue>, extra: ExecuteExtras) => void;
}

function initialValues(spec: OperationSpec, prefill?: Partial<Record<string, FieldValue>>): Record<string, FieldValue> {
  const v: Record<string, FieldValue> = {};
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

/** Renders a typed, validated form for one operation and submits its values. */
export function OperationForm({ spec, busy, initialApprovalId, initialValues: prefill, onSubmit }: Props) {
  const [values, setValues] = useState<Record<string, FieldValue>>(() => initialValues(spec, prefill));
  const [approvalId, setApprovalId] = useState(initialApprovalId ?? '');
  const [deadline, setDeadline] = useState('');

  const set = (name: string, value: FieldValue) => setValues((prev) => ({ ...prev, [name]: value }));

  const needsAuthorityInput = spec.scope === 'authority' && !spec.authorityFrom;

  const submit = () => {
    const extra: ExecuteExtras = {};
    if (approvalId.trim()) (extra as { approvalId?: string }).approvalId = approvalId.trim();
    if (deadline.trim()) (extra as { deadline?: string }).deadline = deadline.trim();
    onSubmit(values, extra);
  };

  const hasFields = spec.fields.length > 0 || needsAuthorityInput;
  const authorityHint = useMemo(
    () => (spec.authorityFrom ? `Authority is taken from “${spec.authorityFrom}”.` : undefined),
    [spec.authorityFrom],
  );

  return (
    <Box component="form" onSubmit={(e) => { e.preventDefault(); submit(); }}>
      <Stack spacing={2}>
        {needsAuthorityInput && (
          <TextField
            fullWidth
            size="small"
            required
            label="Authority id"
            value={(values['__authorityId'] as string) ?? ''}
            onChange={(e) => set('__authorityId', e.target.value)}
            helperText="This authority-scoped operation requires the owning authority id."
          />
        )}

        {spec.fields.map((field) => (
          <OperationField
            key={field.name}
            field={field}
            value={values[field.name]}
            onChange={(v) => set(field.name, v)}
            disabled={busy}
          />
        ))}

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
              Advanced (approval, deadline)
            </Typography>
          </AccordionSummary>
          <AccordionDetails sx={{ px: 0 }}>
            <Stack spacing={2}>
              <TextField
                fullWidth
                size="small"
                label="Approval id (optional)"
                value={approvalId}
                onChange={(e) => setApprovalId(e.target.value)}
                helperText="Supply for a previously approved HIGH_RISK operation."
                disabled={busy}
              />
              <TextField
                fullWidth
                size="small"
                label="Deadline (optional)"
                value={deadline}
                onChange={(e) => setDeadline(e.target.value)}
                placeholder="PT30S"
                helperText="ISO-8601 duration; capped by the server maximum."
                disabled={busy}
              />
            </Stack>
          </AccordionDetails>
        </Accordion>

        <Box>
          <Button type="submit" variant="contained" startIcon={<PlayArrowIcon />} disabled={busy}>
            {busy ? 'Running…' : 'Run operation'}
          </Button>
        </Box>
      </Stack>
    </Box>
  );
}
