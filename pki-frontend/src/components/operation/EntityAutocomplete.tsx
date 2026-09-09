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
import { Autocomplete, CircularProgress, Stack, TextField, Typography } from '@mui/material';
import type { FieldSpec } from '@/api/operationSchema';
import { refSource } from '@/api/entityRefs';
import { useEntityOptions } from '@/hooks/useEntityOptions';

interface Props {
  readonly field: FieldSpec;
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly disabled?: boolean;
}

function label(field: FieldSpec): string {
  const base = field.label ?? field.name;
  return field.required ? base : `${base} (optional)`;
}

/**
 * Type-to-search picker for a field that references an existing entity. Suggests
 * candidates from the entity's list operation once opened, while still allowing a
 * free-typed identifier (freeSolo) — useful when the id is known but the list
 * operation is unavailable to this identity.
 */
export function EntityAutocomplete({ field, value, onChange, disabled }: Props) {
  const [open, setOpen] = useState(false);
  const source = refSource(field.ref);
  const { data, isFetching } = useEntityOptions(field.ref, open);
  const ids = data?.ids ?? [];
  const labels = data?.labels ?? new Map<string, string>();
  const entity = source?.label ?? 'value';

  return (
    <Autocomplete
      freeSolo
      autoHighlight
      size="small"
      open={open}
      onOpen={() => setOpen(true)}
      onClose={() => setOpen(false)}
      options={ids}
      loading={isFetching}
      disabled={disabled}
      inputValue={value ?? ''}
      onInputChange={(_, v) => onChange(v)}
      filterOptions={(opts, state) => {
        const q = state.inputValue.toLowerCase();
        return opts.filter(
          (o) => o.toLowerCase().includes(q) || (labels.get(o) ?? '').toLowerCase().includes(q),
        );
      }}
      renderOption={(props, id) => {
        const { key, ...rest } = props as { key: string } & Record<string, unknown>;
        return (
          <li key={key} {...rest}>
            <Stack sx={{ minWidth: 0 }}>
              <Typography variant="body2" sx={{ fontFamily: 'Roboto Mono, monospace' }}>
                {id}
              </Typography>
              {labels.get(id) && (
                <Typography variant="caption" color="text.secondary" noWrap>
                  {labels.get(id)}
                </Typography>
              )}
            </Stack>
          </li>
        );
      }}
      renderInput={(params) => (
        <TextField
          {...params}
          label={label(field)}
          placeholder={`Start typing to search ${entity}…`}
          helperText={field.help ?? `Search an existing ${entity}, or type an id.`}
          slotProps={{
            input: {
              ...params.InputProps,
              endAdornment: (
                <>
                  {isFetching ? <CircularProgress color="inherit" size={16} /> : null}
                  {params.InputProps.endAdornment}
                </>
              ),
            },
          }}
        />
      )}
    />
  );
}
