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
import { Autocomplete, Button, CircularProgress, Stack, TextField, Typography } from '@mui/material';
import type { FieldSpec } from '@/api/operationSchema';
import type { FieldValue } from '@/api/operations';
import type { SelectionContext } from '@/api/entityRefs';
import { displayLabel } from '@/api/labels';
import { useEntityOptions, type EntityOption } from '@/hooks/useEntityOptions';

interface Props {
  readonly field: FieldSpec;
  readonly value: FieldValue;
  readonly context?: SelectionContext;
  readonly onChange: (value: FieldValue) => void;
  readonly disabled?: boolean;
}

/** Known identities must be selected. Only explicitly new external references permit free entry. */
export function EntityAutocomplete({ field, value, onChange, disabled, context = {} }: Props) {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState('');
  const [search, setSearch] = useState('');
  const [cursor, setCursor] = useState<string | number>();
  const [selected, setSelected] = useState<readonly EntityOption[]>([]);
  useEffect(() => {
    const timer = setTimeout(() => { setSearch(input); setCursor(undefined); }, 250);
    return () => clearTimeout(timer);
  }, [input]);
  const query = useEntityOptions(field.ref, open, context, search, cursor);
  const items = query.data?.items ?? [];
  const multiple = field.type === 'stringSet' || field.type === 'enumSet';
  const ids = Array.isArray(value) ? value : value ? [String(value)] : [];
  const options = ids.map((id) => items.find((item) => item.id === id) ?? selected.find((item) => item.id === id)
    ?? { id, label: id, description: id, record: {} });
  const helper = query.prerequisite ?? (query.error instanceof Error ? query.error.message : field.help)
    ?? (field.allowNew ? 'Choose a known key, or enter a new external key reference.' : 'Search by name or identifier; select an item from the results.');
  return (
    <Stack spacing={0.5}>
      <Autocomplete<EntityOption, boolean, false, boolean>
        multiple={multiple}
        freeSolo={field.allowNew === true}
        autoHighlight
        size="small"
        open={open}
        onOpen={() => setOpen(true)}
        onClose={() => setOpen(false)}
        options={items}
        value={multiple ? options : options[0] ?? null}
        getOptionLabel={(item) => typeof item === 'string' ? item : item.label}
        isOptionEqualToValue={(a, b) => a.id === b.id}
        filterOptions={(available) => available}
        loading={query.isFetching}
        disabled={disabled}
        onInputChange={(_, text, reason) => {
          if (reason === 'input' || reason === 'clear') {
            setInput(text);
            if (field.allowNew && !multiple) onChange(text);
            else if (!multiple && reason === 'input' && ids.length) onChange('');
          }
        }}
        onChange={(_, choice) => {
          const choices = choice === null ? [] : Array.isArray(choice) ? choice : [choice];
          setSelected(choices.filter((item): item is EntityOption => typeof item !== 'string'));
          const values = choices.map((item) => typeof item === 'string' ? item : item.id);
          onChange(multiple ? values : values[0] ?? '');
          setInput('');
        }}
        noOptionsText={query.prerequisite ?? (query.isError ? 'Could not load choices' : 'No matching choices')}
        renderOption={(props, item) => {
          const { key, ...rest } = props;
          return <li key={key} {...rest}><Stack sx={{ minWidth: 0 }}>
            <Typography variant="body2">{item.label}</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{item.description}</Typography>
          </Stack></li>;
        }}
        renderInput={(params) => <TextField {...params}
          label={`${field.label ?? displayLabel(field.name)}${field.required ? '' : ' (optional)'}`}
          error={query.isError} helperText={helper}
          slotProps={{ input: { ...params.InputProps, endAdornment: <>{query.isFetching && <CircularProgress size={16} />}{params.InputProps.endAdornment}</> } }} />}
      />
      {open && <Stack direction="row" spacing={1}>
        {cursor !== undefined && <Button size="small" onMouseDown={(event) => event.preventDefault()} onClick={() => setCursor(undefined)}>First page</Button>}
        {query.data?.next !== undefined && <Button size="small" disabled={query.isFetching} onMouseDown={(event) => event.preventDefault()} onClick={() => setCursor(query.data?.next)}>Next results</Button>}
        {query.isError && <Button size="small" onMouseDown={(event) => event.preventDefault()} onClick={() => void query.refetch()}>Retry</Button>}
      </Stack>}
    </Stack>
  );
}
