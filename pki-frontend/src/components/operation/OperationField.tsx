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

import {
  Autocomplete,
  Chip,
  FormControlLabel,
  Switch,
  TextField,
} from '@mui/material';
import type { SelectionContext } from '@/api/entityRefs';
import { OPERATIONS } from '@/api/operationCatalog';
import { displayLabel, filterChoices } from '@/api/labels';
import type { FieldSpec } from '@/api/operationSchema';
import type { FieldValue } from '@/api/operations';
import { EntityAutocomplete } from '@/components/operation/EntityAutocomplete';

interface Props {
  readonly field: FieldSpec;
  readonly context?: SelectionContext;
  readonly value: FieldValue;
  readonly onChange: (value: FieldValue) => void;
  readonly disabled?: boolean;
}

function labelFor(field: FieldSpec): string {
  const base = field.label ?? displayLabel(field.name);
  return field.required ? base : `${base} (optional)`;
}

/** Renders one operation argument as a typed MUI control. */
export function OperationField({ field, value, onChange, disabled, context }: Props) {
  const label = labelFor(field);

  if (field.name === 'targetOperation' || field.name === 'targetOperationId') {
    const options = OPERATIONS.filter((op) => op.available && (field.name === 'targetOperationId' || (!op.read && op.id !== 'security.approval.request')));
    return <Autocomplete size="small" options={options} getOptionLabel={(op) => `${op.title} · ${op.id}`} value={options.find((op) => op.id === value) ?? null} onChange={(_, op) => onChange(op?.id ?? '')} disabled={disabled} renderInput={(params) => <TextField {...params} label={label} />} />;
  }
  if (field.readOnly) return <TextField fullWidth size="small" label={label} value={Array.isArray(value) ? value.join(', ') : value ?? ''} slotProps={{ input: { readOnly: true } }} helperText={field.help ?? 'Supplied by the selected server record.'} />;

  // Reference to an existing entity: type-to-search picker.
  if (field.ref) {
    return (
      <EntityAutocomplete field={field} value={value} onChange={onChange} disabled={disabled} context={context} />
    );
  }

  switch (field.type) {
    case 'boolean':
      return (
        <FormControlLabel
          control={
            <Switch
              checked={value === true || value === 'true'}
              onChange={(e) => onChange(e.target.checked)}
              disabled={disabled}
            />
          }
          label={label}
        />
      );

    case 'enum':
      return (
        <Autocomplete
          size="small"
          options={field.choices ?? []}
          getOptionLabel={displayLabel}
          filterOptions={(options, state) => filterChoices(options, state.inputValue)}
          value={(value as string) || null}
          onChange={(_, v) => onChange(v ?? '')}
          autoHighlight
          disabled={disabled}
          renderInput={(params) => (
            <TextField
              {...params}
              label={label}
              placeholder="Select or type to filter…"
              helperText={field.help}
            />
          )}
        />
      );

    case 'enumSet':
      return (
        <Autocomplete
          multiple
          size="small"
          options={field.choices ?? []}
          getOptionLabel={displayLabel}
          filterOptions={(options, state) => filterChoices(options, state.inputValue)}
          value={Array.isArray(value) ? value : []}
          onChange={(_, v) => onChange(v)}
          disabled={disabled}
          renderInput={(params) => <TextField {...params} label={label} helperText={field.help} />}
        />
      );

    case 'stringSet':
      return (
        <Autocomplete
          multiple
          freeSolo
          size="small"
          options={[]}
          value={Array.isArray(value) ? value : []}
          onChange={(_, v) => onChange(v as string[])}
          disabled={disabled}
          renderTags={(vals: readonly string[], getTagProps) =>
            vals.map((option, index) => {
              const { key, ...rest } = getTagProps({ index });
              return <Chip key={key} label={option} size="small" {...rest} />;
            })
          }
          renderInput={(params) => (
            <TextField {...params} label={label} helperText={field.help ?? 'Type a value and press Enter'} />
          )}
        />
      );

    case 'json':
      return (
        <TextField
          fullWidth
          multiline
          minRows={3}
          size="small"
          label={label}
          value={(value as string) ?? ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder ?? '{ }'}
          helperText={field.help ?? 'JSON object'}
          disabled={disabled}
          slotProps={{ input: { sx: { fontFamily: 'Roboto Mono, monospace', fontSize: 13 } } }}
        />
      );

    case 'integer':
    case 'long':
      return (
        <TextField
          fullWidth
          size="small"
          type="number"
          label={label}
          value={(value as string) ?? ''}
          onChange={(e) => onChange(e.target.value)}
          helperText={field.help}
          disabled={disabled}
        />
      );

    case 'instant':
      return (
        <TextField
          fullWidth
          size="small"
          label={label}
          value={(value as string) ?? ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder ?? '2026-09-07T12:00:00Z'}
          helperText={field.help ?? 'ISO-8601 instant (UTC), e.g. 2026-09-07T12:00:00Z'}
          disabled={disabled}
        />
      );

    default:
      return (
        <TextField
          fullWidth
          size="small"
          label={label}
          value={(value as string) ?? ''}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          helperText={field.help}
          disabled={disabled}
          slotProps={
            field.type === 'base64'
              ? { input: { sx: { fontFamily: 'Roboto Mono, monospace', fontSize: 13 } } }
              : undefined
          }
        />
      );
  }
}
