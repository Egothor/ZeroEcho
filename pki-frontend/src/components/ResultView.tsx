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

import { useMemo } from 'react';
import { Box, Chip, Stack, Table, TableBody, TableCell, TableRow, Typography } from '@mui/material';
import { DataGrid, type GridColDef } from '@mui/x-data-grid';
import { JsonView } from '@/components/operation/JsonView';

function isRecordArray(value: unknown): value is Record<string, unknown>[] {
  return Array.isArray(value) && value.length > 0 && value.every((v) => v !== null && typeof v === 'object' && !Array.isArray(v));
}

function cell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

/** A sortable, filterable, paginated grid over a set of records. */
export function RecordGrid({ title, rows }: { readonly title?: string; readonly rows: Record<string, unknown>[] }) {
  const columns = useMemo<GridColDef[]>(() => {
    const keys = new Set<string>();
    rows.slice(0, 50).forEach((r) => Object.keys(r).forEach((k) => keys.add(k)));
    return Array.from(keys).map((k) => ({
      field: k,
      headerName: k,
      flex: 1,
      minWidth: 130,
      valueGetter: (_v, row) => cell((row as Record<string, unknown>)[k]),
    }));
  }, [rows]);

  const gridRows = useMemo(
    () => rows.map((r, i) => ({ id: (r['id'] as string) ?? (r['caId'] as string) ?? i, ...r })),
    [rows],
  );

  return (
    <Box>
      {title && (
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          {title} ({rows.length})
        </Typography>
      )}
      <DataGrid
        rows={gridRows}
        columns={columns}
        density="compact"
        autoHeight
        disableColumnMenu={false}
        hideFooterSelectedRowCount
        pageSizeOptions={[10, 25, 50, 100]}
        initialState={{ pagination: { paginationModel: { pageSize: 10 } } }}
        sx={{ '& .MuiDataGrid-cell': { fontFamily: 'Roboto Mono, monospace', fontSize: 12 } }}
      />
    </Box>
  );
}

function valueCell(value: unknown) {
  if (typeof value === 'boolean') {
    return <Chip size="small" color={value ? 'success' : 'default'} variant="outlined" label={String(value)} />;
  }
  if (Array.isArray(value) && value.every((v) => typeof v !== 'object')) {
    return (
      <Stack direction="row" spacing={0.5} sx={{ flexWrap: 'wrap', gap: 0.5 }}>
        {value.length === 0 ? '—' : value.map((v, i) => <Chip key={i} size="small" label={String(v)} />)}
      </Stack>
    );
  }
  if (value !== null && typeof value === 'object') return <JsonView value={value} />;
  return (
    <Typography variant="body2" sx={{ fontFamily: 'Roboto Mono, monospace', wordBreak: 'break-word' }}>
      {value === null || value === undefined || value === '' ? '—' : String(value)}
    </Typography>
  );
}

/** A two-column key/value detail table for a single record. */
export function KeyValueTable({ record }: { readonly record: Record<string, unknown> }) {
  const entries = Object.entries(record);
  if (entries.length === 0) return <Typography variant="body2" color="text.secondary">No fields.</Typography>;
  return (
    <Table size="small">
      <TableBody>
        {entries.map(([k, v]) => (
          <TableRow key={k}>
            <TableCell sx={{ fontWeight: 600, width: 220, verticalAlign: 'top', border: 0 }}>{k}</TableCell>
            <TableCell sx={{ border: 0 }}>{valueCell(v)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/**
 * Renders an operation result as HTML: record arrays as data grids, a single
 * record as a key/value detail table, scalars inline. Raw JSON is only a last
 * resort for genuinely unstructured values.
 */
export function ResultView({ value }: { readonly value: unknown }) {
  if (isRecordArray(value)) return <RecordGrid rows={value} />;
  if (value === null || typeof value !== 'object') {
    return (
      <Typography variant="body2" sx={{ fontFamily: 'Roboto Mono, monospace' }}>
        {String(value)}
      </Typography>
    );
  }

  const record = value as Record<string, unknown>;
  const arrays = Object.entries(record).filter(([, v]) => isRecordArray(v));
  const rest = Object.fromEntries(Object.entries(record).filter(([, v]) => !isRecordArray(v)));

  return (
    <Stack spacing={2}>
      {Object.keys(rest).length > 0 && <KeyValueTable record={rest} />}
      {arrays.map(([k, v]) => (
        <RecordGrid key={k} title={k} rows={v as Record<string, unknown>[]} />
      ))}
    </Stack>
  );
}
