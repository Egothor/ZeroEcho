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
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Box, Button, Menu, MenuItem, Paper, Skeleton, Stack, Tab, Tabs, Typography } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import {
  DataGrid,
  GridActionsCellItem,
  GridToolbar,
  type GridColDef,
  type GridRowParams,
} from '@mui/x-data-grid';
import { PageHeader } from '@/components/PageHeader';
import { OperationBrowser } from '@/components/operation/OperationBrowser';
import { OperationDialog } from '@/components/operation/OperationDialog';
import { OperationField } from '@/components/operation/OperationField';
import { operationSpec } from '@/api/operationCatalog';
import { executeOperation, indexDescriptors, useOperationDescriptors, type FieldValue } from '@/api/operations';
import type { FieldSpec } from '@/api/operationSchema';
import { resultAt } from '@/api/entityRefs';
import { displayLabel } from '@/api/labels';
import { changeFormValue, selectionFields, selectionContextKey } from '@/api/formSelections';
import { createOps, rowActionOps, type DomainListing } from '@/app/domainListings';

function cell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function notEmpty(v: FieldValue): boolean {
  if (v === undefined || v === '') return false;
  if (Array.isArray(v)) return v.length > 0;
  return true;
}

interface DialogState {
  readonly operationId: string;
  readonly initialValues: Partial<Record<string, FieldValue>>;
}

/**
 * One entity table: auto-loaded (or loaded after required filters are supplied),
 * sortable, filterable, paginated, with per-row actions (inspect + mutations
 * pre-filled with the row id and the active filter — the operator never copies an
 * identifier) and a Create menu. List and actions are one integrated surface.
 */
function EntityTable({ navId, listing }: { readonly navId: string; readonly listing: DomainListing }) {
  const queryClient = useQueryClient();
  const listSpec = operationSpec(listing.listOperationId);
  const discovery = useOperationDescriptors();
  const searchAvailable = listing.listOperationId !== 'credential.search'
    || !discovery.isError && indexDescriptors(discovery.data).has('credential.search');
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [createAnchor, setCreateAnchor] = useState<HTMLElement | null>(null);

  // Filter fields = the list operation's own inputs that are not pre-defaulted,
  // plus a synthetic authority picker when the list is authority-scoped.
  const baseFilterFields = useMemo<FieldSpec[]>(() => {
    if (!listSpec) return [];
    const defaulted = new Set(Object.keys(listing.args));
    const params = listSpec.fields.filter((f) => !defaulted.has(f.name) && !f.hidden);
    const needsAuthority = listSpec.scope === 'authority' && !listSpec.authorityFrom;
    const authorityField: FieldSpec = { name: '__authorityId', type: 'pkiId', required: true, ref: 'authority', label: 'Authority' };
    return needsAuthority ? [authorityField, ...params] : params;
  }, [listSpec, listing.args]);

  const [draft, setDraft] = useState<Record<string, FieldValue>>({});
  const filterFields = [...(listSpec ? selectionFields(listSpec, draft) : []), ...baseFilterFields];
  const requiredFilters = filterFields.filter((f) => f.required);
  const hasRequired = requiredFilters.length > 0;

  const [cursor, setCursor] = useState<string | number | undefined>();
  const [applied, setApplied] = useState<Record<string, FieldValue> | null>(hasRequired ? null : {});

  const rowActions = useMemo(() => rowActionOps(navId, listing), [navId, listing]);
  const creates = useMemo(() => createOps(listing), [listing]);
  const queryKey = ['domainList', navId, listing.listOperationId, applied, cursor] as const;
  const draftReady = requiredFilters.every((f) => notEmpty(draft[f.name]));

  const query = useQuery({
    queryKey,
    enabled: applied !== null && !!listSpec && searchAvailable,
    queryFn: async ({ signal }) => {
      const outcome = await executeOperation(listSpec!, { ...listing.args, ...applied, ...(typeof cursor === 'string' ? { after: cursor } : typeof cursor === 'number' ? { offset: cursor } : {}) } as Record<string, never>, { signal });
      if (outcome.kind !== 'succeeded') {
        throw new Error(outcome.envelope.failure?.messageKey ?? 'Listing is not available');
      }
      const result = outcome.envelope.result;
      const rows = resultAt(result, listing.resultKey);
      if (!Array.isArray(rows)) throw new Error('The server returned an invalid list.');
      const page = (listing.resultKey.startsWith('value.') ? resultAt(result, 'value') : result) as Record<string, unknown> | undefined;
      const next = page?.truncated === true ? page.nextCursor : page?.hasMore === true ? page.nextOffset : undefined;
      if (next !== undefined && (typeof next !== 'number' && typeof next !== 'string' || next === cursor)) throw new Error('Invalid list continuation.');
      return { rows: rows as Record<string, unknown>[], next: next as string | number | undefined };
    },
    retry: false,
  });

  const rows = useMemo(() => query.data?.rows ?? [], [query.data]);

  const columns = useMemo<GridColDef[]>(() => {
    const keys = new Set<string>();
    rows.slice(0, 50).forEach((r) => Object.keys(r).forEach((k) => keys.add(k)));
    const dataColumns: GridColDef[] = Array.from(keys).map((k) => ({
      field: k,
      headerName: displayLabel(k),
      flex: 1,
      minWidth: 130,
      valueGetter: (_v, row) => cell((row as Record<string, unknown>)[k]),
    }));
    if (rowActions.length > 0) {
      dataColumns.push({
        field: '__actions',
        type: 'actions',
        headerName: 'Actions',
        width: 90,
        getActions: (params: GridRowParams) => {
          // Pre-fill from the active filter plus every scalar field of the row,
          // so both single and composite keys (e.g. authorityId + type) are
          // supplied automatically; the target operation reads only its own fields.
          const rowValues: Record<string, FieldValue> = { ...(applied ?? {}) };
          for (const [k, v] of Object.entries(params.row as Record<string, unknown>)) {
            if (k !== 'id' && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
              rowValues[k] = v;
            }
          }
          return rowActions.map((op) => (
            <GridActionsCellItem
              key={op.id}
              label={op.title}
              showInMenu
              onClick={() => setDialog({ operationId: op.id, initialValues: rowValues })}
            />
          ));
        },
      });
    }
    return dataColumns;
  }, [rows, rowActions, applied]);

  // Index-based grid id: robust for composite-key entities (e.g. repository
  // aliases keyed by authorityId + type) where no single field is unique.
  const gridRows = useMemo(() => rows.map((r, i) => ({ ...r, id: i })), [rows]);

  const refresh = () => { setCursor(undefined); return queryClient.invalidateQueries({ queryKey: queryKey.slice(0, 4) }); };

  if (!listSpec) return <Alert severity="error">Unknown list operation {listing.listOperationId}.</Alert>;
  if (!searchAvailable) return <Alert severity="info">Certificate search is unavailable for this deployment or identity.</Alert>;

  return (
    <>
      {filterFields.length > 0 && (
        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            {hasRequired ? `Choose a ${listing.entity === 'status object' ? 'issuer' : 'filter'} to load` : 'Filters'}
          </Typography>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'flex-end' }}>
            {filterFields.map((f) => (
              <Box key={`${f.name}:${selectionContextKey(f, draft)}`} sx={{ minWidth: 220, flex: 1 }}>
                <OperationField field={f} context={draft} value={draft[f.name]} onChange={(v) => setDraft((d) => changeFormValue(listSpec, d, f.name, v))} />
              </Box>
            ))}
            <Button variant="contained" disabled={!draftReady} onClick={() => { setCursor(undefined); setApplied({ ...draft }); }} sx={{ flexShrink: 0 }}>
              {applied === null ? 'Load' : 'Apply'}
            </Button>
          </Stack>
        </Paper>
      )}

      <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1, mb: 1 }}>
        <Button size="small" startIcon={<RefreshIcon />} onClick={refresh} variant="outlined" disabled={applied === null}>
          Refresh
        </Button>
        {creates.length > 0 && (
          <Button size="small" startIcon={<AddIcon />} variant="contained" onClick={(e) => setCreateAnchor(e.currentTarget)}>
            Create
          </Button>
        )}
        <Menu anchorEl={createAnchor} open={!!createAnchor} onClose={() => setCreateAnchor(null)}>
          {creates.map((op) => (
            <MenuItem
              key={op.id}
              onClick={() => {
                setCreateAnchor(null);
                setDialog({ operationId: op.id, initialValues: { ...(applied ?? {}) } });
              }}
            >
              {op.title}
            </MenuItem>
          ))}
        </Menu>
      </Box>

      {applied === null ? (
        <Alert severity="info">Provide the required filter above and choose Load to list {listing.entity}s.</Alert>
      ) : query.isError ? (
        <>
          <Alert severity="error" sx={{ mb: 2 }}>{query.error.message}</Alert>
          <OperationBrowser operations={rowActions.concat(creates)} />
        </>
      ) : (
        <Paper variant="outlined" sx={{ p: 1 }}>
          {query.isLoading ? (
            <Skeleton variant="rounded" height={320} />
          ) : (
            <DataGrid
              rows={gridRows}
              columns={columns}
              density="compact"
              autoHeight
              loading={query.isFetching}
              pageSizeOptions={[10, 25, 50, 100]}
              initialState={{ pagination: { paginationModel: { pageSize: 25 } } }}
              slots={{ toolbar: GridToolbar }}
              slotProps={{ toolbar: { showQuickFilter: true } }}
              sx={{ '& .MuiDataGrid-cell': { fontFamily: 'Roboto Mono, monospace', fontSize: 12 } }}
            />
          )}
        </Paper>
      )}

      {query.data && <Stack direction="row" spacing={1} sx={{ my: 1 }}>
        <Button disabled={cursor === undefined || query.isFetching} onClick={() => setCursor(undefined)}>First results</Button>
        <Button disabled={query.data.next === undefined || query.isFetching} onClick={() => setCursor(query.data?.next)}>Next results</Button>
      </Stack>}

      <OperationDialog
        operationId={dialog?.operationId ?? null}
        open={!!dialog}
        initialValues={dialog?.initialValues}
        onClose={() => setDialog(null)}
        onCompleted={() => void refresh()}
      />
    </>
  );
}

interface Props {
  readonly navId: string;
  readonly title: string;
  readonly description?: string;
  readonly listings: readonly DomainListing[];
}

/** Domain screen: one entity table, or a tab per entity for multi-entity areas. */
export function EntityListPage({ navId, title, description, listings }: Props) {
  const [tab, setTab] = useState(0);
  const active = listings[tab] ?? listings[0]!;

  return (
    <>
      <PageHeader title={title} description={description} />
      {listings.length > 1 && (
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }} variant="scrollable" allowScrollButtonsMobile>
          {listings.map((l, i) => (
            <Tab key={l.listOperationId} label={l.title} value={i} />
          ))}
        </Tabs>
      )}
      <EntityTable key={active.listOperationId} navId={navId} listing={active} />
    </>
  );
}
