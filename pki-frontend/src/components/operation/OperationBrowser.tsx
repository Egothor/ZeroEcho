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
  Box,
  Chip,
  InputAdornment,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Skeleton,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import type { OperationSpec } from '@/api/operationSchema';
import { indexDescriptors, useOperationDescriptors } from '@/api/operations';
import { OperationRunner } from '@/components/operation/OperationRunner';

interface Props {
  readonly operations: readonly OperationSpec[];
}

/** Two-pane operation browser: a searchable, discoverability-filtered list + a runner. */
export function OperationBrowser({ operations }: Props) {
  const descriptors = useOperationDescriptors();
  const index = useMemo(() => indexDescriptors(descriptors.data), [descriptors.data]);
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<string | null>(null);

  // Until the catalog loads (or if it is unavailable) show all; once loaded,
  // only operations this identity may invoke are shown at all — never merely
  // disabled. The server remains the authority on every request.
  const permitted = (id: string) => index.size === 0 || index.has(id);

  const visible = useMemo(() => {
    const q = search.trim().toLowerCase();
    return operations
      .filter((o) => permitted(o.id))
      .filter((o) => !q || o.title.toLowerCase().includes(q) || o.id.toLowerCase().includes(q))
      .slice()
      .sort((a, b) => Number(a.read) - Number(b.read) || a.title.localeCompare(b.title));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [operations, search, index]);

  const activeId = selected ?? visible[0]?.id ?? null;

  return (
    <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: '340px 1fr' }, alignItems: 'start' }}>
      <Paper variant="outlined" sx={{ p: 1.5 }}>
        <TextField
          fullWidth
          size="small"
          placeholder="Filter operations"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          sx={{ mb: 1 }}
          slotProps={{
            input: {
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" />
                </InputAdornment>
              ),
            },
          }}
        />
        {descriptors.isLoading && <Skeleton variant="rounded" height={200} />}
        <List dense sx={{ maxHeight: '70vh', overflowY: 'auto' }}>
          {visible.map((op) => (
            <ListItemButton
              key={op.id}
              selected={op.id === activeId}
              onClick={() => setSelected(op.id)}
              sx={{ borderRadius: 1 }}
            >
              <ListItemText
                primary={
                  <Stack direction="row" spacing={0.5} alignItems="center">
                    <span>{op.title}</span>
                    {op.approval === 'HIGH_RISK' && <Chip size="small" color="error" label="HR" sx={{ height: 18 }} />}
                  </Stack>
                }
                secondary={op.id}
                slotProps={{ secondary: { sx: { fontFamily: 'Roboto Mono, monospace', fontSize: 11 } } }}
              />
            </ListItemButton>
          ))}
          {visible.length === 0 && !descriptors.isLoading && (
            <Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>
              {search ? 'No operations match.' : 'No operations in this area are available to your identity.'}
            </Typography>
          )}
        </List>
      </Paper>

      <Box>
        {descriptors.isError && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            Could not load the operation catalog. Showing the built-in operation set; the server remains authoritative.
          </Alert>
        )}
        {activeId ? (
          <OperationRunner
            key={activeId}
            operationId={activeId}
            descriptor={index.get(activeId)}
            permitted={permitted(activeId)}
          />
        ) : (
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Typography color="text.secondary">Select an operation.</Typography>
          </Paper>
        )}
      </Box>
    </Box>
  );
}
