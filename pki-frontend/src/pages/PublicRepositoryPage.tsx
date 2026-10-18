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

import { lazy, Suspense, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Alert, Box, Button, Link, Paper, Stack, TextField, Typography } from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import { api, ApiRequestError } from '@/api/client';
import { PageHeader } from '@/components/PageHeader';
import { JsonView } from '@/components/operation/JsonView';

const ResultView = lazy(() => import('@/components/ResultView').then((m) => ({ default: m.ResultView })));

/** Read-only browser over the public repository API (`/public/v1/...`). */
export function PublicRepositoryPage() {
  const [authorityId, setAuthorityId] = useState('');

  const authorities = useMutation({
    mutationFn: () => api.get<unknown>('/public/v1/authorities', { query: { limit: 100 } }),
  });

  const links = authorityId.trim()
    ? [
        { label: 'Current chain', href: `/public/v1/authorities/${encodeURIComponent(authorityId.trim())}/chain` },
        { label: 'Current CRL', href: `/public/v1/authorities/${encodeURIComponent(authorityId.trim())}/crl` },
        { label: 'Delta CRL', href: `/public/v1/authorities/${encodeURIComponent(authorityId.trim())}/delta-crl` },
      ]
    : [];

  return (
    <>
      <PageHeader
        title="Public Repository"
        description="The unauthenticated public distribution surface: authority metadata, chains, CRLs, and published certificates."
      />

      <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
        <Typography variant="h3" sx={{ mb: 1.5 }}>
          Published authorities
        </Typography>
        <Button variant="outlined" onClick={() => authorities.mutate()} disabled={authorities.isPending}>
          {authorities.isPending ? 'Loading…' : 'List authorities'}
        </Button>
        {authorities.isError && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            {authorities.error instanceof ApiRequestError
              ? `${authorities.error.code}: ${authorities.error.message}`
              : 'Failed to list authorities'}
          </Alert>
        )}
        {authorities.data != null && (
          <Box sx={{ mt: 2 }}>
            <Suspense fallback={<JsonView value={authorities.data} />}>
              <ResultView value={authorities.data} />
            </Suspense>
          </Box>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 3 }}>
        <Typography variant="h3" sx={{ mb: 1.5 }}>
          Authority artifacts
        </Typography>
        <TextField
          size="small"
          fullWidth
          label="Authority id"
          value={authorityId}
          onChange={(e) => setAuthorityId(e.target.value)}
          sx={{ mb: 2, maxWidth: 420 }}
        />
        <Stack direction="row" spacing={2} sx={{ flexWrap: 'wrap', gap: 1 }}>
          {links.map((l) => (
            <Button
              key={l.href}
              component={Link}
              href={l.href}
              startIcon={<DownloadIcon />}
              variant="text"
              target="_blank"
              rel="noopener"
            >
              {l.label}
            </Button>
          ))}
          {links.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              Enter an authority id to build download links.
            </Typography>
          )}
        </Stack>
      </Paper>
    </>
  );
}
