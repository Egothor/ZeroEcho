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
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Stack, Typography } from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import { certificateArtifact, statusArtifact } from '@/api/certificateArtifacts';
import { useDemoMode } from '@/demo/demoModeContext';

/**
 * Offers only server-authorized certificate or status representations using native binary attachments.
 * @param props Exact status/credential or authority identity; current CA resolution belongs to the server.
 * @returns Direct attachment links, or an explicit unavailable state; demo never reaches a real download route.
 */
export function CertificateDownloads(props: { readonly statusObjectId?: string; readonly credentialId?: string; readonly authorityId?: string; readonly compact?: boolean }) {
  const demo = useDemoMode();
  const [opened, setOpened] = useState(!props.compact);
  const status = !!props.statusObjectId;
  const noun = status ? 'Status object' : 'Certificate';
  const downloadLabel = status ? 'Download status object' : props.authorityId && !props.credentialId ? 'Download CA certificate' : 'Download certificate';
  const target = props.credentialId ? { credentialId: props.credentialId } : { authorityId: props.authorityId ?? '' };
  const query = useQuery({ queryKey: ['artifact', props.statusObjectId, target], enabled: opened && !!(props.statusObjectId || props.credentialId || props.authorityId) && !demo.enabled,
    queryFn: async ({ signal }) => props.statusObjectId ? statusArtifact(props.statusObjectId, signal) : certificateArtifact(target, signal), retry: false, staleTime: 15000, refetchOnWindowFocus: true });
  if (demo.enabled) return <Typography variant="caption">{noun} downloads require a live authenticated deployment.</Typography>;
  if (!opened) return <Button size="small" onClick={() => setOpened(true)}>{downloadLabel}</Button>;
  if (query.isLoading) return <Typography variant="caption">Reading {noun.toLowerCase()} access…</Typography>;
  if (query.isError) return <Stack><Typography variant="caption" color="error">{noun} download unavailable for this identity.</Typography><Button size="small" onClick={() => void query.refetch()}>Retry {noun.toLowerCase()} access</Button></Stack>;
  if (!query.data) return null;
  if (query.data.representations.length === 0) return props.compact
    ? <Typography variant="caption">{noun} metadata only</Typography>
    : <Alert severity="info">{noun} metadata is visible, but this identity has no authorized download representation.</Alert>;
  return <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }} aria-label={`${noun} downloads`}>
    {query.data.representations.map(representation => <Button key={representation.id} component="a" href={representation.href}
      download={representation.fileName} size="small" startIcon={<DownloadIcon />} aria-label={`${downloadLabel} — ${representation.label}`}>
      {representation.label}
    </Button>)}
  </Stack>;
}
