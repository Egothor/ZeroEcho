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

import { Alert, Box, Chip, Paper, Skeleton, Stack, Typography } from '@mui/material';
import { PageHeader } from '@/components/PageHeader';
import { useRealm } from '@/hooks/useRealm';
import { useOperationDescriptors } from '@/api/operations';

function Stat({ label, value }: { readonly label: string; readonly value: string | number }) {
  return (
    <Paper variant="outlined" sx={{ p: 2, minWidth: 160 }}>
      <Typography variant="h2">{value}</Typography>
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
    </Paper>
  );
}

export function RealmPage() {
  const realm = useRealm();
  const descriptors = useOperationDescriptors();

  const ops = descriptors.data?.operations ?? [];
  const mutating = ops.filter((o) => o.mutating).length;
  const highRisk = ops.filter((o) => o.approval === 'HIGH_RISK').length;

  return (
    <>
      <PageHeader title="Realm" description="The administrative realm this console is operating within." />

      {realm.isLoading && <Skeleton variant="rounded" height={120} />}
      {realm.isError && (
        <Alert severity="warning">Realm metadata is unavailable. Confirm your client certificate is authorized.</Alert>
      )}

      {realm.data && (
        <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
          <Stack spacing={1}>
            <Typography variant="h2">{realm.data.displayName}</Typography>
            <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
              <Chip label={`realm: ${realm.data.realmId}`} variant="outlined" />
              <Chip label={`authority exposure: ${realm.data.authorityExposure}`} variant="outlined" />
              <Chip
                color={realm.data.authorityCreationPermitted ? 'success' : 'default'}
                variant="outlined"
                label={realm.data.authorityCreationPermitted ? 'authority creation permitted' : 'authority creation restricted'}
              />
            </Stack>
          </Stack>
        </Paper>
      )}

      <Typography variant="h3" sx={{ mb: 1.5 }}>
        Operations available to you
      </Typography>
      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <Stat label="Discoverable operations" value={descriptors.isLoading ? '…' : ops.length} />
        <Stat label="Mutating" value={descriptors.isLoading ? '…' : mutating} />
        <Stat label="HIGH_RISK" value={descriptors.isLoading ? '…' : highRisk} />
      </Box>
    </>
  );
}
