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

import { Alert, Box, Card, CardActionArea, CardContent, Stack, Typography } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { PageHeader } from '@/components/PageHeader';
import { NAV_ITEMS } from '@/app/navigation';
import type { NavItem } from '@/app/navigation';
import { useRealm } from '@/hooks/useRealm';
import { MetricsDashboard } from '@/components/MetricsDashboard';

const SECTIONS: { label: string; ids: string[] }[] = [
  { label: 'Certificate Management', ids: ['authorities', 'issuance', 'requests', 'revocation', 'approvals', 'audit'] },
  { label: 'Enrollment Protocols & Services', ids: ['scep', 'cmp', 'est', 'ocsp', 'acme', 'enrollment', 'configuration'] },
];

function NavGrid({ items }: { items: NavItem[] }) {
  return (
    <Box
      sx={{
        display: 'grid',
        gap: 2,
        gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)' },
      }}
    >
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <Card key={item.id} variant="outlined">
            <CardActionArea component={RouterLink} to={item.path}>
              <CardContent>
                <Stack direction="row" spacing={1.5} alignItems="center">
                  <Icon color="primary" />
                  <Typography variant="h3" component="h2">
                    {item.label}
                  </Typography>
                </Stack>
              </CardContent>
            </CardActionArea>
          </Card>
        );
      })}
    </Box>
  );
}

export function DashboardPage() {
  const realm = useRealm();

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Administer certificate authorities, issuance, lifecycle, enrollment protocols, and trust for this realm."
      />

      {realm.isError && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          Realm metadata is unavailable. Confirm your client certificate is presented and authorized.
        </Alert>
      )}

      {realm.data && (
        <Stack spacing={0.5} sx={{ mb: 3 }}>
          <Typography variant="h2">{realm.data.displayName}</Typography>
          <Typography variant="body2" color="text.secondary">
            Realm <code>{realm.data.realmId}</code> · authority exposure {realm.data.authorityExposure} ·
            {realm.data.authorityCreationPermitted ? ' authority creation permitted' : ' authority creation restricted'}
          </Typography>
        </Stack>
      )}

      <MetricsDashboard />

      <Stack spacing={4}>
        {SECTIONS.map((section) => {
          const items = NAV_ITEMS.filter((i) => section.ids.includes(i.id));
          return (
            <Stack key={section.label} spacing={1.5}>
              <Typography variant="overline" color="text.secondary">
                {section.label}
              </Typography>
              <NavGrid items={items} />
            </Stack>
          );
        })}
      </Stack>
    </>
  );
}
