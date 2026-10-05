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

import { useLocation } from 'react-router-dom';
import { Alert } from '@mui/material';
import { NAV_ITEMS } from '@/app/navigation';
import { operationsForNav } from '@/api/operationCatalog';
import { domainListings } from '@/app/domainListings';
import { PageHeader } from '@/components/PageHeader';
import { OperationBrowser } from '@/components/operation/OperationBrowser';
import { EntityListPage } from '@/pages/EntityListPage';

const DESCRIPTIONS: Record<string, string> = {
  authorities: 'Create and manage certificate authorities, intermediates, rollovers, and key rotation.',
  issuers: 'Inspect issuer generations and manage certificate chain paths.',
  profiles: 'Register, validate, inspect, and activate certificate profiles.',
  requests: 'Import and verify certification requests (CSRs).',
  issuance: 'Issue and inspect credentials.',
  lifecycle: 'Renew, replace, and reissue credentials.',
  confirmations: 'Manage credential confirmation (proof-of-possession) challenges.',
  revocation: 'Revoke credentials and read revocation state and history.',
  status: 'Generate and inspect CRLs and status objects.',
  publication: 'Register, process, retry, and reconcile publications.',
  principals: 'Register and manage security principals.',
  access: 'Manage role templates, role assignments, grants, and evaluate authorization.',
  approvals: 'Request, inspect, and decide durable approvals for HIGH_RISK operations.',
  'break-glass': 'Create, activate, and manage break-glass emergency grants.',
  disclosure: 'Manage disclosure policies and time-bounded disclosure capabilities.',
  audit: 'Search the audit trail, inspect records, and verify chain integrity.',
  acme: 'Administer ACME directories and accounts for automated certificate lifecycle.',
  ocsp: 'Administer OCSP responders for real-time certificate status queries.',
  scep: 'Administer SCEP enrollment endpoints for network devices and MDM pipelines (RFC 8894).',
  cmp: 'Administer CMP enrollment endpoints for telco, automotive (V2X), and regulated deployments (RFC 9480 Lightweight Profile).',
  est: 'Administer EST enrollment endpoints for TLS-protected certificate enrollment over HTTPS (RFC 7030).',
  enrollment: 'Define and manage enrollment profiles that govern policy constraints for SCEP, CMP, EST, and ACME requests.',
  repository: 'Manage repository aliases (stable routes to CRLs and chain paths).',
  configuration: 'Validate configuration and inspect algorithm bindings.',
};

/** Generic domain screen: the operation browser for the current navigation area. */
export function DomainPage() {
  const location = useLocation();
  const item = NAV_ITEMS.find((i) => i.path !== '/' && location.pathname.startsWith(i.path));
  const navId = item?.id ?? '';
  const operations = operationsForNav(navId);
  const listings = domainListings(navId);

  // Entity-centric screen where the backend can enumerate the entity...
  if (listings) {
    return (
      <EntityListPage
        navId={navId}
        title={item?.label ?? 'Entities'}
        description={DESCRIPTIONS[navId]}
        listings={listings}
      />
    );
  }

  // ...otherwise the operation browser (no realm-wide list operation exists yet).
  return (
    <>
      <PageHeader title={item?.label ?? 'Operations'} description={DESCRIPTIONS[navId]} />
      {operations.length === 0 ? (
        <Alert severity="info">No operations are mapped to this area.</Alert>
      ) : (
        <OperationBrowser operations={operations} />
      )}
    </>
  );
}
