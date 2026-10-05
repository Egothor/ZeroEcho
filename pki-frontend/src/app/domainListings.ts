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

import { operationSpec, operationsForNav } from '@/api/operationCatalog';
import type { OperationId } from '@/api/operationCatalog';
import type { OperationSpec } from '@/api/operationSchema';

/**
 * Entity-centric listing configuration per navigation area.
 *
 * A domain with listings renders as a real admin screen: an auto-loaded,
 * paginated, sortable, filterable table of entities, with per-row actions
 * (inspect + mutations pre-filled with the row's id) and Create actions. A
 * multi-entity area declares several listings and is rendered with a tab per
 * entity. Scoped lists require their authority or issuer selection first.
 */
export interface DomainListing {
  /** Tab / section label. */
  readonly title: string;
  /** List operation whose result populates the table. */
  readonly listOperationId: OperationId;
  /** Arguments for the list operation. */
  readonly args: Record<string, unknown>;
  /** Key under `result` holding the row array. */
  readonly resultKey: string;
  /** Row field that identifies the entity. */
  readonly idKey: string;
  /** Operation-argument name that per-row actions pre-fill with the row id. */
  readonly idArg: string;
  /** Human singular name of the entity. */
  readonly entity: string;
  /**
   * Operations that create a new entity of this type. Declared explicitly
   * because creation conventions differ (some mint the id as an argument, some —
   * like authorities — have the server assign it), so it cannot be derived
   * reliably. Row/inspect actions ARE derived (ref-based) and need no config.
   */
  readonly createOperationIds?: readonly OperationId[];
}

export const DOMAIN_LISTINGS: Record<string, readonly DomainListing[]> = {
  requests: [
    { title: 'Certificate requests', listOperationId: 'request.list', args: { limit: 100 }, resultKey: 'requests', idKey: 'requestId', idArg: 'requestId', entity: 'request', createOperationIds: ['request.import'] },
  ],
  issuance: [
    { title: 'Certificates', listOperationId: 'credential.search', args: { limit: 100 }, resultKey: 'credentials', idKey: 'credentialId', idArg: 'credentialId', entity: 'certificate', createOperationIds: ['credential.issue'] },
  ],
  authorities: [
    { title: 'Authorities', listOperationId: 'ca.list', args: { limit: 200 }, resultKey: 'authorities', idKey: 'caId', idArg: 'caId', entity: 'authority', createOperationIds: ['ca.create', 'ca.intermediate.create', 'ca.intermediate.issue'] },
  ],
  principals: [
    { title: 'Principals', listOperationId: 'security.principal.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'principalId', idArg: 'principalId', entity: 'principal', createOperationIds: ['security.principal.register'] },
  ],
  access: [
    { title: 'Grants', listOperationId: 'security.grant.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'grantId', idArg: 'grantId', entity: 'grant', createOperationIds: ['security.grant.create'] },
    { title: 'Role assignments', listOperationId: 'security.role-assignment.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'assignmentId', idArg: 'assignmentId', entity: 'role assignment', createOperationIds: ['security.role-assignment.create'] },
    { title: 'Role templates', listOperationId: 'security.role-template.list', args: {}, resultKey: 'value', idKey: 'templateId', idArg: 'templateId', entity: 'role template' },
  ],
  approvals: [
    { title: 'Approvals', listOperationId: 'security.approval.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'approvalId', idArg: 'approvalId', entity: 'approval', createOperationIds: ['security.approval.request'] },
  ],
  'break-glass': [
    { title: 'Break-glass', listOperationId: 'security.break-glass.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'breakGlassId', idArg: 'breakGlassId', entity: 'break-glass grant', createOperationIds: ['security.break-glass.create'] },
  ],
  publication: [
    { title: 'Publications', listOperationId: 'publication.list', args: { limit: 200 }, resultKey: 'publications', idKey: 'publicationId', idArg: 'publicationId', entity: 'publication', createOperationIds: ['publication.register'] },
  ],
  acme: [
    { title: 'Directories', listOperationId: 'acme.directory.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'directoryId', idArg: 'directoryId', entity: 'ACME directory', createOperationIds: ['acme.directory.register'] },
    { title: 'Accounts', listOperationId: 'acme.account.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'accountId', idArg: 'accountId', entity: 'ACME account' },
  ],
  ocsp: [
    { title: 'Responders', listOperationId: 'ocsp.responder.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'responderId', idArg: 'responderId', entity: 'OCSP responder', createOperationIds: ['ocsp.responder.register'] },
  ],
  scep: [
    { title: 'Endpoints', listOperationId: 'scep.endpoint.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'label', idArg: 'label', entity: 'SCEP endpoint', createOperationIds: ['scep.endpoint.register'] },
  ],
  cmp: [
    { title: 'Endpoints', listOperationId: 'cmp.endpoint.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'label', idArg: 'label', entity: 'CMP endpoint', createOperationIds: ['cmp.endpoint.register'] },
  ],
  est: [
    { title: 'Endpoints', listOperationId: 'est.endpoint.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'label', idArg: 'label', entity: 'EST endpoint', createOperationIds: ['est.endpoint.register'] },
  ],
  enrollment: [
    { title: 'Profiles', listOperationId: 'enrollment.profile.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'id', idArg: 'id', entity: 'enrollment profile', createOperationIds: ['enrollment.profile.register'] },
  ],
  configuration: [
    { title: 'Algorithm bindings', listOperationId: 'algorithm.binding.list', args: { limit: 200 }, resultKey: 'bindings', idKey: 'bindingId', idArg: 'bindingId', entity: 'algorithm binding' },
  ],
  repository: [
    { title: 'Repository aliases', listOperationId: 'repository.alias.list', args: { offset: 0, limit: 200 }, resultKey: 'value.items', idKey: 'authorityId', idArg: 'authorityId', entity: 'repository alias', createOperationIds: ['repository.alias.set'] },
  ],
  audit: [
    { title: 'Audit trail', listOperationId: 'security.audit.search', args: { limit: 200 }, resultKey: 'value.events', idKey: 'objectId', idArg: 'objectId', entity: 'audit record' },
  ],
  // Parameterised listings: the list operation requires a key (issuer, profile,
  // credential, authority) supplied through the table's filter bar before it loads.
  status: [
    { title: 'Status objects', listOperationId: 'inventory.status', args: { limit: 200 }, resultKey: 'statusObjects', idKey: 'statusObjectId', idArg: 'statusObjectId', entity: 'status object', createOperationIds: ['status.generate'] },
  ],
  issuers: [
    { title: 'Issuer generations', listOperationId: 'issuer.generation.list', args: { limit: 100 }, resultKey: 'generations', idKey: 'issuerId', idArg: 'issuerId', entity: 'issuer generation' },
    { title: 'Chain paths', listOperationId: 'issuer.path.list', args: {}, resultKey: 'paths', idKey: 'pathId', idArg: 'pathId', entity: 'chain path', createOperationIds: ['issuer.path.register'] },
  ],
  profiles: [
    { title: 'Profiles', listOperationId: 'profile.list-all', args: { limit: 100 }, resultKey: 'profiles', idKey: 'profileId', idArg: 'profileId', entity: 'profile', createOperationIds: ['profile.register'] },
    { title: 'Profile versions', listOperationId: 'profile.list', args: {}, resultKey: 'versions', idKey: 'profileVersion', idArg: 'profileVersion', entity: 'profile version', createOperationIds: ['profile.register'] },
  ],
  revocation: [
    { title: 'Revocations', listOperationId: 'revocation.snapshot', args: { limit: 200 }, resultKey: 'revocations', idKey: 'credentialId', idArg: 'credentialId', entity: 'revocation' },
  ],
  confirmations: [
    { title: 'Pending confirmations', listOperationId: 'credential.confirmation.pending.list', args: { limit: 200 }, resultKey: 'pendingConfirmations', idKey: 'credentialId', idArg: 'credentialId', entity: 'pending confirmation' },
  ],
};

export function domainListings(navId: string): readonly DomainListing[] | undefined {
  return DOMAIN_LISTINGS[navId];
}

/**
 * Operations that act on an existing row: any operation in the area (other than
 * the list operation and the declared create operations) that takes the entity's
 * id argument. Matching by argument name — not by `ref` — so it also works for
 * parameterised listings whose id has no realm-wide picker (e.g. status objects).
 */
export function rowActionOps(navId: string, listing: DomainListing): OperationSpec[] {
  const creates = new Set<string>(listing.createOperationIds ?? []);
  return operationsForNav(navId).filter(
    (op) =>
      op.id !== listing.listOperationId &&
      !creates.has(op.id) &&
      op.fields.some((f) => f.name === listing.idArg),
  );
}

/** Explicitly-declared operations that create a new entity of this type. */
export function createOps(listing: DomainListing): OperationSpec[] {
  return (listing.createOperationIds ?? [])
    .map((id) => operationSpec(id))
    .filter((s): s is OperationSpec => !!s);
}
