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

/**
 * Entity reference sources.
 *
 * Maps a field's `ref` entity type to the list operation that enumerates
 * candidates, so reference fields become type-to-search pickers instead of
 * free-text identifier boxes. Only entities that have a realm-wide list
 * operation appear here; entities without one (credentials, requests, profiles,
 * issuer generations, status objects, chain paths) fall back to a free-entry
 * search field until the backend adds the corresponding list/search operation
 * (see docs/backend-gap-analysis.md, GAP-1 and the picker-support note).
 */

export interface RefSource {
  /** List operation id that returns candidate records. */
  readonly operationId: string;
  /** Arguments to pass to the list operation. */
  readonly args: Record<string, unknown>;
  /** Key under `result` holding the array of records. */
  readonly resultKey: string;
  /** Field on each record that is the identifier to submit. */
  readonly idKey: string;
  /** Fields on each record shown as a secondary label. */
  readonly labelKeys: readonly string[];
  /** Human name of the entity (for placeholders). */
  readonly label: string;
}

export const REF_SOURCES: Record<string, RefSource> = {
  authority: {
    operationId: 'ca.list', args: { limit: 200 }, resultKey: 'authorities',
    idKey: 'caId', labelKeys: ['subject', 'state'], label: 'authority',
  },
  publication: {
    operationId: 'publication.list', args: { limit: 200 }, resultKey: 'publications',
    idKey: 'publicationId', labelKeys: ['sourceType', 'state'], label: 'publication',
  },
  principal: {
    operationId: 'security.principal.list', args: { offset: 0, limit: 200 }, resultKey: 'principals',
    idKey: 'principalId', labelKeys: ['displayName', 'type'], label: 'principal',
  },
  grant: {
    operationId: 'security.grant.list', args: { offset: 0, limit: 200 }, resultKey: 'grants',
    idKey: 'grantId', labelKeys: ['principalId', 'action'], label: 'grant',
  },
  roleTemplate: {
    operationId: 'security.role-template.list', args: {}, resultKey: 'roleTemplates',
    idKey: 'templateId', labelKeys: ['version'], label: 'role template',
  },
  roleAssignment: {
    operationId: 'security.role-assignment.list', args: { offset: 0, limit: 200 }, resultKey: 'roleAssignments',
    idKey: 'assignmentId', labelKeys: ['principalId', 'templateId'], label: 'role assignment',
  },
  approval: {
    operationId: 'security.approval.list', args: { offset: 0, limit: 200 }, resultKey: 'approvals',
    idKey: 'approvalId', labelKeys: ['targetOperation', 'state'], label: 'approval',
  },
  breakGlass: {
    operationId: 'security.break-glass.list', args: { offset: 0, limit: 200 }, resultKey: 'breakGlass',
    idKey: 'breakGlassId', labelKeys: ['principalId', 'state'], label: 'break-glass grant',
  },
  acmeDirectory: {
    operationId: 'acme.directory.list', args: { offset: 0, limit: 200 }, resultKey: 'acmeDirectories',
    idKey: 'directoryId', labelKeys: ['alias', 'state'], label: 'ACME directory',
  },
  acmeAccount: {
    operationId: 'acme.account.list', args: { offset: 0, limit: 200 }, resultKey: 'acmeAccounts',
    idKey: 'accountId', labelKeys: ['contact', 'state'], label: 'ACME account',
  },
  ocspResponder: {
    operationId: 'ocsp.responder.list', args: { offset: 0, limit: 200 }, resultKey: 'ocspResponders',
    idKey: 'responderId', labelKeys: ['alias', 'state'], label: 'OCSP responder',
  },
  algorithmBinding: {
    operationId: 'algorithm.binding.list', args: { limit: 200 }, resultKey: 'algorithmBindings',
    idKey: 'bindingId', labelKeys: ['algorithm', 'role'], label: 'algorithm binding',
  },
};

export function refSource(ref: string | undefined): RefSource | undefined {
  return ref ? REF_SOURCES[ref] : undefined;
}
