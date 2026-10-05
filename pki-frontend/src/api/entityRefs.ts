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

import type { FieldValue } from '@/api/operations';
import type { OperationId } from '@/api/operationCatalog';

export type SelectionContext = Readonly<Record<string, FieldValue>>;
export interface RefSource {
  readonly operationId: OperationId;
  readonly args: Record<string, FieldValue>;
  readonly resultKey: string;
  readonly idKey: string;
  readonly labelKeys: readonly string[];
  readonly label: string;
  readonly paging?: 'cursor' | 'offset';
  readonly pagePath?: string;
  readonly inputs?: Readonly<Record<string, string>>;
  readonly filterBy?: Readonly<Record<string, string>>;
}
const page = (operationId: OperationId, resultKey: string, idKey: string, label: string, labelKeys: string[], extra: Partial<RefSource> = {}): RefSource =>
  ({ operationId, resultKey, idKey, label, labelKeys, args: { limit: 100 }, paging: 'cursor', ...extra });
const control = (operationId: OperationId, idKey: string, label: string, labelKeys: string[]): RefSource =>
  page(operationId, 'value.items', idKey, label, labelKeys, { args: { offset: 0, limit: 100 }, paging: 'offset', pagePath: 'value' });
const configured = (resultKey: string, idKey: string, label: string): RefSource =>
  ({ operationId: 'configuration.choices', args: { limit: 100 }, resultKey: `value.${resultKey}`, idKey, label, labelKeys: ['displayName'] });

/** Exact result paths mirror the signing-operation and selection API response contracts. */
export const REF_SOURCES: Readonly<Record<string, RefSource>> = {
  authority: page('ca.list', 'authorities', 'caId', 'authority', ['displayName', 'kind', 'state']),
  profile: page('profile.list-all', 'profiles', 'profileId', 'certificate profile', ['displayName', 'certificateType', 'formatId']),
  request: page('request.list', 'requests', 'requestId', 'certificate request', ['formatId', 'profileId']),
  credential: page('credential.search', 'credentials', 'credentialId', 'certificate', ['profileId', 'status', 'notAfter'], { inputs: { __authorityId: '$authority' } }),
  issuer: page('issuer.generation.list', 'generations', 'issuerId', 'issuer generation', ['state', 'profileId'], { inputs: { __authorityId: '$authority' } }),
  status: page('inventory.status', 'statusObjects', 'statusObjectId', 'revocation list', ['type', 'thisUpdate'], { inputs: { issuerCaId: '$authority' } }),
  parentIssuer: page('issuer.generation.list', 'generations', 'issuerId', 'parent issuer generation', ['state', 'profileId'], { inputs: { __authorityId: '__parentAuthorityId' } }),
  parentPath: { operationId: 'issuer.path.list', args: {}, resultKey: 'paths', idKey: 'pathId', label: 'parent certificate chain', labelKeys: ['issuerId'], inputs: { issuerId: '__parentIssuerId' } },
  path: { operationId: 'issuer.path.list', args: {}, resultKey: 'paths', idKey: 'pathId', label: 'certificate chain', labelKeys: ['issuerId'], inputs: { issuerId: '$issuer' } },
  profileVersion: { operationId: 'profile.list', args: {}, resultKey: 'versions', idKey: 'profileVersion', label: 'profile version', labelKeys: ['displayName', 'certificateType'], inputs: { profileId: 'profileId', __authorityId: '$authority' } },
  publication: page('publication.list', 'publications', 'publicationId', 'publication', ['sourceType', 'status']),
  principal: control('security.principal.list', 'principalId', 'principal', ['displayName', 'type']),
  grant: control('security.grant.list', 'grantId', 'permission grant', ['principalId', 'action', 'effect']),
  roleTemplate: { operationId: 'security.role-template.list', args: {}, resultKey: 'value', idKey: 'templateId', label: 'role template', labelKeys: ['templateId', 'version'] },
  templateVersion: { operationId: 'security.role-template.list', args: {}, resultKey: 'value', idKey: 'version', label: 'template version', labelKeys: ['templateId'], filterBy: { templateId: 'templateId' } },
  roleAssignment: control('security.role-assignment.list', 'assignmentId', 'role assignment', ['principalId', 'templateId']),
  approval: control('security.approval.list', 'approvalId', 'approval', ['operation', 'requesterId', 'state']),
  breakGlass: control('security.break-glass.list', 'breakGlassId', 'break-glass grant', ['principalId', 'state']),
  acmeDirectory: control('acme.directory.list', 'directoryId', 'ACME directory', ['alias', 'status', 'profileId']),
  acmeAccount: control('acme.account.list', 'accountId', 'ACME account', ['directoryId', 'status', 'createdAt']),
  ocspResponder: control('ocsp.responder.list', 'responderId', 'OCSP responder', ['alias', 'state']),
  scepEndpoint: control('scep.endpoint.list', 'label', 'SCEP endpoint', ['authorityId', 'profileId']),
  cmpEndpoint: control('cmp.endpoint.list', 'label', 'CMP endpoint', ['authorityId', 'protectionPolicy']),
  estEndpoint: control('est.endpoint.list', 'label', 'EST endpoint', ['authorityId', 'profileId']),
  enrollmentProfile: control('enrollment.profile.list', 'id', 'enrollment profile', ['displayName', 'state', 'certificateProfileId']),
  algorithmBinding: page('algorithm.binding.list', 'bindings', 'bindingId', 'algorithm binding', ['algorithmId', 'role', 'origin']),
  algorithmOrigin: page('algorithm.binding.list', 'bindings', 'origin', 'algorithm origin', ['origin']),
  algorithmRole: page('algorithm.binding.list', 'bindings', 'role', 'algorithm role', ['role']),
  format: configured('formats', 'formatId', 'certificate format'),
  key: { ...configured('keys.items', 'keyRef', 'signing key'), paging: 'cursor', pagePath: 'value.keys' },
  signatureAlgorithm: configured('algorithms', 'algorithmId', 'signature algorithm'),
  publicationTarget: { ...configured('publicationTargets', 'targetId', 'publication target'), filterBy: { targetType: 'targetType' } },
  challengeProvider: configured('acmeChallengeProviders', 'providerId', 'challenge provider'),
  eabProvider: configured('acmeEabProviders', 'providerId', 'external-account provider'),
  capability: page('security.disclosure.capability.list', 'value.items', 'capabilityId', 'disclosure capability', ['objectId', 'expiresAt', 'revoked'], { inputs: { objectId: 'objectId' }, pagePath: 'value' }),
};

export function contextValue(context: SelectionContext, name: string): FieldValue {
  if (name === '$authority') return context['__authorityId'] || context['authorityId'] || context['issuerCaId'] || context['caId'] || context['__selectionAuthorityId'];
  if (name === '$issuer') return context['issuerId'] || context['__selectionIssuerId'];
  return context[name];
}

export function refSource(ref: string | undefined, context: SelectionContext = {}): RefSource | undefined {
  if (ref === 'sourceObject') ref = context['sourceType'] === 'STATUS_OBJECT' ? 'status' : 'credential';
  if (ref === 'aliasTarget') ref = context['type'] === 'CURRENT_CHAIN' ? 'path' : 'status';
  if (ref === 'object') ref = String(context['__objectKind'] || 'credential');
  return ref ? REF_SOURCES[ref] : undefined;
}

export function resultAt(value: unknown, path: string): unknown {
  let current = value;
  for (const part of path.split('.').filter(Boolean)) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
