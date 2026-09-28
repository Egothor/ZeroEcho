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

import type { FieldSpec, OperationSpec } from '@/api/operationSchema';
import type { FieldValue } from '@/api/operations';
import { contextValue, refSource } from '@/api/entityRefs';

const AUTHORITY_FIELDS = ['__authorityId', 'authorityId', 'issuerCaId', 'caId', '__selectionAuthorityId'];
const ISSUER_FIELDS = ['issuerId', '__selectionIssuerId'];
const field = (name: string, ref: string, label: string): FieldSpec => ({ name, ref, label, type: 'pkiId', required: true });

/** Context choices drive reads only; buildRequest never includes these synthetic fields. */
export function selectionFields(spec: OperationSpec, values: Record<string, FieldValue>): FieldSpec[] {
  const fields = [...spec.fields];
  const context: FieldSpec[] = [];
  if (spec.id === 'acme.directory.register') context.push({ name: '__validityMode', type: 'enum', required: true, label: 'Certificate validity', choices: ['PROFILE_MAXIMUM', 'CUSTOM'] });
  if (fields.some((f) => f.ref === 'parentPath')) context.push(field('__parentAuthorityId', 'authority', 'Parent authority'), field('__parentIssuerId', 'parentIssuer', 'Parent issuer generation'));
  if (fields.some((f) => f.ref === 'capability') && !fields.some((f) => f.name === 'objectId')) {
    const object = field('objectId', 'object', 'Published object');
    context.push(object); fields.push(object);
  }
  if (fields.some((f) => f.ref === 'object')) context.unshift({
    name: '__objectKind', type: 'enum', required: true, label: 'Object type', choices: ['credential', 'status', 'path'],
  });
  const sources = fields.map((f) => refSource(f.ref, values));
  const needsIssuer = sources.some((s) => Object.values(s?.inputs ?? {}).includes('$issuer'));
  if (needsIssuer && !spec.fields.some((f) => f.name === 'issuerId')) context.push(field('__selectionIssuerId', 'issuer', 'Issuer generation'));
  const needsAuthority = needsIssuer || sources.some((s) => Object.values(s?.inputs ?? {}).includes('$authority'));
  if (needsAuthority && spec.scope !== 'authority' && !fields.some((f) => AUTHORITY_FIELDS.includes(f.name))) {
    context.unshift(field('__selectionAuthorityId', 'authority', 'Selection authority'));
  }
  return context;
}

const DERIVED_DEPENDENCIES: Readonly<Record<string, readonly string[]>> = {
  maximumValidityMillis: ['profileId', '__validityMode', ...AUTHORITY_FIELDS],
  targetArguments: ['targetOperation'], targetAuthorityId: ['targetOperation'],
  expectedCommitment: ['bindingId'], signatureBindingCommitment: ['signatureBindingId', 'signatureAlgorithm'],
  expectedCurrentCommitment: ['authorityId', 'type'], publicKeyAlgorithms: ['profileId', ...AUTHORITY_FIELDS],
  x509BindingPolicies: ['profileId', ...AUTHORITY_FIELDS],
  expectedLifecycleRevision: ['credentialId'], expectedLifecycleRecordCommitment: ['credentialId'], expectedChallengeRecordCommitment: ['credentialId'],
};

/** Parent changes invalidate their dependent choices, including transitive dependencies. */
export function changeFormValue(spec: OperationSpec, previous: Record<string, FieldValue>, name: string, value: FieldValue): Record<string, FieldValue> {
  if (previous[name] === value) return previous;
  const next = { ...previous, [name]: value };
  const changed = new Set([name]);
  const fields = [...spec.fields, ...selectionFields(spec, previous)];
  let progress = true;
  while (progress) {
    progress = false;
    for (const f of fields) {
      if (changed.has(f.name)) continue;
      const source = refSource(f.ref, previous);
      const dependencies = [...Object.values(source?.inputs ?? {}), ...Object.values(source?.filterBy ?? {}), ...(DERIVED_DEPENDENCIES[f.name] ?? [])];
      if (f.ref === 'sourceObject') dependencies.push('sourceType');
      if (f.ref === 'aliasTarget') dependencies.push('type');
      if (f.ref === 'object') dependencies.push('__objectKind');
      const affected = dependencies.some((dependency) => dependency === '$authority'
        ? AUTHORITY_FIELDS.some((key) => changed.has(key))
        : dependency === '$issuer' ? ISSUER_FIELDS.some((key) => changed.has(key)) : changed.has(dependency));
      if (affected) {
        next[f.name] = f.type === 'stringSet' || f.type === 'enumSet' ? [] : '';
        changed.add(f.name); progress = true;
      }
    }
  }
  return next;
}

export function hasValue(value: FieldValue): boolean {
  return value !== undefined && value !== '' && (!Array.isArray(value) || value.length > 0);
}

export function selectionContextKey(field: FieldSpec, values: Record<string, FieldValue>): string {
  const source = refSource(field.ref, values);
  const names = [...Object.values(source?.inputs ?? {}), ...Object.values(source?.filterBy ?? {})];
  return JSON.stringify([source?.operationId, names.map((name) => contextValue(values, name))]);
}
