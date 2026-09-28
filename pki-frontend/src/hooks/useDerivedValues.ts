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

import { useQuery } from '@tanstack/react-query';
import { operationSpec } from '@/api/operationCatalog';
import { executeOperation, type FieldValue } from '@/api/operations';
import type { OperationSpec } from '@/api/operationSchema';
import { resultAt } from '@/api/entityRefs';

type Values = Record<string, FieldValue>;
async function read(id: string, values: Values, signal: AbortSignal, missing = false) {
  const result = await executeOperation(operationSpec(id)!, values, { signal });
  if (result.kind !== 'succeeded') {
    if (missing && result.envelope.failure?.classification === 'NOT_FOUND') return null;
    throw new Error(result.envelope.failure?.messageKey ?? 'Unable to read the selected record.');
  }
  return result.envelope.result;
}
function text(record: unknown, key: string): string {
  const value = resultAt(record, key);
  if (typeof value !== 'string' || !value) throw new Error(`The selected record has no ${key}.`);
  return value;
}
function strings(record: unknown, key: string): string[] {
  const value = resultAt(record, key);
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) throw new Error(`Invalid profile ${key}.`);
  return value;
}

/** Java Duration output uses hours/minutes/seconds; reject unsafe or nonpositive values. */
export function profileValidityMillis(duration: string): number {
  const match = /^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d{1,9})?)S)?$/.exec(duration);
  if (!match || !match.slice(1).some(Boolean)) throw new Error('Invalid profile maximum validity.');
  const milliseconds = Math.floor((Number(match[1] ?? 0) * 3600 + Number(match[2] ?? 0) * 60 + Number(match[3] ?? 0)) * 1000);
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0) throw new Error('Invalid profile maximum validity.');
  return Math.min(milliseconds, 398 * 86400000);
}

/** Reads authoritative preconditions; query identity prevents a late response crossing selections. */
export function useDerivedValues(spec: OperationSpec, values: Values) {
  const { bindingId, signatureBindingId, signatureAlgorithm, authorityId, type, profileId } = values;
  const binding = spec.id === 'algorithm.binding.validate' && !!bindingId;
  const signature = spec.id === 'ocsp.responder.register' && !!signatureAlgorithm;
  const alias = ['repository.alias.set', 'repository.alias.remove'].includes(spec.id) && !!authorityId && !!type;
  const profile = spec.id === 'acme.directory.register' && !!authorityId && !!profileId;
  const enabled = binding || signature || alias || profile;
  const query = useQuery<Values>({
    queryKey: ['derivedValues', spec.id, bindingId, signatureBindingId, signatureAlgorithm, authorityId, type, profileId],
    enabled, retry: false, staleTime: 0, gcTime: 0,
    queryFn: async ({ signal }) => {
      if (binding || signature) {
        const id = signature ? signatureBindingId : bindingId;
        const result = await read(id ? 'algorithm.binding.inspect' : 'algorithm.binding.list', id ? { bindingId: id } : { limit: 1 }, signal);
        return { [signature ? 'signatureBindingCommitment' : 'expectedCommitment']: text(result, id ? 'bindingCommitment' : 'registryCommitment') };
      }
      if (alias) {
        const result = await read('repository.alias.inspect', { authorityId, type }, signal, spec.id === 'repository.alias.set');
        return { expectedCurrentCommitment: result ? text(result, 'value.recordCommitment') : '' };
      }
      if (profile) {
        const result = await read('profile.list', { __authorityId: authorityId, profileId }, signal);
        const version = result?.activeVersion;
        if (typeof version !== 'number') throw new Error('The selected profile has no active version.');
        const selected = await read('profile.inspect', { __authorityId: authorityId, profileId, profileVersion: version }, signal);
        return { __profileMaximumValidityMillis: profileValidityMillis(text(selected, 'maximumValidity')), publicKeyAlgorithms: strings(selected, 'publicKeyAlgorithms'), x509BindingPolicies: strings(selected, 'x509BindingPolicies') };
      }
      return {};
    },
  });
  const derived = enabled ? query.data ?? {} : {};
  return { values: profile && values.__validityMode !== 'CUSTOM' ? { ...derived, maximumValidityMillis: derived.__profileMaximumValidityMillis } : derived, loading: enabled && query.isPending, error: enabled ? query.error : null };
}
