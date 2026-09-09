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
import { executeOperation } from '@/api/operations';
import { operationSpec } from '@/api/operationCatalog';
import { refSource } from '@/api/entityRefs';

export interface EntityOption {
  readonly id: string;
  readonly label: string;
}

export interface EntityOptions {
  readonly ids: readonly string[];
  readonly labels: ReadonlyMap<string, string>;
}

const EMPTY: EntityOptions = { ids: [], labels: new Map() };

/**
 * Loads candidate identifiers for a reference field by running the entity's list
 * operation. Fetches lazily (when the picker is opened) and tolerates a denied
 * or missing list operation by returning no suggestions — the field then behaves
 * as a plain free-entry search box. The server remains authoritative.
 */
export function useEntityOptions(ref: string | undefined, enabled: boolean) {
  const source = refSource(ref);
  return useQuery<EntityOptions>({
    queryKey: ['entityOptions', ref],
    enabled: enabled && !!source,
    staleTime: 60_000,
    queryFn: async () => {
      if (!source) return EMPTY;
      const spec = operationSpec(source.operationId);
      if (!spec) return EMPTY;
      const outcome = await executeOperation(spec, source.args as Record<string, never>);
      if (outcome.kind !== 'succeeded') return EMPTY;
      const rows = (outcome.envelope.result?.[source.resultKey] as Record<string, unknown>[] | undefined) ?? [];
      const labels = new Map<string, string>();
      const ids: string[] = [];
      for (const row of rows) {
        const id = row[source.idKey];
        if (typeof id !== 'string') continue;
        ids.push(id);
        const label = source.labelKeys
          .map((k) => row[k])
          .filter((v) => v !== undefined && v !== null && v !== '')
          .join(' · ');
        if (label) labels.set(id, label);
      }
      return { ids, labels };
    },
  });
}
