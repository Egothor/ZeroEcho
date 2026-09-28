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
import { executeOperation, type FieldValue } from '@/api/operations';
import { operationSpec } from '@/api/operationCatalog';
import { contextValue, refSource, resultAt, type RefSource, type SelectionContext } from '@/api/entityRefs';
import { displayLabel } from '@/api/labels';

export interface EntityOption {
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly record: Readonly<Record<string, unknown>>;
}
export interface EntityOptions {
  readonly items: readonly EntityOption[];
  readonly next?: string | number;
}

function readable(value: unknown): string {
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') return '';
  return typeof value === 'string' && /^[A-Z_]+$/.test(value) ? displayLabel(value) : String(value);
}

/** Search authorized pages incrementally, keeping at most one page and no cursor history. */
export async function loadEntityOptions(source: RefSource, context: SelectionContext, search = '', after?: string | number, signal?: AbortSignal): Promise<EntityOptions> {
  const spec = operationSpec(source.operationId);
  if (!spec) throw new Error('This selection source is unavailable.');
  const values: Record<string, FieldValue> = { ...source.args };
  for (const [argument, input] of Object.entries(source.inputs ?? {})) {
    const value = contextValue(context, input);
    if (value === undefined || value === '') throw new Error(`Choose ${input === '$authority' ? 'an authority' : input === '$issuer' ? 'an issuer generation' : displayLabel(input)} first.`);
    values[argument] = value;
  }
  for (const input of Object.values(source.filterBy ?? {})) {
    if (!contextValue(context, input)) throw new Error(`Choose ${displayLabel(input)} first.`);
  }
  let cursor = after;
  do {
    if (signal?.aborted) throw new Error('Selection cancelled.');
    if (source.paging === 'cursor') values['after'] = typeof cursor === 'string' ? cursor : undefined;
    if (source.paging === 'offset') values['offset'] = typeof cursor === 'number' ? cursor : 0;
    const outcome = await executeOperation(spec, values, { signal });
    if (outcome.kind !== 'succeeded') throw new Error(outcome.envelope.failure?.messageKey ?? 'Selection is unavailable.');
    const result = outcome.envelope.result;
    const rows = resultAt(result, source.resultKey);
    if (!Array.isArray(rows)) throw new Error('The server returned an invalid selection list.');
    const page = (source.pagePath ? resultAt(result, source.pagePath) : result) as Record<string, unknown> | null;
    let next: string | number | undefined;
    if (source.paging === 'cursor' && page?.['truncated'] === true) {
      const token = page['nextCursor'];
      if (typeof token !== 'string' || !token || (typeof cursor === 'string' && token <= cursor)) throw new Error('The server returned an invalid continuation.');
      next = token;
    } else if (source.paging === 'offset' && page?.['hasMore'] === true) {
      const offset = page['nextOffset'];
      if (typeof offset !== 'number' || !Number.isSafeInteger(offset) || offset <= Number(cursor ?? 0)) throw new Error('The server returned an invalid continuation.');
      next = offset;
    }
    const items = new Map<string, EntityOption>();
    for (const candidate of rows) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) throw new Error('The server returned an invalid selection item.');
      const row = candidate as Record<string, unknown>;
      if (Object.entries(source.filterBy ?? {}).some(([key, input]) => row[key] !== contextValue(context, input))) continue;
      const identity = row[source.idKey];
      if (typeof identity !== 'string' && typeof identity !== 'number') throw new Error('A selection item has no identity.');
      const id = String(identity);
      const details = source.labelKeys.map((key) => readable(row[key])).filter(Boolean);
      const label = typeof row['displayName'] === 'string' && row['displayName'] ? row['displayName']
        : typeof row['alias'] === 'string' && row['alias'] ? row['alias']
        : `${displayLabel(source.label)}${details.length ? ` · ${details.join(' · ')}` : ''}`;
      const description = id;
      if (`${label} ${id}`.toLowerCase().includes(search.trim().toLowerCase())) items.set(id, { id, label, description, record: row });
    }
    if (items.size > 0 || next === undefined) return { items: [...items.values()], next };
    // Empty filtered pages can still have a continuation, especially with scoped control lists.
    cursor = next;
  } while (cursor !== undefined);
  return { items: [] };
}

export function useEntityOptions(ref: string | undefined, enabled: boolean, context: SelectionContext = {}, search = '', after?: string | number) {
  const source = refSource(ref, context);
  const missing = source && [...Object.values(source.inputs ?? {}), ...Object.values(source.filterBy ?? {})]
    .find((name) => { const value = contextValue(context, name); return value === undefined || value === ''; });
  const query = useQuery<EntityOptions>({
    queryKey: ['entityOptions', ref, context, search, after],
    enabled: enabled && !!source && !missing,
    retry: false,
    staleTime: 0,
    gcTime: 0,
    queryFn: ({ signal }) => loadEntityOptions(source!, context, search, after, signal),
  });
  return { ...query, prerequisite: missing ? `Choose ${missing === '$authority' ? 'an authority' : missing === '$issuer' ? 'an issuer generation' : displayLabel(missing)} first.` : undefined };
}
