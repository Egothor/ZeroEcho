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

import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import type { OperationSpec } from '@/api/operationSchema';
import type { FieldValue } from '@/api/operations';
import { REF_SOURCES } from '@/api/entityRefs';
import { loadEntityOptions } from '@/hooks/useEntityOptions';

const inputSchema = z.object({ label: z.string(), help: z.string(), placeholder: z.string(), pattern: z.string().optional() });
/** Provider-owned, portable input guidance for the selected credential format. */
export type SubjectInput = z.infer<typeof inputSchema>;

async function selectedProfile(profileId: string, signal: AbortSignal) {
  let after: string | number | undefined;
  do {
    const page = await loadEntityOptions(REF_SOURCES.profile!, {}, profileId, after, signal);
    const selected = page.items.find(item => item.id === profileId);
    if (selected) return selected.record;
    after = page.next;
  } while (after !== undefined);
  throw new Error('The selected profile is unavailable. Select an accessible active profile.');
}

/**
 * Reads provider-owned subject guidance bound to the selected format and profile.
 * @param spec Current operation schema; operations without subject input perform no lookup.
 * @param values Current typed format/profile/subject values.
 * @returns Input guidance, field validity and lookup state; late responses remain bound to their selection key.
 */
export function useSubjectInput(spec: OperationSpec, values: Record<string, FieldValue>) {
  const formatId = String(values.formatId ?? '');
  const profileId = String(values.profileId ?? '');
  const enabled = spec.fields.some(field => field.name === 'subjectRef') && !!(formatId || profileId);
  const query = useQuery({ queryKey: ['subjectInput', formatId, profileId], enabled, retry: false,
    queryFn: async ({ signal }) => {
      const profile = profileId ? await selectedProfile(profileId, signal) : undefined;
      const profileFormat = typeof profile?.formatId === 'string' ? profile.formatId : undefined;
      if (profileFormat && formatId && profileFormat !== formatId) throw new Error(`The selected profile requires format ${profileFormat}; select the matching format.`);
      const effectiveFormat = profileFormat || formatId;
      const formats = await loadEntityOptions(REF_SOURCES.format!, {}, '', undefined, signal);
      const selected = formats.items.find(item => item.id === effectiveFormat);
      if (!selected) throw new Error('The selected credential format is unavailable.');
      const metadata = inputSchema.parse(selected.record.subjectInput ?? { label: 'Subject reference', help: 'Value interpreted by the selected credential format.', placeholder: '' });
      if (metadata.pattern) {
        try { new RegExp(metadata.pattern); } catch { throw new Error('The selected format returned an invalid subject input pattern.'); }
      }
      return metadata;
    },
  });
  const metadata = enabled ? query.data : undefined;
  const invalid = !!metadata?.pattern && !!values.subjectRef && !new RegExp(metadata.pattern).test(String(values.subjectRef));
  return { metadata, invalid, loading: enabled && query.isPending, error: enabled ? query.error : null };
}
