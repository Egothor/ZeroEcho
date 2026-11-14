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
import { api } from '@/api/client';

/** Realm metadata as returned by `GET /admin/v1/realm`. */
export interface RealmInfo {
  readonly realmId: string;
  readonly displayName: string;
  readonly authorityExposure: string;
  readonly authorityCreationPermitted: boolean;
  readonly publicRepository?: { readonly available: boolean; readonly authorityListAvailable?: boolean; readonly basePath?: string };
}

const realmResponse = z.object({
  version: z.literal(1), requestId: z.string().min(1), operation: z.literal('realm.inspect'),
  status: z.literal('SUCCEEDED'), failure: z.null(),
  result: z.object({ realmId: z.string().min(1), displayName: z.string().min(1),
    authorityExposure: z.string().min(1), authorityCreationPermitted: z.boolean(),
    publicRepository: z.object({ available: z.boolean(), authorityListAvailable: z.boolean().optional(), basePath: z.literal('/public/v1').optional() }).optional() }),
});

/**
 * Reads validated realm metadata from the administrative success envelope.
 * @returns Query state with the decoded realm result; malformed responses become query errors.
 */
export function useRealm() {
  return useQuery({
    queryKey: ['realm'],
    queryFn: async ({ signal }): Promise<RealmInfo> => realmResponse.parse(await api.get<unknown>('/admin/v1/realm', { signal })).result,
    staleTime: 5 * 60_000,
    retry: false,
  });
}
