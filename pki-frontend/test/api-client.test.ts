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

import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError, api, request } from '@/api/client';

function mockFetch(response: Response) {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValue(response);
}

afterEach(() => vi.restoreAllMocks());

describe('api client', () => {
  it('parses a JSON success body', async () => {
    const fetchSpy = mockFetch(
      new Response(JSON.stringify({ realmId: 'r1', displayName: 'Realm One' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const body = await api.get<{ realmId: string }>('/admin/v1/realm');
    expect(body.realmId).toBe('r1');
    expect(fetchSpy).toHaveBeenCalledOnce();
    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url).toContain('/admin/v1/realm');
  });

  it('appends query parameters and omits undefined ones', async () => {
    const fetchSpy = mockFetch(new Response('[]', { status: 200 }));
    await api.get('/admin/v1/operations', { query: { limit: 25, missing: undefined, flag: true } });
    const url = fetchSpy.mock.calls[0]![0] as string;
    expect(url).toContain('limit=25');
    expect(url).toContain('flag=true');
    expect(url).not.toContain('missing');
  });

  it('maps a structured server failure to ApiRequestError', async () => {
    mockFetch(
      new Response(JSON.stringify({ code: 'AUTHORIZATION_DENIED', message: 'no grant', reason: 'NO_MATCHING_GRANT' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
    const err = await request('/admin/v1/operations/ca.create', { method: 'POST', body: {} }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiRequestError);
    expect((err as ApiRequestError).status).toBe(403);
    expect((err as ApiRequestError).code).toBe('AUTHORIZATION_DENIED');
    expect((err as ApiRequestError).reason).toBe('NO_MATCHING_GRANT');
  });

  it('surfaces a network failure as a synthetic error', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));
    const err = await api.get('/admin/v1/realm').catch((e) => e);
    expect(err).toBeInstanceOf(ApiRequestError);
    expect((err as ApiRequestError).status).toBe(0);
    expect((err as ApiRequestError).code).toBe('network_error');
  });

  it('returns undefined for 204 responses', async () => {
    mockFetch(new Response(null, { status: 204 }));
    const body = await api.get('/admin/v1/nothing');
    expect(body).toBeUndefined();
  });
});
