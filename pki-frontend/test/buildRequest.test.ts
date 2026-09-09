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

import { describe, expect, it } from 'vitest';
import { buildRequest } from '@/api/operations';
import { operationSpec } from '@/api/operationCatalog';

function spec(id: string) {
  const s = operationSpec(id);
  if (!s) throw new Error(`missing ${id}`);
  return s;
}

describe('buildRequest', () => {
  it('derives the top-level authorityId from an embedded argument', () => {
    const { path, request } = buildRequest(spec('ca.inspect'), { caId: 'ca-1' });
    expect(path).toBe('/admin/v1/operations/ca.inspect');
    expect(request.authorityId).toBe('ca-1');
    expect(request.arguments).toEqual({ caId: 'ca-1' });
    expect(request.version).toBe(1);
  });

  it('omits authorityId for realm-wide operations and coerces integers', () => {
    const { request } = buildRequest(spec('ca.list'), { limit: '25' });
    expect(request.authorityId).toBeUndefined();
    expect(request.arguments).toEqual({ limit: 25 });
  });

  it('requires an explicit authorityId for authority-scoped ops without an embedded field', () => {
    expect(() => buildRequest(spec('profile.list'), { profileId: 'p1' })).toThrow(/authority/i);
    const { request } = buildRequest(spec('profile.list'), { profileId: 'p1', __authorityId: 'ca-2' });
    expect(request.authorityId).toBe('ca-2');
    expect(request.arguments).toEqual({ profileId: 'p1' });
  });

  it('throws when a required field is missing', () => {
    expect(() => buildRequest(spec('ca.transition'), { caId: 'ca-1', state: 'RETIRED' })).toThrow(/required/i);
  });

  it('omits optional fields left blank', () => {
    const { request } = buildRequest(spec('credential.revoke'), {
      credentialId: 'cred-1',
      reason: 'SUPERSEDED',
      justification: '',
      __authorityId: 'ca-1',
    });
    expect(request.arguments).toEqual({ credentialId: 'cred-1', reason: 'SUPERSEDED' });
    expect(request.authorityId).toBe('ca-1');
  });

  it('carries enum-set arrays and optional approval/deadline', () => {
    const { request } = buildRequest(
      spec('acme.directory.register'),
      {
        alias: 'tls', authorityId: 'ca-1', profileId: 'p', dnsNamespaces: ['example.org'],
        maximumValidityMillis: '86400000', publicKeyAlgorithms: ['EC'], x509BindingPolicies: ['default'],
        challengeTypes: ['HTTP_01', 'DNS_01'], challengeProviderIds: ['http'], eabRequired: false,
      },
      { approvalId: 'ap-1', deadline: 'PT30S' },
    );
    expect(request.authorityId).toBe('ca-1');
    expect(request.arguments['challengeTypes']).toEqual(['HTTP_01', 'DNS_01']);
    expect(request.approvalId).toBe('ap-1');
    expect(request.deadline).toBe('PT30S');
  });
});
