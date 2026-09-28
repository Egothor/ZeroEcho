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
import { createDemoTransport } from '@/demo/demoBackend';
import { discoverableOperations, type DemoRole } from '@/demo/roles';
import type { TransportResponse } from '@/api/transport';

function backend(role: DemoRole) {
  const t = createDemoTransport(() => role);
  return {
    get: (path: string) => t({ method: 'GET', path, headers: {} }),
    post: (path: string, body: unknown) =>
      t({ method: 'POST', path, headers: {}, body: JSON.stringify(body) }),
  };
}

function parse(res: TransportResponse): Record<string, unknown> {
  return JSON.parse(res.body) as Record<string, unknown>;
}

describe('demo backend', () => {
  it('serves realm metadata', async () => {
    const res = await backend('ADMINISTRATOR').get('/admin/v1/realm');
    expect(res.status).toBe(200);
    expect(parse(res)['realmId']).toBe('demo');
  });

  it('filters the operation catalog by persona', async () => {
    const admin = parse(await backend('ADMINISTRATOR').get('/admin/v1/operations'));
    expect(admin['count']).toBe(107);

    const publicUser = parse(await backend('PUBLIC_USER').get('/admin/v1/operations'));
    expect(publicUser['count']).toBe(discoverableOperations('PUBLIC_USER').length);
    expect(publicUser['count']).toBeLessThan(10);

    const auditor = parse(await backend('AUDITOR').get('/admin/v1/operations'));
    expect(auditor['count']).toBe(discoverableOperations('AUDITOR').length);
  });

  it('denies an operation the persona cannot invoke (403)', async () => {
    const res = await backend('PUBLIC_USER').post('/admin/v1/operations/ca.create', {
      version: 1,
      arguments: { formatId: 'f', subjectRef: 's', profileId: 'p', keyRef: 'k' },
    });
    expect(res.status).toBe(403);
    const env = parse(res);
    expect(env['status']).toBe('FAILED');
    expect((env['failure'] as Record<string, unknown>)['code']).toBe('AUTHORIZATION_DENIED');
  });

  it('requires approval for HIGH_RISK operations, then accepts signing with an approval id', async () => {
    const b = backend('ADMINISTRATOR');
    const args = { version: 1, authorityId: 'x', arguments: { formatId: 'f', subjectRef: 's', profileId: 'p', keyRef: 'k' } };
    const first = await b.post('/admin/v1/operations/ca.create', args);
    expect(first.status).toBe(409);
    expect(parse(first)['status']).toBe('APPROVAL_REQUIRED');
    expect((parse(first)['result'] as Record<string, unknown>)['operationCommitment']).toBeTruthy();

    const second = await b.post('/admin/v1/operations/ca.create', { ...args, approvalId: 'ap-1' });
    expect(second.status).toBe(202);
    expect(parse(second)['status']).toBe('PENDING');
    const receipt = parse(second)['result'] as { operationId: string };
    const polled = await b.get(`/admin/v1/signing-operations/${receipt.operationId}`);
    expect(polled.status).toBe(200);
    expect(parse(polled)['result']).toMatchObject({ operationId: receipt.operationId, kind: 'CA', encoding: 'DER' });
    expect(parse(polled)['result']).not.toHaveProperty('completed');
  });

  it('returns seeded records for list operations', async () => {
    const res = await backend('ADMINISTRATOR').post('/admin/v1/operations/ca.list', {
      version: 1,
      arguments: { limit: 50 },
    });
    expect(res.status).toBe(200);
    const result = parse(res)['result'] as Record<string, unknown>;
    expect(Array.isArray(result['authorities'])).toBe(true);
    expect((result['authorities'] as unknown[]).length).toBeGreaterThan(0);
  });
});
