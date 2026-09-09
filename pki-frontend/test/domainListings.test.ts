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
import { DOMAIN_LISTINGS, createOps, rowActionOps } from '@/app/domainListings';
import { operationSpec } from '@/api/operationCatalog';

describe('domain listings', () => {
  it('grants table wires revoke/inspect as row actions (no id memorisation) and create separately', () => {
    const grants = DOMAIN_LISTINGS['access']!.find((l) => l.entity === 'grant')!;
    const rowActions = rowActionOps('access', grants).map((o) => o.id);
    expect(rowActions).toContain('security.grant.revoke');
    expect(rowActions).toContain('security.grant.inspect');
    // Another entity's action must not leak into the grants table.
    expect(rowActions).not.toContain('security.role-assignment.revoke');
    expect(createOps(grants).map((o) => o.id)).toEqual(['security.grant.create']);
  });

  it('authorities table exposes lifecycle actions per row and creation actions', () => {
    const authorities = DOMAIN_LISTINGS['authorities']![0]!;
    const rowActions = rowActionOps('authorities', authorities).map((o) => o.id);
    expect(rowActions).toEqual(expect.arrayContaining(['ca.inspect', 'ca.transition', 'ca.rollover', 'ca.rotate']));
    expect(createOps(authorities).map((o) => o.id)).toContain('ca.create');
  });

  it('every listing references a real list operation and declares real create ops', () => {
    for (const listings of Object.values(DOMAIN_LISTINGS)) {
      for (const l of listings) {
        expect(operationSpec(l.listOperationId), l.listOperationId).toBeTruthy();
        for (const id of l.createOperationIds ?? []) {
          expect(operationSpec(id), id).toBeTruthy();
        }
      }
    }
  });

  it('read-only listings (audit, algorithm bindings) declare no create operations', () => {
    expect(DOMAIN_LISTINGS['audit']![0]!.createOperationIds).toBeUndefined();
    expect(DOMAIN_LISTINGS['configuration']![0]!.createOperationIds).toBeUndefined();
  });
});
