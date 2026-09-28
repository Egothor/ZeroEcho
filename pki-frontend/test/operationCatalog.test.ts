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
import { OPERATIONS, operationSpec, operationsForNav } from '@/api/operationCatalog';
import { REF_SOURCES, refSource } from '@/api/entityRefs';

describe('operation catalog', () => {
  it('contains all 107 operations (41 PKI + 10 signing + 56 control)', () => {
    expect(OPERATIONS).toHaveLength(107);
    expect(OPERATIONS.filter((o) => o.family === 'PKI_OPERATION')).toHaveLength(41);
    expect(OPERATIONS.filter((o) => o.family === 'SIGNING_OPERATION')).toHaveLength(10);
    expect(OPERATIONS.filter((o) => o.family === 'SERVER_CONTROL_OPERATION')).toHaveLength(56);
  });

  it('has unique operation ids', () => {
    const ids = OPERATIONS.map((o) => o.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('enum and enumSet fields always declare choices', () => {
    for (const op of OPERATIONS) {
      for (const f of op.fields) {
        if (f.type === 'enum' || f.type === 'enumSet') {
          expect(f.choices, `${op.id}.${f.name}`).toBeTruthy();
          expect(f.choices!.length, `${op.id}.${f.name}`).toBeGreaterThan(0);
        }
      }
    }
  });

  it('authorityFrom always references an existing argument and implies authority scope', () => {
    for (const op of OPERATIONS) {
      if (op.authorityFrom) {
        expect(op.scope, op.id).toBe('authority');
        expect(op.fields.map((f) => f.name), op.id).toContain(op.authorityFrom);
      }
    }
  });

  it('realm-scoped operations never derive an authority', () => {
    for (const op of OPERATIONS.filter((o) => o.scope === 'realm')) {
      expect(op.authorityFrom, op.id).toBeUndefined();
    }
  });

  it('read operations carry no approval requirement', () => {
    for (const op of OPERATIONS.filter((o) => o.read)) {
      expect(op.approval, op.id).toBe('NONE');
    }
  });

  it('every reference field points at a known entity source and an existing argument', () => {
    for (const op of OPERATIONS) {
      for (const f of op.fields) {
        if (f.ref) {
          expect(refSource(f.ref), `${op.id}.${f.name} -> ${f.ref}`).toBeTruthy();
        }
      }
    }
  });

  it('reference sources name a list operation that exists in the catalog', () => {
    for (const src of Object.values(REF_SOURCES)) {
      expect(operationSpec(src.operationId), src.operationId).toBeTruthy();
    }
  });

  it('indexes by id and by nav', () => {
    expect(operationSpec('ca.create')?.title).toBe('Create root authority');
    expect(operationsForNav('authorities').length).toBeGreaterThan(0);
    expect(operationSpec('does.not.exist')).toBeUndefined();
  });
});
