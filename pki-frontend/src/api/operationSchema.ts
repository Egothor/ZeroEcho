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

/**
 * Client-side operation-parameter schema.
 *
 * Rendering types for the generated server OperationDescriptorCatalog projection.
 * Identity, fields, permissions and transport semantics are generated under the
 * server build directory. Runtime discovery controls visibility; the server
 * decoder and authorization boundary remain authoritative for requests.
 */

export type FieldType =
  | 'text'
  | 'pkiId'
  | 'integer'
  | 'long'
  | 'boolean'
  | 'enum'
  | 'enumSet'
  | 'stringSet'
  | 'instant'
  | 'base64'
  | 'json';

export interface FieldSpec {
  readonly name: string;
  readonly type: FieldType;
  readonly required: boolean;
  readonly label?: string;
  readonly help?: string;
  /** Allowed values for `enum`/`enumSet` fields. */
  readonly choices?: readonly string[];
  /** Placeholder / example text. */
  readonly placeholder?: string;
  /**
   * When set, this field references an EXISTING entity of the named type; the UI
   * renders a type-to-search picker backed by that entity's list operation (see
   * entityRefs.ts). Only set on fields that point at existing objects — never on
   * fields that name a NEW id being created.
   */
  readonly ref?: string;
  /** Only for genuinely new values outside the known PKI inventory, such as external key references. */
  readonly allowNew?: boolean;
  /** Continuation is managed by the UI, never transcribed by the operator. */
  readonly hidden?: boolean;
  readonly readOnly?: boolean;
}

import type { OperationFamily } from '@/api/types';
export type { OperationFamily } from '@/api/types';
export type OperationScope = 'realm' | 'authority';
export type ApprovalCategory = 'NONE' | 'HIGH_RISK' | 'ISSUANCE_SINGLE' | 'ISSUANCE_THRESHOLD';

export interface OperationSpec {
  readonly id: string;
  /** Static execution availability; server authorization is additionally required. */
  readonly available: boolean;
  readonly permissionAction: string;
  readonly permissionResourceType: string;
  readonly title: string;
  readonly summary: string;
  readonly family: OperationFamily;
  /** Navigation area id (see navigation.ts) this operation is presented under. */
  readonly nav: string;
  /** Whether the request envelope carries a top-level authorityId. */
  readonly scope: OperationScope;
  /**
   * For authority-scoped operations whose top-level `authorityId` must equal an
   * embedded argument (the server's `validateAuthority`), the name of that
   * argument. The form derives `authorityId` from it instead of asking twice.
   */
  readonly authorityFrom?: string;
  /** Non-mutating read (annotation mirror; server descriptor is authoritative). */
  readonly read: boolean;
  readonly approval: ApprovalCategory;
  readonly fields: readonly FieldSpec[];
}

// ---- compact field builders -------------------------------------------------

type Opt = Partial<Omit<FieldSpec, 'name' | 'type' | 'required'>>;

const mk =
  (type: FieldType, required: boolean) =>
  (name: string, opt: Opt = {}): FieldSpec => ({ name, type, required, ...opt });

export const F = {
  text: mk('text', true),
  textOpt: mk('text', false),
  id: mk('pkiId', true),
  idOpt: mk('pkiId', false),
  int: mk('integer', true),
  long: mk('long', true),
  bool: mk('boolean', true),
  instant: mk('instant', true),
  instantOpt: mk('instant', false),
  base64: mk('base64', true),
  enum: (name: string, choices: readonly string[], opt: Opt = {}): FieldSpec => ({
    name,
    type: 'enum',
    required: true,
    choices,
    ...opt,
  }),
  enumOpt: (name: string, choices: readonly string[], opt: Opt = {}): FieldSpec => ({
    name,
    type: 'enum',
    required: false,
    choices,
    ...opt,
  }),
  enumSet: (name: string, choices: readonly string[], opt: Opt = {}): FieldSpec => ({
    name,
    type: 'enumSet',
    required: false,
    choices,
    ...opt,
  }),
  stringSet: (name: string, opt: Opt = {}): FieldSpec => ({ name, type: 'stringSet', required: true, ...opt }),
};
