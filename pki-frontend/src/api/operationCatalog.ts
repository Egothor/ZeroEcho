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

import { OPERATION_SCHEMA } from '@generated/operationSchema.generated';
import type { OperationSpec } from '@/api/operationSchema';
export type { OperationId } from '@generated/operationSchema.generated';

/** Complete static catalog; execution and navigation also enforce availability. */
export const OPERATIONS: readonly OperationSpec[] = OPERATION_SCHEMA.map((operation) => ({
  id: operation.operationId,
  title: operation.title,
  summary: operation.summary,
  family: operation.family,
  nav: operation.nav,
  scope: operation.scope,
  authorityFrom: operation.authorityFrom || undefined,
  read: !operation.mutating,
  approval: operation.approval,
  available: operation.available,
  permissionAction: operation.permissionAction,
  permissionResourceType: operation.permissionResourceType,
  fields: operation.fields.map((field) => ({
    name: field.name, type: field.semanticType, required: field.required,
    choices: field.choices, ref: field.ref || undefined, allowNew: field.allowNew,
    hidden: field.hidden, readOnly: field.readOnly, label: field.label || undefined,
    help: field.help || undefined, placeholder: field.placeholder || undefined,
  })),
}));

const BY_ID = new Map<string, OperationSpec>(OPERATIONS.map((operation) => [operation.id, operation]));

export function operationSpec(id: string): OperationSpec | undefined {
  return BY_ID.get(id);
}

export function operationsForNav(navId: string): readonly OperationSpec[] {
  return OPERATIONS.filter((operation) => operation.nav === navId && operation.available);
}
