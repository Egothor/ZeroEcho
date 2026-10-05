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

import { OPERATIONS } from '@/api/operationCatalog';
import type { OperationSpec } from '@/api/operationSchema';

/**
 * Demo personas. Each maps to a discoverability predicate that mirrors how the
 * server's authorization engine filters `GET /admin/v1/operations` per principal.
 * Switching persona lets a reviewer walk the console as an administrator and as
 * an ordinary user without any client certificate.
 */
export type DemoRole = 'ADMINISTRATOR' | 'OPERATOR' | 'AUDITOR' | 'ISSUER' | 'PUBLIC_USER';

export const DEMO_ROLES: readonly { id: DemoRole; label: string; description: string }[] = [
  { id: 'ADMINISTRATOR', label: 'Administrator', description: 'Full realm administration (all operations).' },
  { id: 'OPERATOR', label: 'Operator', description: 'Day-to-day issuance, lifecycle, revocation, status, publication.' },
  { id: 'ISSUER', label: 'Issuer', description: 'Submit requests and issue/inspect credentials.' },
  { id: 'AUDITOR', label: 'Auditor', description: 'Read-only visibility, including the audit trail.' },
  { id: 'PUBLIC_USER', label: 'Ordinary user', description: 'A non-privileged user: submit and inspect own requests only.' },
];

const OPERATOR_PREFIXES = [
  'ca.list', 'ca.inspect', 'issuer.', 'profile.list', 'profile.inspect', 'profile.validate',
  'request.', 'credential.', 'revocation.', 'status.', 'inventory.status', 'publication.',
  'configuration.validate', 'algorithm.binding.',
];

const ISSUER_ALLOW = new Set([
  'request.import', 'request.inspect', 'request.verify', 'credential.issue', 'credential.inspect',
  'ca.list', 'ca.inspect', 'profile.list', 'profile.inspect', 'revocation.inspect',
]);

const PUBLIC_ALLOW = new Set(['request.import', 'request.inspect', 'request.verify', 'credential.inspect']);

function operatorAllows(op: OperationSpec): boolean {
  if (op.approval === 'HIGH_RISK') return false;
  if (op.family === 'SERVER_CONTROL_OPERATION') return false;
  return OPERATOR_PREFIXES.some((p) => op.id === p || op.id.startsWith(p));
}

/** Whether the given persona can discover/invoke the operation. */
export function roleCanInvoke(role: DemoRole, op: OperationSpec): boolean {
  if (!op.available) return false;
  switch (role) {
    case 'ADMINISTRATOR':
      return true;
    case 'OPERATOR':
      return operatorAllows(op);
    case 'ISSUER':
      return ISSUER_ALLOW.has(op.id);
    case 'AUDITOR':
      return op.read;
    case 'PUBLIC_USER':
      return PUBLIC_ALLOW.has(op.id);
  }
}

export function discoverableOperations(role: DemoRole): OperationSpec[] {
  return OPERATIONS.filter((op) => roleCanInvoke(role, op));
}
