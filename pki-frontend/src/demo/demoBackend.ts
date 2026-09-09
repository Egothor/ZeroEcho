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

import type { Transport, TransportRequest, TransportResponse } from '@/api/transport';
import type { OperationSpec } from '@/api/operationSchema';
import { operationSpec } from '@/api/operationCatalog';
import { createDemoState, demoId, type DemoState } from '@/demo/demoData';
import { discoverableOperations, roleCanInvoke, type DemoRole } from '@/demo/roles';

const REALM = {
  realmId: 'demo',
  displayName: 'ZeroEcho Demo Realm',
  authorityExposure: 'PUBLIC',
  authorityCreationPermitted: true,
};

/** Operation id -> demo collection whose contents a list operation returns. */
const LIST_MAP: Record<string, string> = {
  'ca.list': 'authorities',
  'issuer.path.list': 'chainPaths',
  'profile.list': 'profiles',
  'publication.list': 'publications',
  'inventory.status': 'statusObjects',
  'revocation.history': 'revocationHistory',
  'revocation.snapshot': 'revocations',
  'credential.confirmation.pending.list': 'pendingConfirmations',
  'security.principal.list': 'principals',
  'security.role-template.list': 'roleTemplates',
  'security.role-assignment.list': 'roleAssignments',
  'security.grant.list': 'grants',
  'security.approval.list': 'approvals',
  'security.break-glass.list': 'breakGlass',
  'security.audit.search': 'auditRecords',
  'repository.alias.list': 'repositoryAliases',
  'acme.directory.list': 'acmeDirectories',
  'acme.account.list': 'acmeAccounts',
  'ocsp.responder.list': 'ocspResponders',
  'algorithm.binding.list': 'algorithmBindings',
};

/** Mutating create/register ops -> collection to append a new record to. */
const CREATE_MAP: Record<string, string> = {
  'ca.create': 'authorities',
  'ca.intermediate.create': 'authorities',
  'profile.register': 'profiles',
  'request.import': 'requests',
  'credential.issue': 'credentials',
  'security.principal.register': 'principals',
  'security.role-assignment.create': 'roleAssignments',
  'security.grant.create': 'grants',
  'security.approval.request': 'approvals',
  'security.break-glass.create': 'breakGlass',
  'acme.directory.register': 'acmeDirectories',
  'ocsp.responder.register': 'ocspResponders',
  'publication.register': 'publications',
};

function descriptorOf(spec: OperationSpec) {
  return {
    operation: spec.id,
    family: spec.family,
    mutating: !spec.read,
    resourceType: spec.family === 'PKI_OPERATION' ? 'AUTHORITY' : 'REALM',
    approval: spec.approval,
    dataView: 'METADATA_REDACTED',
  };
}

function json(status: number, body: unknown, extraHeaders: Record<string, string> = {}): TransportResponse {
  return {
    status,
    headers: { 'content-type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  };
}

function envelope(operation: string, status: string, result: unknown, failure: unknown = null) {
  return { version: 1, requestId: demoId('req'), operation, status, result, failure };
}

function hexCommitment(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function idField(args: Record<string, unknown>): string {
  for (const key of ['caId', 'credentialId', 'requestId', 'publicationId', 'statusObjectId', 'pathId', 'issuerId',
    'principalId', 'grantId', 'assignmentId', 'approvalId', 'breakGlassId', 'directoryId', 'accountId',
    'responderId', 'authorityId', 'objectId', 'profileId', 'bindingId']) {
    if (typeof args[key] === 'string') return args[key] as string;
  }
  return demoId('obj');
}

function dispatch(spec: OperationSpec, args: Record<string, unknown>, state: DemoState): unknown {
  const listKey = LIST_MAP[spec.id];
  if (listKey) {
    const items = state[listKey] ?? [];
    return { [listKey]: items, count: items.length };
  }

  const createKey = CREATE_MAP[spec.id];
  if (createKey) {
    const id = idField(args);
    const record = { ...args, id, createdAt: new Date().toISOString(), state: 'ACTIVE' };
    (state[createKey] ??= []).push(record);
    return { created: id, record };
  }

  if (spec.id.includes('.inspect') || spec.id === 'ca.inspect' || spec.id === 'credential.inspect') {
    const wantedId = idField(args);
    for (const key of Object.keys(state)) {
      const found = state[key]?.find((r) => Object.values(r).includes(wantedId));
      if (found) return found;
    }
    return { ...args, note: 'Synthetic demo record' };
  }

  if (spec.read) {
    return { ...args, result: 'ok', note: 'Demo read result' };
  }

  // Generic mutating outcome: echo and mark ok.
  return { ok: true, applied: args };
}

/**
 * Creates an in-browser transport that answers the admin API from an in-memory
 * dataset, filtered by the active demo persona. No server, no certificate.
 */
export function createDemoTransport(getRole: () => DemoRole): Transport {
  const state = createDemoState();

  return async (req: TransportRequest): Promise<TransportResponse> => {
    const role = getRole();
    const path = req.path.split('?')[0] ?? req.path;

    // Simulate light latency so loading states are visible.
    await new Promise((r) => setTimeout(r, 120));

    if (req.method === 'GET' && path === '/admin/v1/realm') return json(200, REALM);
    if (req.method === 'GET' && path === '/health/live') return json(200, { status: 'LIVE' });
    if (req.method === 'GET' && path === '/health/ready') return json(200, { status: 'READY' });

    if (req.method === 'GET' && path === '/admin/v1/operations') {
      const ops = discoverableOperations(role).map(descriptorOf);
      return json(200, { count: ops.length, operations: ops });
    }

    if (req.method === 'GET' && path.startsWith('/admin/v1/operations/')) {
      const id = decodeURIComponent(path.substring('/admin/v1/operations/'.length));
      const spec = operationSpec(id);
      if (!spec) return json(404, { error: 'unknown operation' });
      return json(200, descriptorOf(spec));
    }

    if (req.method === 'GET' && path.startsWith('/admin/v1/signing-operations/')) {
      const id = decodeURIComponent(path.substring('/admin/v1/signing-operations/'.length));
      return json(200, envelope('signing', 'SUCCEEDED', { signingOperationId: id, completed: true }));
    }

    if (req.method === 'POST' && path.startsWith('/admin/v1/operations/')) {
      const id = decodeURIComponent(path.substring('/admin/v1/operations/'.length));
      const spec = operationSpec(id);
      if (!spec) return json(400, envelope(id, 'FAILED', null, { classification: 'VALIDATION', code: 'UNKNOWN_OPERATION', messageKey: 'Operation is not exposed', recoveryRequired: false, reconciliationRequired: false }));

      if (!roleCanInvoke(role, spec)) {
        return json(403, envelope(id, 'FAILED', null, { classification: 'DENIED', code: 'AUTHORIZATION_DENIED', messageKey: 'NO_MATCHING_GRANT', recoveryRequired: false, reconciliationRequired: false }));
      }

      const body = req.body ? (JSON.parse(req.body) as { approvalId?: string; arguments?: Record<string, unknown> }) : {};
      const args = body.arguments ?? {};

      if (spec.approval === 'HIGH_RISK' && !body.approvalId) {
        return json(409, envelope(id, 'APPROVAL_REQUIRED', { operationCommitment: hexCommitment() }));
      }

      const result = dispatch(spec, args, state);
      return json(200, envelope(id, 'SUCCEEDED', result));
    }

    if (req.method === 'GET' && path === '/public/v1/authorities') {
      return json(200, { authorities: state['authorities'], count: state['authorities']?.length ?? 0 });
    }

    return json(404, { error: 'not found', path });
  };
}
