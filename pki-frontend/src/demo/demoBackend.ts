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
import type { SigningCompletedResult } from '@/api/types';
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
  'profile.list-all': 'profiles',
  'request.list': 'requests',
  'credential.search': 'credentials',
  'issuer.generation.list': 'generations',
  'security.disclosure.capability.list': 'capabilities',
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
    resourceType: spec.family === 'SERVER_CONTROL_OPERATION' ? 'REALM' : 'AUTHORITY',
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

function cursorPage(items: Record<string, unknown>[], key: string, args: Record<string, unknown>) {
  const sorted = items.filter((item) => !args.after || String(item[key]) > String(args.after))
    .sort((a, b) => String(a[key]) < String(b[key]) ? -1 : String(a[key]) > String(b[key]) ? 1 : 0);
  const limit = Number(args.limit ?? 100), page = sorted.slice(0, limit), truncated = sorted.length > limit;
  return { items: page, count: page.length, truncated, ...(truncated ? { nextCursor: String(page.at(-1)?.[key]) } : {}) };
}

function dispatch(spec: OperationSpec, args: Record<string, unknown>, state: DemoState): unknown {
  if (spec.id === 'configuration.choices') return { value: {
    formats: [{ formatId: 'x509', displayName: 'X.509 certificate' }],
    signingProviders: [{ providerId: 'local', displayName: 'Local signing provider' }],
    publicationTargets: [{ targetType: 'FILESYSTEM', targetId: 'public-repository', displayName: 'Public repository' }],
    keys: cursorPage([{ keyRef: 'local:root.prv', displayName: 'Root authority key' }, { keyRef: 'local:issuing.prv', displayName: 'Issuing authority key' }], 'keyRef', args),
    algorithms: [{ algorithmId: 'SHA256withECDSA', displayName: 'ECDSA with SHA-256' }],
    acmeChallengeProviders: [{ providerId: 'dns', displayName: 'DNS challenge service', challengeTypes: ['DNS_01'] }],
    acmeEabProviders: [{ providerId: 'accounts', displayName: 'External account service' }],
  } };
  if (spec.id === 'credential.confirmation.challenge.issue') return {
    credentialId: args.credentialId, expectedLifecycleRevision: 1,
    expectedLifecycleRecordCommitment: 'a'.repeat(64), expectedChallengeRecordCommitment: hexCommitment(),
    proofSuiteId: 'demo', expiresAt: new Date(Date.now() + 300000).toISOString(), maximumResponseBytes: 4096,
    presentation: { message: 'Demonstration challenge' },
  };
  const listKey = LIST_MAP[spec.id];
  if (listKey) {
    let items = state[listKey] ?? [];
    for (const name of ['profileId', 'issuerId', 'objectId', 'state', 'requesterPrincipalId', 'targetOperationId']) {
      const key = name === 'requesterPrincipalId' ? 'requesterId' : name === 'targetOperationId' ? 'operation' : name;
      if (args[name]) items = items.filter((item) => item[key] === args[name]);
    }
    if (spec.id === 'credential.search' || spec.id === 'issuer.generation.list') items = items.filter((item) => item.authorityId === args.__authorityId);
    if (spec.id === 'inventory.status') items = items.filter((item) => item.issuerCaId === args.issuerCaId);
    if (spec.id === 'profile.list') return { profileId: args.profileId, versions: items, count: items.length, activeVersion: items.find((item) => item.active)?.profileVersion };
    if (spec.id === 'security.role-template.list') return { value: items };
    if (spec.id === 'security.audit.search') return { value: { events: items, count: items.length } };
    if (spec.id === 'issuer.path.list') return { paths: items, count: items.length };
    const idKeys: Record<string, string> = { authorities: 'caId', profiles: 'profileId', requests: 'requestId', credentials: 'credentialId', generations: 'issuerId', publications: 'publicationId', statusObjects: 'statusObjectId', algorithmBindings: 'bindingId', capabilities: 'capabilityId' };
    if (idKeys[listKey]) {
      const page = cursorPage(items, idKeys[listKey]!, args);
      if (listKey === 'capabilities') return { value: page };
      const key = listKey === 'algorithmBindings' ? 'bindings' : listKey;
      return { [key]: page.items, count: page.count, truncated: page.truncated, ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}), ...(listKey === 'algorithmBindings' ? { registryCommitment: 'b'.repeat(64) } : {}) };
    }
    if (spec.family === 'SERVER_CONTROL_OPERATION') {
      const offset = Number(args.offset ?? 0), limit = Number(args.limit ?? 100);
      const page = items.slice(offset, offset + limit);
      return { value: { items: page, count: page.length, hasMore: offset + limit < items.length, nextOffset: offset + page.length } };
    }
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
    const collection = spec.id === 'repository.alias.inspect' ? 'repositoryAliases' : spec.id === 'profile.inspect' ? 'profiles' : spec.id === 'algorithm.binding.inspect' ? 'algorithmBindings' : undefined;
    for (const key of collection ? [collection] : Object.keys(state)) {
      const found = state[key]?.find((r) => Object.values(r).includes(wantedId) && (args.type === undefined || r.type === args.type) && (args.profileVersion === undefined || r.profileVersion === args.profileVersion));
      if (found) return spec.family === 'SERVER_CONTROL_OPERATION' ? { value: found } : found;
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
  // Demo-only receipt state; the production client keeps no workflow registry.
  const signing = new Map<string, { spec: OperationSpec; result: SigningCompletedResult }>();

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
      const receipt = signing.get(id);
      if (!receipt || !roleCanInvoke(role, receipt.spec)) {
        return json(404, envelope('operation', 'FAILED', null, {
          classification: 'NOT_FOUND', code: 'OPERATION_NOT_FOUND', messageKey: 'OPERATION_NOT_FOUND',
          recoveryRequired: false, reconciliationRequired: false,
        }));
      }
      return json(200, envelope('signing.operation', 'SUCCEEDED', receipt.result));
    }

    if (req.method === 'POST' && path.startsWith('/admin/v1/operations/')) {
      const id = decodeURIComponent(path.substring('/admin/v1/operations/'.length));
      const spec = operationSpec(id);
      if (!spec) return json(400, envelope(id, 'FAILED', null, { classification: 'VALIDATION', code: 'UNKNOWN_OPERATION', messageKey: 'Operation is not exposed', recoveryRequired: false, reconciliationRequired: false }));

      if (!roleCanInvoke(role, spec)) {
        return json(403, envelope(id, 'FAILED', null, { classification: 'DENIED', code: 'AUTHORIZATION_DENIED', messageKey: 'NO_MATCHING_GRANT', recoveryRequired: false, reconciliationRequired: false }));
      }

      const body = req.body ? (JSON.parse(req.body) as { approvalId?: string; authorityId?: string; arguments?: Record<string, unknown> }) : {};
      const args = body.arguments ?? {};

      if (spec.approval === 'HIGH_RISK' && !body.approvalId) {
        return json(409, envelope(id, 'APPROVAL_REQUIRED', { operationCommitment: hexCommitment() }, {
          classification: 'APPROVAL_REQUIRED', code: 'APPROVAL_REQUIRED', messageKey: 'APPROVAL_REQUIRED',
          recoveryRequired: false, reconciliationRequired: false,
        }));
      }

      const result = dispatch(spec, { ...args, __authorityId: body.authorityId }, state);
      if (spec.family === 'SIGNING_OPERATION') {
        const operationId = demoId('sign');
        const kind = id.startsWith('ca.') ? 'CA' : id === 'status.generate' ? 'STATUS' : 'ISSUANCE';
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(result)));
        const completed: SigningCompletedResult = {
          operationId, kind, encoding: kind === 'STATUS' ? 'UTF8' : 'DER',
          resultSha256: Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join(''),
          ...(kind === 'STATUS' ? { statusObjectId: demoId('status') } : { credentialId: demoId('cred') }),
        };
        signing.set(operationId, { spec, result: completed });
        return json(202, envelope(id, 'PENDING', { operationId }), {
          location: `/admin/v1/signing-operations/${encodeURIComponent(operationId)}`,
        });
      }
      return json(200, envelope(id, 'SUCCEEDED', result));
    }

    if (req.method === 'GET' && path === '/public/v1/authorities') {
      return json(200, { authorities: state['authorities'], count: state['authorities']?.length ?? 0 });
    }

    return json(404, { error: 'not found', path });
  };
}
