/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
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

import { X509Certificate } from 'node:crypto';
import { test, expect, type Page, type Locator, type APIRequestContext } from '@playwright/test';

type Envelope = { status: string; result: Record<string, unknown> | null };
type OperationRequest = { version: number; arguments: Record<string, unknown>; authorityId?: string };

function runner(page: Page, title: string): Locator {
  return page.getByRole('region', { name: title, exact: true });
}
async function verifyCertificateAttachments(page: Page, subject: string) {
  async function bytes(label: string, extension: string): Promise<Buffer> {
    const accepted = page.waitForEvent('download');
    await page.getByRole('link', { name: new RegExp(`Download (?:CA )?certificate — ${label}$`) }).click();
    const download = await accepted;
    expect(await download.failure()).toBeNull();
    expect(download.suggestedFilename().endsWith('.' + extension)).toBe(true);
    const stream = await download.createReadStream();
    expect(stream).not.toBeNull();
    const chunks: Buffer[] = [];
    for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  }
  const der = await bytes('DER', 'der');
  const pem = await bytes('PEM', 'pem');
  expect(pem.toString('ascii')).toContain('-----BEGIN CERTIFICATE-----');
  const certificate = new X509Certificate(der);
  expect(certificate.subject).toContain(subject);
  expect(new X509Certificate(pem).raw).toEqual(certificate.raw);
}

async function choose(page: Page, form: Locator, label: string, value: RegExp) {
  await form.getByLabel(label, { exact: true }).click();
  await page.getByRole('option', { name: value }).click();
}
async function operation(page: Page, id: string, title: string) {
  await page.goto('/operations');
  await page.getByPlaceholder('Filter operations').fill(id);
  await page.getByText(id, { exact: true }).first().click();
  return runner(page, title);
}
async function approve(request: APIRequestContext, approvalId: string, authorityId?: string) {
  const response = await request.post('/fixture/approve', {
    data: { version: 1, ...(authorityId ? { authorityId } : {}),
      arguments: { approvalId, justification: 'Independent live fixture approval' } },
  });
  expect(response.status()).toBe(200);
  expect((await response.json() as Envelope).status).toBe('SUCCEEDED');
}
async function submitManaged(page: Page, request: APIRequestContext, form: Locator, approvalRequired = false) {
  const accepted = page.waitForResponse(response => response.url().endsWith('/admin/v1/requests') && response.status() === 202);
  await form.getByRole('button', { name: 'Submit request', exact: true }).click();
  const response = await accepted;
  const intent = response.request().postDataJSON() as OperationRequest & { requestId: string; operation: string };
  const projection = (await response.json() as Envelope).result!;
  const id = String(projection.requestId);
  expect(id).not.toBe('undefined');
  await expect(page).toHaveURL(new RegExp(`/administrative-requests/${id}$`));
  if (approvalRequired || typeof projection.approvalId === 'string') {
    const approvalId = String(projection.approvalId);
    expect(approvalId).not.toBe('undefined');
    const self = await request.post('/admin/v1/operations/security.approval.approve', { data: {
      version: 1, ...(intent.authorityId ? { authorityId: intent.authorityId } : {}),
      arguments: { approvalId, justification: 'Ordinary requester cannot self approve' },
    } });
    expect(self.status()).toBeGreaterThanOrEqual(400);
    expect(self.status()).toBeLessThan(500);
    expect((await self.json() as Envelope).status).toBe('FAILED');
    const conflict = await request.post('/admin/v1/requests', { data: { ...intent, arguments: { ...intent.arguments, ...(typeof intent.arguments.subjectRef === 'string' ? { subjectRef: 'CN=Different Unapproved Subject' } : { displayName: 'Different unapproved display name' }) } } });
    expect(conflict.status()).toBe(409);
    await approve(request, approvalId, intent.authorityId);
  }
  await expect(page.getByText('Operation completed.', { exact: true })).toBeVisible({ timeout: 30000 });
  const inspected = await request.get(`/admin/v1/requests/${encodeURIComponent(id)}`);
  expect(inspected.status()).toBe(200);
  const complete = (await inspected.json() as Envelope).result!;
  expect(complete.state).toBe('SUCCEEDED');
  return { id, intent, complete };
}

test('protocol routes discover and execute available endpoint operations', async ({ page, request }) => {
  for (const protocol of ['est', 'scep', 'cmp']) {
    await page.goto(`/${protocol}`);
    await expect(page.getByRole('heading', { name: protocol.toUpperCase(), exact: true })).toBeVisible();
    const id = `${protocol}.endpoint.list`;
    await page.getByPlaceholder('Filter operations').fill(id);
    await page.getByText(id, { exact: true }).first().click();
    await page.getByRole('spinbutton', { name: 'Offset', exact: true }).fill('0');
    await page.getByRole('spinbutton', { name: 'Limit', exact: true }).fill('20');
    const response = page.waitForResponse((r) => r.url().endsWith(`/operations/${id}`));
    await page.getByRole('button', { name: /^Run operation$/i }).click();
    expect((await response).status()).toBe(200);
    await expect(page.getByText('Succeeded', { exact: true })).toBeVisible();
  }
  await page.getByPlaceholder('Filter operations').fill('cmp.endpoint.deregister');
  await expect(page.getByRole('button', { name: /^Run operation$/i })).toHaveCount(0);
  const denied = await request.post('/admin/v1/operations/cmp.endpoint.deregister', {
    data: { version: 1, arguments: { label: 'not-authorized' } },
  });
  // The admin boundary deliberately hides operations outside discovery with 404.
  expect(denied.status()).toBe(404);
  expect(await denied.json()).toMatchObject({ status: 'FAILED', result: null,
    failure: { code: 'OPERATION_NOT_FOUND' } });
});

test('direct protocol routes fail closed when discovery excludes their operations', async ({ page }) => {
  // Model a principal with no visible operations using the real discovery envelope.
  await page.route('**/admin/v1/operations', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.result = { operations: [], count: 0 };
    await route.fulfill({ response, json: body });
  });
  for (const protocol of ['est', 'scep', 'cmp']) {
    await page.goto(`/${protocol}`);
    await expect(page.getByRole('heading', { name: protocol.toUpperCase(), exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('Filter operations')).toBeVisible();
    await expect(page.getByRole('button', { name: /^Run operation$/i })).toHaveCount(0);
  }
});

test('dashboard requests no measurements when discovery excludes metrics', async ({ page }) => {
  const metricRequests: string[] = [];
  page.on('request', (sent) => {
    if (sent.url().includes('/operations/dashboard.')) metricRequests.push(sent.url());
  });
  await page.route('**/admin/v1/operations', async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    body.result.operations = body.result.operations.filter((entry: { operation: string }) => !entry.operation.startsWith('dashboard.'));
    body.result.count = body.result.operations.length;
    await route.fulfill({ response, json: body });
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Operational metrics', exact: true })).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Metrics authority' })).toBeDisabled();
  await expect(page.getByRole('button', { name: /^Refresh .* metrics$/ })).toHaveCount(0);
  expect(metricRequests).toHaveLength(0);
});

test('enrollment requests submit once, execute after peer approval and persist across restart', async ({ page, request }) => {
  const profileId = 'browser-enrollment';
  const register = await operation(page, 'enrollment.profile.register', 'Register enrollment profile');
  await register.getByLabel('Id', { exact: true }).fill(profileId);
  await register.getByLabel('Display name', { exact: true }).fill('Browser policy');
  await choose(page, register, 'Certificate profile id', /Server TLS/);
  const created = await submitManaged(page, request, register, true);
  expect(created.complete.result).toMatchObject({ value: { id: profileId, state: 'ACTIVE' } });
  // Reusing the entity ID with a new workflow identity is refused before retaining work.
  const duplicateId = `${created.id}-duplicate`;
  const duplicate = await request.post('/admin/v1/requests', { data: { ...created.intent, requestId: duplicateId } });
  expect(duplicate.status()).toBe(400);
  expect((await request.get(`/admin/v1/requests/${encodeURIComponent(duplicateId)}`)).status()).toBe(404);

  const update = await operation(page, 'enrollment.profile.update', 'Update enrollment profile');
  await choose(page, update, 'Id', new RegExp(profileId));
  await update.getByLabel('Display name', { exact: true }).fill('Updated browser policy');
  await choose(page, update, 'Certificate profile id', /Server TLS/);
  await update.getByLabel('Subject dn pattern (optional)', { exact: true }).fill('CN=.*');
  await update.getByLabel('Required san domains (optional)', { exact: true }).fill('example.test');
  await update.getByLabel('Required san domains (optional)', { exact: true }).press('Enter');
  await update.getByLabel('Require approval (optional)', { exact: true }).check();
  await submitManaged(page, request, update);
  const denied = await request.post('/fixture/enrollment-denied', { data: { version: 1, arguments: { id: profileId } } });
  expect(denied.status()).toBeGreaterThanOrEqual(400);
  expect(denied.status()).toBeLessThan(500);
  expect(await denied.json()).toMatchObject({ status: 'FAILED', result: null });
  expect((await request.post('/fixture/restart')).status()).toBe(200);
  const inspect = await operation(page, 'enrollment.profile.inspect', 'Inspect enrollment profile');
  await choose(page, inspect, 'Id', new RegExp(profileId));
  const inspected = page.waitForResponse(response => response.url().endsWith('/operations/enrollment.profile.inspect'));
  await inspect.getByRole('button', { name: 'Run operation', exact: true }).click();
  expect((await (await inspected).json() as Envelope).result).toMatchObject({ value: {
    id: profileId, displayName: 'Updated browser policy', state: 'ACTIVE', certificateProfileId: 'server-tls',
    subjectDnPattern: 'CN=.*', requiredSanDomains: ['example.test'], requireApproval: true,
  } });
});

test('enrollment direct route exposes no actions without successful discovery', async ({ page }) => {
  for (const unavailable of [false, true]) {
    await page.route('**/admin/v1/operations', async (route) => {
      if (unavailable) { await route.abort('failed'); return; }
      const response = await route.fetch();
      const body = await response.json();
      body.result = { operations: [], count: 0 };
      await route.fulfill({ response, json: body });
    });
    await page.goto('/enrollment');
    await expect(page.getByRole('heading', { name: 'Enrollment Profiles', exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('Filter operations')).toBeVisible();
    await expect(page.getByRole('button', { name: /^Run operation$/i })).toHaveCount(0);
    await page.unroute('**/admin/v1/operations');
  }
});

// One sequential scenario owns its newly created authorities and approvals.
// The second identity uses direct mTLS; the packaged deployment suite verifies browser certificate forwarding.
test('real selectors, bound dual-control approval, CA proof and receipt recheck', async ({ page, request }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await expect(page.getByText(/Demo mode/i)).toHaveCount(0);
  const root = await operation(page, 'ca.create', 'Create root authority');
  await choose(page, root, 'Certificate format', /X.509/);
  await root.getByLabel(/distinguished name$/i).fill('CN=Browser Root');
  await choose(page, root, 'Certificate profile', /Root CA/);
  await choose(page, root, 'Signing key', /fixture:root.prv/);
  let submissions = 0;
  let directTargets = 0;
  page.on('request', sent => {
    if (sent.method() === 'POST' && sent.url().endsWith('/admin/v1/requests')) submissions++;
    if (sent.method() === 'POST' && sent.url().endsWith('/operations/ca.create')) directTargets++;
  });
  const rootRequest = await submitManaged(page, request, root, true);
  const operationId = String(rootRequest.complete.signingOperationId);
  expect(operationId).not.toBe('undefined');
  const proof = await request.get(`/admin/v1/signing-operations/${encodeURIComponent(operationId)}`);
  const completed = await proof.json() as Envelope;
  expect(completed.status).toBe('SUCCEEDED');
  expect(completed.result).toMatchObject({ operationId, kind: 'CA', encoding: 'DER' });
  expect(completed.result?.resultSha256).toMatch(/^[0-9a-f]{64}$/);
  // Reload observes the retained intent; it never replays target creation.
  await page.reload();
  await expect(page.getByText('Operation completed.', { exact: true })).toBeVisible();
  expect(submissions).toBe(1);
  expect(directTargets).toBe(0);
  await verifyCertificateAttachments(page, 'CN=Browser Root');

  const issue = await operation(page, 'credential.issue', 'Issue credential');
  await choose(page, issue, 'Issuing authority', /Authority · Root · Active/);
  await choose(page, issue, 'Certificate request', /certificate request/i);
  await choose(page, issue, 'Certificate profile', /Server TLS/);
  await submitManaged(page, request, issue);

  const search = await operation(page, 'credential.search', 'Browse certificates');
  await choose(page, search, 'Authority', /Authority · Root · Active/);
  await search.getByLabel('Limit', { exact: true }).fill('20');
  await search.getByLabel('Subject alternative name (optional)', { exact: true }).fill('DNS_NAME:BROWSER.EXAMPLE.TEST');
  await expect(search.getByLabel('Credential ID prefix (optional)', { exact: true })).toBeVisible();
  const searched = page.waitForResponse((response) => response.url().endsWith('/operations/credential.search'));
  await search.getByRole('button', { name: /^Run operation$/i }).click();
  const searchResponse = await searched;
  expect(searchResponse.status()).toBe(200);
  const searchResult = await searchResponse.json() as Envelope;
  expect(searchResult.result?.count).toBe(1);
  const found = (searchResult.result?.credentials as Record<string, unknown>[])[0]!;
  const searchArguments = searchResponse.request().postDataJSON() as OperationRequest;
  const prefix = String(found.credentialId).slice(0, 12);
  await search.getByLabel('Credential ID prefix (optional)', { exact: true }).fill(prefix);
  const filtered = page.waitForResponse((response) => response.url().endsWith('/operations/credential.search'));
  await search.getByRole('button', { name: /^Run operation$/i }).click();
  expect((await (await filtered).json() as Envelope).result?.count).toBe(1);
  expect((await request.post('/fixture/restart')).status()).toBe(200);
  const recovered = await request.post('/admin/v1/operations/credential.search', { data: searchArguments });
  expect(recovered.status()).toBe(200);
  expect((await recovered.json() as Envelope).result?.credentials).toEqual(searchResult.result?.credentials);

  // Render current measurements from the real backend for exactly the chosen CA.
  const serverSnapshot = page.waitForResponse((response) => response.url().endsWith('/operations/dashboard.server'));
  await page.goto('/');
  expect((await serverSnapshot).status()).toBe(200);
  const metricIds = ['authority', 'certificate', 'revocation', 'publication'];
  const authoritySnapshots = metricIds.map((id) => page.waitForResponse((response) => response.url().endsWith(`/operations/dashboard.${id}`)));
  await choose(page, page.getByRole('main'), 'Metrics authority', /Authority · Root · Active/);
  for (const snapshot of authoritySnapshots) {
    const response = await snapshot;
    expect(response.status()).toBe(200);
    const result = await response.json() as Envelope;
    expect(result.status).toBe('SUCCEEDED');
    expect(result.result?.caId).toBe(searchArguments.authorityId);
  }
  const certificateMetrics = page.getByRole('region', { name: 'Certificate metrics', exact: true });
  await expect(certificateMetrics.getByRole('meter', { name: 'Certificates counted' })).toHaveAttribute('value', '2');
  await expect(certificateMetrics.getByText('Unavailable', { exact: true })).toBeVisible();
  await expect(certificateMetrics.getByText(/Expiration windows are cumulative/)).toBeVisible();
  await expect(page.getByRole('region', { name: 'Revocation metrics' }).getByText('Unavailable', { exact: true })).toHaveCount(4);

  const intermediate = await operation(page, 'ca.intermediate.create', 'Create intermediate CA');
  await choose(page, intermediate, 'Certificate format', /X.509/);
  await choose(page, intermediate, 'Issuing authority', /Authority · Root · Active/);
  await intermediate.getByLabel(/distinguished name$/i).fill('CN=Browser Intermediate');
  await choose(page, intermediate, 'Certificate profile', /Intermediate CA/);
  await choose(page, intermediate, 'Signing key (optional)', /fixture:intermediate.prv/);
  const intermediateRequest = await submitManaged(page, request, intermediate, true);
  const intermediateId = String(intermediateRequest.complete.signingOperationId);
  const proofResponse = await request.get(`/admin/v1/signing-operations/${encodeURIComponent(intermediateId)}`);
  const proofResult = await proofResponse.json() as Envelope;
  expect(proofResult.status).toBe('SUCCEEDED');
  expect(proofResult.result).toMatchObject({ operationId: intermediateId, kind: 'CA', encoding: 'DER' });
  expect(proofResult.result?.resultSha256).toMatch(/^[0-9a-f]{64}$/);
  // Exercise the newly generated status-transition forms against the same real authority.
  let heldCredential: unknown;
  for (const [id, title, state] of [
    ['credential.hold', 'Hold credential', 'HELD'],
    ['credential.unhold', 'Release credential hold', 'CLEAR'],
  ] as const) {
    await page.goto('/revocation');
    await page.getByPlaceholder('Filter operations').fill(id);
    await page.getByText(id, { exact: true }).first().click();
    const form = runner(page, title);
    await choose(page, form, 'Authority', /Authority · Root · Active/);
    await form.getByLabel('Certificate', { exact: true }).click();
    await page.getByRole('option').first().click();
    const completed = await submitManaged(page, request, form);
    const result = completed.complete.result as Record<string, unknown>;
    expect(result.state).toBe(state);
    if (id === 'credential.hold') heldCredential = result.credentialId;
    else expect(result.credentialId).toBe(heldCredential);
  }
});
