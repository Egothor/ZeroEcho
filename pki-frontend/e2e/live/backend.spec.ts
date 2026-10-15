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

import { test, expect, type Page, type Locator, type APIRequestContext, type Route } from '@playwright/test';

type Envelope = { status: string; result: Record<string, unknown> | null };
type OperationRequest = { version: number; arguments: Record<string, unknown>; authorityId?: string };

function runner(page: Page, title: string): Locator {
  return page.getByRole('heading', { name: title, exact: true })
    .locator('xpath=ancestor::div[contains(@class,"MuiPaper-root")][1]');
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
async function requestApproval(page: Page, request: APIRequestContext, form: Locator, id: string) {
  const requiredResponse = page.waitForResponse((response) => response.status() === 409);
  await form.getByRole('button', { name: /^Run operation$/i }).first().click();
  const original = (await requiredResponse).request();
  const originalBody = original.postDataJSON() as OperationRequest;
  await expect(form.getByText('Approval required', { exact: true })).toBeVisible();
  await form.getByRole('button', { name: 'Prepare approval request' }).click();
  const approval = runner(page, 'Request approval');
  await approval.getByRole('textbox', { name: 'Approval', exact: true }).fill(id);
  await expect(approval.getByText('Target arguments prepared. You can now request approval.')).toBeVisible();
  const response = page.waitForResponse((r) => r.url().endsWith('/operations/security.approval.request'));
  await approval.getByRole('button', { name: /^Run operation$/i }).last().click();
  const approvalResponse = await response;
  expect(approvalResponse.status()).toBe(200);
  const approvalBody = approvalResponse.request().postDataJSON() as OperationRequest;
  expect(approvalBody.arguments.targetOperation).toBe(original.url().split('/').at(-1));
  expect(approvalBody.arguments.targetArguments).toEqual(originalBody.arguments);
  if (originalBody.authorityId) expect(approvalBody.arguments.targetAuthorityId).toBe(originalBody.authorityId);
  await expect(approval.getByText('Succeeded', { exact: true })).toBeVisible();
  const selfApproval = await request.post('/admin/v1/operations/security.approval.approve', {
    data: { version: 1, ...(originalBody.authorityId ? { authorityId: originalBody.authorityId } : {}),
      arguments: { approvalId: id, justification: 'Requester cannot self approve' } },
  });
  expect(selfApproval.status()).toBeGreaterThanOrEqual(400);
  expect(selfApproval.status()).toBeLessThan(500);
  expect((await selfApproval.json() as Envelope).status).toBe('FAILED');
  await approve(request, id, originalBody.authorityId);
  const changedTarget = await request.post(original.url(), {
    data: { ...originalBody, approvalId: id,
      arguments: { ...originalBody.arguments, subjectRef: 'CN=Different Unapproved Subject' } },
  });
  // The existing gateway maps a mismatched approval claim to a safe internal failure.
  // It must reject without consuming the approval; the unchanged UI request executes below.
  expect(changedTarget.status()).toBe(500);
  expect(await changedTarget.json()).toMatchObject({ status: 'FAILED', result: null,
    failure: { classification: 'INTERNAL_FAILURE', code: 'SAFE_INTERNAL_FAILURE',
      recoveryRequired: false, reconciliationRequired: false },
  });
  await form.getByText('Advanced (approval, deadline)', { exact: true }).first().click();
  await choose(page, form.locator('form').first(), 'Approval (optional)', new RegExp(id));
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

test('enrollment profiles use real approval, forms, persistence and authorization', async ({ page, request }) => {
  const profileId = 'browser-enrollment';
  async function select(id: string, title: string) {
    await page.goto('/enrollment');
    await expect(page.getByRole('heading', { name: 'Enrollment Profiles', exact: true })).toBeVisible();
    await page.getByPlaceholder('Filter operations').fill(`enrollment.profile.${id}`);
    await page.getByText(`enrollment.profile.${id}`, { exact: true }).first().click();
    return runner(page, title);
  }
  async function run(form: Locator, id: string) {
    const response = page.waitForResponse((r) => r.url().endsWith(`/operations/enrollment.profile.${id}`));
    await form.getByRole('button', { name: /^Run operation$/i }).first().click();
    const received = await response;
    expect(received.status()).toBe(200);
    await expect(form.getByText('Succeeded', { exact: true })).toBeVisible();
    return await received.json() as Envelope;
  }
  async function inspect(state: string) {
    const form = await select('inspect', 'Inspect enrollment profile');
    await choose(page, form, 'Id', new RegExp(profileId));
    expect((await run(form, 'inspect')).result).toMatchObject({ value: {
      id: profileId, displayName: 'Updated browser policy', state, certificateProfileId: 'server-tls',
      subjectDnPattern: 'CN=.*', requiredSanDomains: ['example.test'], requireApproval: true,
    } });
  }
  await page.goto('/');
  await page.getByRole('link', { name: 'Enrollment Profiles', exact: true }).first().click();
  await expect(page).toHaveURL(/\/enrollment$/);
  const register = await select('register', 'Register enrollment profile');
  await register.getByLabel('Id', { exact: true }).fill(profileId);
  await register.getByLabel('Display name', { exact: true }).fill('Browser policy');
  await choose(page, register, 'Certificate profile id', /Server TLS/);
  const required = page.waitForResponse((r) => r.url().endsWith('/operations/enrollment.profile.register'));
  await register.getByRole('button', { name: /^Run operation$/i }).first().click();
  expect((await required).status()).toBe(409);
  await register.getByRole('button', { name: 'Prepare approval request' }).click();
  const approval = runner(page, 'Request approval');
  await approval.getByRole('textbox', { name: 'Approval', exact: true }).fill('browser-enrollment-approval');
  await expect(approval.getByText('Target arguments prepared. You can now request approval.')).toBeVisible();
  const requested = page.waitForResponse((r) => r.url().endsWith('/operations/security.approval.request'));
  await approval.getByRole('button', { name: /^Run operation$/i }).last().click();
  expect((await requested).status()).toBe(200);
  await approve(request, 'browser-enrollment-approval');
  await register.getByText('Advanced (approval, deadline)', { exact: true }).first().click();
  await choose(page, register.locator('form').first(), 'Approval (optional)', /browser-enrollment-approval/);
  expect((await run(register, 'register')).result).toMatchObject({ value: { id: profileId, state: 'ACTIVE' } });

  const update = await select('update', 'Update enrollment profile');
  await choose(page, update, 'Id', new RegExp(profileId));
  await update.getByLabel('Display name', { exact: true }).fill('Updated browser policy');
  await choose(page, update, 'Certificate profile id', /Server TLS/);
  await update.getByLabel('Subject dn pattern (optional)', { exact: true }).fill('(?=unsupported)');
  const invalid = page.waitForResponse((r) => r.url().endsWith('/operations/enrollment.profile.update'));
  await update.getByRole('button', { name: /^Run operation$/i }).click();
  expect((await invalid).status()).toBeGreaterThanOrEqual(400);
  await expect(update.getByText(/^Failed:/)).toBeVisible();
  await update.getByLabel('Subject dn pattern (optional)', { exact: true }).fill('CN=.*');
  await update.getByLabel('Required san domains (optional)', { exact: true }).fill('example.test');
  await update.getByLabel('Required san domains (optional)', { exact: true }).press('Enter');
  await update.getByLabel('Require approval (optional)', { exact: true }).check();
  await run(update, 'update');
  await page.reload();
  await inspect('ACTIVE');
  for (const [id, title, state] of [
    ['suspend', 'Suspend enrollment profile', 'SUSPENDED'],
    ['activate', 'Activate enrollment profile', 'ACTIVE'],
  ] as const) {
    const form = await select(id, title);
    await choose(page, form, 'Id', new RegExp(profileId));
    expect((await run(form, id)).result).toMatchObject({ value: { state } });
  }
  const denied = await request.post('/fixture/enrollment-denied', { data: { version: 1, arguments: { id: profileId } } });
  expect(denied.status()).toBeGreaterThanOrEqual(400);
  expect(denied.status()).toBeLessThan(500);
  expect(await denied.json()).toMatchObject({ status: 'FAILED', result: null });
  await inspect('ACTIVE');
  expect((await request.post('/fixture/restart')).status()).toBe(200);
  await inspect('ACTIVE');
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
  await root.getByLabel('Subject', { exact: true }).fill('CN=Browser Root');
  await choose(page, root, 'Certificate profile', /Root CA/);
  await choose(page, root, 'Signing key', /fixture:root.prv/);
  await requestApproval(page, request, root, 'browser-root');

  let submissions = 0;
  const statusIds: string[] = [];
  page.on('request', (sent) => {
    if (sent.method() === 'POST' && sent.url().endsWith('/operations/ca.create')) submissions++;
    if (sent.method() === 'GET' && sent.url().includes('/signing-operations/')) statusIds.push(sent.url());
  });
  // Abort only the first observation; the backend still accepts and completes the actual operation.
  await page.route('**/admin/v1/signing-operations/*', (route) => route.abort('failed'), { times: 1 });
  const acceptedPromise = page.waitForResponse((response) => response.url().endsWith('/operations/ca.create'));
  await root.getByRole('button', { name: /^Run operation$/i }).first().click();
  const accepted = await acceptedPromise;
  expect(accepted.status()).toBe(202);
  const receipt = await accepted.json() as Envelope;
  const operationId = String(receipt.result?.operationId);
  expect(operationId).not.toBe('undefined');
  await expect(root.getByText('Pending', { exact: true })).toBeVisible();
  await expect(root.getByText(`Operation: ${operationId}`, { exact: true })).toBeVisible();
  const completedPromise = page.waitForResponse((response) => response.url().includes('/signing-operations/') && response.status() === 200);
  await root.getByRole('button', { name: 'Check status', exact: true }).click();
  const completed = await (await completedPromise).json() as Envelope;
  expect(completed.status).toBe('SUCCEEDED');
  expect(completed.result).toMatchObject({ operationId, kind: 'CA', encoding: 'DER' });
  expect(completed.result?.resultSha256).toMatch(/^[0-9a-f]{64}$/);
  await expect(root.getByText('Succeeded', { exact: true })).toBeVisible();
  expect(submissions).toBe(1);
  expect(statusIds.length).toBeGreaterThanOrEqual(2);
  expect(new Set(statusIds).size).toBe(1);

  const issue = await operation(page, 'credential.issue', 'Issue credential');
  await choose(page, issue, 'Issuing authority', /Authority · Root · Active/);
  await choose(page, issue, 'Certificate request', /certificate request/i);
  await choose(page, issue, 'Certificate profile', /Server TLS/);
  const issued = page.waitForResponse((response) => response.url().endsWith('/operations/credential.issue'));
  await issue.getByRole('button', { name: /^Run operation$/i }).click();
  expect((await issued).status()).toBe(202);
  await expect(issue.getByText('Succeeded', { exact: true })).toBeVisible();

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
  await intermediate.getByLabel('Subject', { exact: true }).fill('CN=Browser Intermediate');
  await choose(page, intermediate, 'Certificate profile', /Intermediate CA/);
  await choose(page, intermediate, 'Signing key (optional)', /fixture:intermediate.prv/);
  await requestApproval(page, request, intermediate, 'browser-intermediate');
  let intermediateSubmissions = 0;
  const intermediateChecks: string[] = [];
  page.on('request', (sent) => {
    if (sent.method() === 'POST' && sent.url().endsWith('/operations/ca.intermediate.create')) intermediateSubmissions++;
    if (sent.method() === 'GET' && sent.url().includes('/signing-operations/')) intermediateChecks.push(sent.url());
  });
  await page.clock.install();
  let observe: (route: Route) => void = () => { throw new Error('Observation not initialized'); };
  const observation = new Promise<Route>((resolve) => { observe = resolve; });
  await page.route('**/admin/v1/signing-operations/*', (route) => { observe(route); }, { times: 1 });
  const intermediateAccepted = page.waitForResponse((response) => response.url().endsWith('/operations/ca.intermediate.create'));
  await intermediate.getByRole('button', { name: /^Run operation$/i }).first().click();
  const acceptance = await intermediateAccepted;
  expect(acceptance.status()).toBe(202);
  const intermediateId = String((await acceptance.json() as Envelope).result?.operationId);
  const stalledObservation = await observation;
  // Advance only the browser wait budget; the real backend clock and operation continue normally.
  await page.clock.fastForward(31_000);
  await expect(intermediate.getByText('The local wait budget elapsed while checking the operation.')).toBeVisible();
  await expect(intermediate.getByText(`Operation: ${intermediateId}`, { exact: true })).toBeVisible();
  await stalledObservation.abort('timedout');
  const proofCompletion = page.waitForResponse((response) => response.url().includes('/signing-operations/') && response.status() === 200);
  await intermediate.getByRole('button', { name: 'Check status', exact: true }).click();
  const proofResult = await (await proofCompletion).json() as Envelope;
  expect(proofResult.status).toBe('SUCCEEDED');
  expect(proofResult.result).toMatchObject({ operationId: intermediateId, kind: 'CA', encoding: 'DER' });
  expect(proofResult.result?.resultSha256).toMatch(/^[0-9a-f]{64}$/);
  expect(intermediateSubmissions).toBe(1);
  expect(intermediateChecks.length).toBeGreaterThanOrEqual(2);
  expect(new Set(intermediateChecks).size).toBe(1);
  await expect(intermediate.getByText('Succeeded', { exact: true })).toBeVisible();
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
    const response = page.waitForResponse((r) => r.url().endsWith(`/operations/${id}`));
    await form.getByRole('button', { name: /^Run operation$/i }).click();
    const result = await response;
    expect(result.status()).toBe(200);
    const body = await result.json() as Envelope;
    expect(body.status).toBe('SUCCEEDED');
    expect(body.result?.state).toBe(state);
    if (id === 'credential.hold') heldCredential = body.result?.credentialId;
    else expect(body.result?.credentialId).toBe(heldCredential);
    await expect(form.getByText('Succeeded', { exact: true })).toBeVisible();
  }
});
