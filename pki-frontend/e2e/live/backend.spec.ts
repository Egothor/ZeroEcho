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
});
