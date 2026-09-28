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

import { test, expect, request as requests, type Page, type Locator } from '@playwright/test';
import { join } from 'node:path';

type Envelope = { status: string; result: Record<string, unknown> | null };
type OperationRequest = { version: number; arguments: Record<string, unknown>; authorityId?: string };

function runner(page: Page, title: string): Locator {
  return page.getByRole('heading', { name: title, exact: true })
    .locator('xpath=ancestor::div[contains(@class,"MuiPaper-root")][1]');
}
async function choose(page: Page, form: Locator, label: string, value: RegExp) {
  await form.getByLabel(label, { exact: true }).click();
  await page.getByRole('option', { name: value }).first().click();
}
async function operation(page: Page, id: string, title: string) {
  await page.goto('/operations');
  await page.getByPlaceholder('Filter operations').fill(id);
  await page.getByText(id, { exact: true }).first().click();
  return runner(page, title);
}

// Both identities authenticate at nginx with actual client certificates. No bridge or
// test backend route participates in authentication, authorization or approval.
test('packaged SPA uses mTLS identities, known choices and a retained asynchronous receipt', async ({ page, request }) => {
  const baseURL = process.env.E2E_PACKAGED_BASE_URL!;
  const tls = process.env.E2E_PACKAGED_TLS!;
  const approver = await requests.newContext({
    baseURL, ignoreHTTPSErrors: false,
    clientCertificates: [{ origin: baseURL, certPath: join(tls, 'approver.crt'), keyPath: join(tls, 'approver.key') }],
  });
  try {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    await expect(page.getByText(/Demo mode/i)).toHaveCount(0);
    const root = await operation(page, 'ca.create', 'Create root authority');
    await choose(page, root, 'Certificate format', /X.509/);
    await root.getByLabel('Subject', { exact: true }).fill('CN=Packaged Browser Root');
    await choose(page, root, 'Certificate profile', /Root CA/);
    await choose(page, root, 'Signing key', /fixture:root.prv/);
    const required = page.waitForResponse((r) => r.url().endsWith('/operations/ca.create') && r.status() === 409);
    await root.getByRole('button', { name: /^Run operation$/i }).first().click();
    const originalBody = (await required).request().postDataJSON() as OperationRequest;
    await expect(root.getByText('Approval required', { exact: true })).toBeVisible();
    await root.getByRole('button', { name: 'Prepare approval request' }).click();
    const approval = runner(page, 'Request approval');
    await approval.getByRole('textbox', { name: 'Approval', exact: true }).fill('packaged-browser-root');
    const requested = page.waitForResponse((r) => r.url().endsWith('/operations/security.approval.request'));
    await approval.getByRole('button', { name: /^Run operation$/i }).last().click();
    const response = await requested;
    expect(response.status()).toBe(200);
    expect((response.request().postDataJSON() as OperationRequest).arguments.targetArguments).toEqual(originalBody.arguments);
    const decision = { version: 1, arguments: { approvalId: 'packaged-browser-root', justification: 'Independent packaged browser approval' } };
    const self = await request.post('/admin/v1/operations/security.approval.approve', { data: decision });
    expect(self.status()).toBeGreaterThanOrEqual(400);
    expect(self.status()).toBeLessThan(500);
    const approved = await approver.post('/admin/v1/operations/security.approval.approve', { data: decision });
    expect(approved.status()).toBe(200);
    expect((await approved.json() as Envelope).status).toBe('SUCCEEDED');
    await root.getByText('Advanced (approval, deadline)', { exact: true }).first().click();
    await choose(page, root.locator('form').first(), 'Approval (optional)', /packaged-browser-root/);

    let submissions = 0;
    const inspected: string[] = [];
    page.on('request', (sent) => {
      if (sent.method() === 'POST' && sent.url().endsWith('/operations/ca.create')) submissions++;
      if (sent.method() === 'GET' && sent.url().includes('/signing-operations/')) inspected.push(sent.url());
    });
    // Client-side observation failure cannot undo acceptance or trigger another POST.
    await page.route('**/admin/v1/signing-operations/*', (route) => route.abort('failed'), { times: 1 });
    const accepted = page.waitForResponse((r) => r.url().endsWith('/operations/ca.create'));
    await root.getByRole('button', { name: /^Run operation$/i }).first().click();
    const acceptedResponse = await accepted;
    expect(acceptedResponse.status()).toBe(202);
    const id = String((await acceptedResponse.json() as Envelope).result?.operationId);
    expect(id).not.toBe('undefined');
    await expect(root.getByText(`Operation: ${id}`, { exact: true })).toBeVisible();
    await expect(root.getByText('Pending', { exact: true })).toBeVisible();
    await root.getByRole('button', { name: 'Check status', exact: true }).click();
    await expect(root.getByText('Succeeded', { exact: true })).toBeVisible();
    expect(submissions).toBe(1);
    expect(inspected.length).toBeGreaterThanOrEqual(2);
    expect(new Set(inspected)).toEqual(new Set([`${baseURL}/admin/v1/signing-operations/${encodeURIComponent(id)}`]));

    const issue = await operation(page, 'credential.issue', 'Issue credential');
    await choose(page, issue, 'Issuing authority', /Authority · Root · Active/);
    await choose(page, issue, 'Certificate request', /certificate request/i);
    await choose(page, issue, 'Certificate profile', /Server TLS/);
  } finally {
    await approver.dispose();
  }
});
