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
import { test, expect, request as requests, type Page, type Locator } from '@playwright/test';
import { join } from 'node:path';

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
    await root.getByLabel(/distinguished name$/i).fill('CN=Packaged Browser Root');
    await choose(page, root, 'Certificate profile', /Root CA/);
    await choose(page, root, 'Signing key', /fixture:root.prv/);
    let submissions = 0;
    let directCommands = 0;
    page.on('request', sent => {
      if (sent.method() === 'POST' && sent.url().endsWith('/admin/v1/requests')) submissions++;
      if (sent.method() === 'POST' && sent.url().endsWith('/operations/ca.create')) directCommands++;
    });
    const accepted = page.waitForResponse(response => response.url().endsWith('/admin/v1/requests') && response.status() === 202);
    await root.getByRole('button', { name: 'Submit request', exact: true }).click();
    const response = await accepted;
    const intent = response.request().postDataJSON() as OperationRequest;
    expect(intent.arguments.subjectRef).toBe('CN=Packaged Browser Root');
    const projection = (await response.json() as Envelope).result!;
    const id = String(projection.requestId);
    const approvalId = String(projection.approvalId);
    expect(id).not.toBe('undefined');
    expect(approvalId).not.toBe('undefined');
    await expect(page).toHaveURL(new RegExp(`/administrative-requests/${id}$`));
    const decision = { version: 1, arguments: { approvalId, justification: 'Independent packaged browser approval' } };
    const self = await request.post('/admin/v1/operations/security.approval.approve', { data: decision });
    expect(self.status()).toBeGreaterThanOrEqual(400);
    expect(self.status()).toBeLessThan(500);
    const approved = await approver.post('/admin/v1/operations/security.approval.approve', { data: decision });
    expect(approved.status()).toBe(200);
    expect((await approved.json() as Envelope).status).toBe('SUCCEEDED');
    // Browser closure cannot prevent dispatch: the independent server owns the request.
    await page.reload();
    await expect(page.getByText('SUCCEEDED', { exact: true }).first()).toBeVisible({ timeout: 30000 });
    expect(submissions).toBe(1);
    expect(directCommands).toBe(0);
    await verifyCertificateAttachments(page, 'CN=Packaged Browser Root');

    const issue = await operation(page, 'credential.issue', 'Issue credential');
    await choose(page, issue, 'Issuing authority', /Authority · Root · Active/);
    await choose(page, issue, 'Certificate request', /certificate request/i);
    await choose(page, issue, 'Certificate profile', /Server TLS/);
  } finally {
    await approver.dispose();
  }
});
