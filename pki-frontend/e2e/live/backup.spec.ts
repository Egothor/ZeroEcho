/*
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
 */

import { test, expect } from '@playwright/test';
import { stat } from 'node:fs/promises';

test('large backup download, local verification, approval and cold activation', async ({ page, request }) => {
  await page.goto('/backup');
  await expect(page.getByRole('button', { name: 'Create backup', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Create backup', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Download archive once' })).toBeEnabled();
  const downloading = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download archive once' }).click();
  const downloaded = await downloading;
  const path = await downloaded.path();
  expect(path).not.toBeNull();
  expect((await stat(path!)).size).toBeGreaterThan(4 * 1024 * 1024);
  await page.getByLabel('Backup archive').setInputFiles(path!);
  await page.getByRole('button', { name: 'Check file and reserve upload' }).click();
  await expect(page.getByRole('button', { name: 'Upload archive', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Upload archive', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Verify uploaded archive' })).toBeEnabled();
  await page.getByRole('button', { name: 'Verify uploaded archive' }).click();
  await expect(page.getByRole('button', { name: 'Stage restore' })).toBeEnabled();
  await page.getByRole('button', { name: 'Stage restore' }).click();
  await expect(page.getByRole('status')).toContainText('Approval is required');
  await page.getByRole('button', { name: 'Request approval', exact: true }).click();
  await expect(page.getByRole('status')).toContainText('Approval requested');
  const approvalId = await page.getByLabel('Approval identifier', { exact: true }).inputValue();
  const approved = await request.post('/fixture/approve', {
    data: { version: 1, arguments: { approvalId, justification: 'Independent backup fixture approval' } },
  });
  expect(approved.status()).toBe(200);
  await page.getByRole('button', { name: 'Stage restore' }).click();
  await expect(page.getByRole('status')).toContainText('Restore staged');
  const workflow = await page.getByLabel('Restore workflow identifier').inputValue();
  expect(workflow).toMatch(/^[0-9a-f]{64}$/);
  const restarted = await request.post('/fixture/restart');
  expect(restarted.status()).toBe(200);
  await page.getByRole('button', { name: 'Inspect restore outcome' }).click();
  await expect(page.getByRole('status')).toContainText('Restore activated successfully after restart');
  await page.getByRole('button', { name: 'Acknowledge outcome' }).click();
  await expect(page.getByRole('status')).toContainText('Restore outcome acknowledged');
  // The restarted configuration has no protocol listeners. Unlike the initial
  // test service installation, this proves actual runtime unavailability.
  for (const protocol of ['est', 'scep', 'cmp']) {
    const discovery = page.waitForResponse((r) => r.url().endsWith('/admin/v1/operations'));
    await page.goto(`/${protocol}`);
    const catalog = await (await discovery).json();
    expect(catalog.result.operations.some((entry: { operation: string }) =>
      entry.operation.startsWith(`${protocol}.`))).toBe(false);
    await expect(page.getByRole('heading', { name: protocol.toUpperCase(), exact: true })).toBeVisible();
    await expect(page.getByPlaceholder('Filter operations')).toBeVisible();
    await expect(page.getByRole('button', { name: /^Run operation$/i })).toHaveCount(0);
  }
});
