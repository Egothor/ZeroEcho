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

import { test, expect, type Page } from '@playwright/test';

/**
 * Browser-to-UI end-to-end coverage in demo mode (in-browser mock backend).
 * Exercises navigation, an operation execution with a rendered result, the
 * approval flow for a HIGH_RISK operation, and persona switching (negative
 * authorization / discoverability).
 */

async function openDemo(page: Page) {
  await page.goto('/?demo=1');
  await expect(page.getByText(/Demo mode/i)).toBeVisible();
}

function nav(page: Page) {
  return page.getByRole('navigation', { name: 'Primary' });
}

test('dashboard renders with the demo banner and realm heading', async ({ page }) => {
  await openDemo(page);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'ZeroEcho Demo Realm' })).toBeVisible();
});

test('authorities screen auto-loads an entity table', async ({ page }) => {
  await openDemo(page);
  await nav(page).getByRole('link', { name: 'Certificate Authorities' }).click();
  // The screen loads the authorities table on its own (no manual operation run).
  await expect(page.getByRole('grid')).toBeVisible();
  await expect(page.getByText('ZeroEcho Root CA', { exact: false })).toBeVisible();
});

test('HIGH_RISK create (via Create menu) surfaces the approval-required flow', async ({ page }) => {
  await openDemo(page);
  await nav(page).getByRole('link', { name: 'Certificate Authorities' }).click();
  await page.getByRole('button', { name: 'Create' }).click();
  await page.getByRole('menuitem', { name: 'Create root authority' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('formatId').fill('x509-v3');
  await dialog.getByLabel('subjectRef').fill('CN=New Root');
  await dialog.getByLabel('profileId').fill('root-ca-v1');
  await dialog.getByLabel('keyRef').fill('key-1');
  await dialog.getByRole('button', { name: /Run operation/i }).click();
  await expect(dialog.getByText('Approval required')).toBeVisible();
});

test('grants are presented as a table with per-row actions (multi-entity tabs)', async ({ page }) => {
  await openDemo(page);
  await nav(page).getByRole('link', { name: 'Roles & Grants' }).click();
  await expect(page.getByRole('tab', { name: 'Grants' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Role assignments' })).toBeVisible();
  await expect(page.getByRole('grid')).toBeVisible();
  // A seeded grant is listed, so the operator picks it from the list — not from memory.
  await expect(page.getByText('g-01', { exact: false })).toBeVisible();
});

test('parameterised listing (Status & CRLs) loads a table after a filter is set', async ({ page }) => {
  await openDemo(page);
  await nav(page).getByRole('link', { name: 'Status & CRLs' }).click();
  // The listing needs an issuer; a filter bar is shown before the table loads.
  await page.getByLabel('issuerCaId').fill('ca-tls-issuing-01');
  await page.getByRole('button', { name: /^(Load|Apply)$/ }).click();
  await expect(page.getByRole('grid')).toBeVisible();
  await expect(page.getByText('crl-tls-014', { exact: false })).toBeVisible();
});

test('persona switch changes the discoverable operation catalog', async ({ page }) => {
  await openDemo(page);
  await page.getByLabel('Demo persona').click();
  await page.getByRole('option', { name: 'Ordinary user' }).click();
  await expect(page.getByText(/Acting as/)).toContainText('Ordinary user');

  await nav(page).getByRole('link', { name: 'Operations Explorer' }).click();
  // An ordinary user may submit/inspect requests...
  await expect(page.getByText('request.import', { exact: true }).first()).toBeVisible();
  // ...but privileged operations are hidden entirely (not merely disabled).
  await expect(page.getByText('ca.create', { exact: true })).toHaveCount(0);
  // Privileged nav areas disappear too.
  await expect(nav(page).getByRole('link', { name: 'Principals' })).toHaveCount(0);
});
