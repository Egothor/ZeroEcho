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

import { defineConfig, devices } from '@playwright/test';
import { join } from 'node:path';

const baseURL = process.env.E2E_PACKAGED_BASE_URL;
const tls = process.env.E2E_PACKAGED_TLS;
const spki = process.env.E2E_EDGE_SPKI;
const output = process.env.E2E_PACKAGED_OUTPUT;
if (!baseURL || !tls || !spki || !output) {
  throw new Error('Run :pki-server:packagedIntegrationTest to own the packaged deployment fixture.');
}

export default defineConfig({
  testDir: './e2e/packaged',
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  outputDir: join(output, 'results'),
  reporter: [['list'], ['html', { outputFolder: join(output, 'report'), open: 'never' }]],
  use: {
    ...devices['Desktop Chrome'], baseURL, ignoreHTTPSErrors: false, actionTimeout: 15_000,
    clientCertificates: [{ origin: baseURL, certPath: join(tls, 'administrator.crt'), keyPath: join(tls, 'administrator.key') }],
    launchOptions: {
      ...(process.env.E2E_BROWSER_EXECUTABLE ? { executablePath: process.env.E2E_BROWSER_EXECUTABLE } : {}),
      // Trust only this invocation's ephemeral edge key. The OS trust database is untouched;
      // curl, the CLI and Playwright API requests validate the fixture CA and hostname normally.
      args: [`--ignore-certificate-errors-spki-list=${spki}`],
    },
    trace: 'retain-on-failure',
  },
});
