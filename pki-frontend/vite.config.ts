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

import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// The SPA is served by nginx at the deployment edge under the site root. All
// admin API calls go to same-origin `/admin/...`, `/public/...`, `/health/...`
// paths, which nginx reverse-proxies to pki-server over mTLS. In dev, a proxy
// target may be supplied via VITE_DEV_API_TARGET.
const devApiTarget = process.env.VITE_DEV_API_TARGET ?? 'https://localhost:8443';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      '@generated': fileURLToPath(new URL('../pki-server/build/generated/schema', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    // Deterministic, cache-bustable, self-hosted assets (no CDN).
    assetsDir: 'assets',
    sourcemap: true,
    target: 'es2022',
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\\/](?:react|react-dom|react-router|react-router-dom)[\\/]/ },
            { name: 'mui', test: /node_modules[\\/]@mui[\\/](?:material|icons-material)[\\/]/ },
            { name: 'datagrid', test: /node_modules[\\/]@mui[\\/]x-data-grid[\\/]/ },
            { name: 'query', test: /node_modules[\\/]@tanstack[\\/]react-query[\\/]/ },
          ],
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/admin': { target: devApiTarget, changeOrigin: true, secure: false },
      '/public': { target: devApiTarget, changeOrigin: true, secure: false },
      '/health': { target: devApiTarget, changeOrigin: true, secure: false },
      '/account': { target: devApiTarget, changeOrigin: true, secure: false },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.{test,spec}.{ts,tsx}', 'src/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reportsDirectory: 'coverage',
      reporter: ['text-summary', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.d.ts', 'src/main.tsx', 'src/**/*.test.{ts,tsx}'],
    },
  },
});
