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

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { ColorModeProvider } from '@/theme/ColorMode';
import { DemoModeProvider } from '@/demo/DemoModeProvider';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { AppLayout } from '@/components/AppLayout';
import { DashboardPage } from '@/pages/DashboardPage';
import { DomainPage } from '@/pages/DomainPage';
import { RealmPage } from '@/pages/RealmPage';
import { BackupPage } from '@/pages/BackupPage';
import { OperationsExplorerPage } from '@/pages/OperationsExplorerPage';
import { PublicRepositoryPage } from '@/pages/PublicRepositoryPage';
import { NotFoundPage } from '@/pages/NotFoundPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The server is the source of truth; keep client state bounded and honest.
      staleTime: 30_000,
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});

/** Navigation areas rendered by the generic operation-browser domain screen. */
const DOMAIN_PATHS = [
  '/authorities', '/issuers', '/profiles', '/requests', '/issuance', '/lifecycle', '/confirmations',
  '/revocation', '/status', '/publication', '/principals', '/access', '/approvals', '/break-glass',
  '/disclosure', '/audit', '/acme', '/ocsp', '/est', '/scep', '/cmp', '/enrollment', '/repository', '/configuration',
];

export function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <DemoModeProvider>
          <ColorModeProvider>
            <BrowserRouter>
            <Routes>
              <Route element={<AppLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="/realm" element={<RealmPage />} />
                <Route path="/backup" element={<BackupPage />} />
                <Route path="/operations" element={<OperationsExplorerPage />} />
                <Route path="/public" element={<PublicRepositoryPage />} />
                {DOMAIN_PATHS.map((path) => (
                  <Route key={path} path={`${path}/*`} element={<DomainPage />} />
                ))}
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
            </BrowserRouter>
          </ColorModeProvider>
        </DemoModeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
