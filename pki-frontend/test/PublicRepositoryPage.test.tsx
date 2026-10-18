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

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiRequestError } from '@/api/client';
import { PublicRepositoryPage } from '@/pages/PublicRepositoryPage';
import type * as Results from '@/components/ResultView';

const renderer = vi.hoisted(() => {
  let release!: () => void;
  const ready = new Promise<void>((resolve) => { release = resolve; });
  return { ready, release: () => release() };
});

// Hold the chunk boundary while still exercising the actual result renderer.
vi.mock('@/components/ResultView', async (original) => {
  await renderer.ready;
  return original<typeof Results>();
});

const get = vi.spyOn(api, 'get');
afterEach(() => get.mockReset());

function renderPage() {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><PublicRepositoryPage /></QueryClientProvider>);
}

describe('public repository authority results', () => {
  it('keeps pending and fallback results visible until the result chunk loads', async () => {
    let respond!: (value: unknown) => void;
    get.mockReturnValueOnce(new Promise((resolve) => { respond = resolve; }));
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: 'List authorities' }));
    await waitFor(() => expect(get).toHaveBeenCalledWith('/public/v1/authorities', { query: { limit: 100 } }));
    expect(screen.getByRole('button', { name: 'Loading…' })).toBeDisabled();
    await act(async () => { respond({ name: 'Published authority' }); });
    expect(await screen.findByText(/Published authority/, { selector: 'pre' })).toBeVisible();
    await act(async () => { renderer.release(); });
    expect(await screen.findByText('Published authority')).toBeVisible();
    expect(screen.queryByText(/Published authority/, { selector: 'pre' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'List authorities' })).toBeEnabled();
  });

  it.each([
    { error: new Error('connection failed'), message: 'Failed to list authorities' },
    { error: new ApiRequestError({ status: 503, code: 'UNAVAILABLE', message: 'Repository unavailable' }),
      message: 'UNAVAILABLE: Repository unavailable' },
  ])('shows the request failure without rendering a result: $message', async ({ error, message }) => {
    get.mockRejectedValueOnce(error);
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: 'List authorities' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(message);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'List authorities' })).toBeEnabled();
  });
});
