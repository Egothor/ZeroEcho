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
import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { OperationBrowser } from '@/components/operation/OperationBrowser';
import { OPERATIONS } from '@/api/operationCatalog';
import type { OperationCatalogResponse } from '@/api/types';
import type * as Operations from '@/api/operations';

const discovery = vi.hoisted(() => ({ data: { count: 0, operations: [] } as OperationCatalogResponse, isLoading: false, isError: false }));
vi.mock('@/api/operations', async (original) => ({
  ...await original<typeof Operations>(),
  useOperationDescriptors: () => discovery,
}));
vi.mock('@/components/operation/OperationRunner', () => ({
  OperationRunner: () => <div data-testid="runner" />,
}));

it('never substitutes built-in operations for empty or failed discovery', () => {
  const view = render(<OperationBrowser operations={OPERATIONS} />);
  expect(screen.getByText('No operations in this area are available to your identity.')).toBeInTheDocument();
  expect(screen.queryByTestId('runner')).not.toBeInTheDocument();
  discovery.isError = true;
  view.rerender(<OperationBrowser operations={OPERATIONS} />);
  expect(screen.getByText(/Operations remain unavailable until discovery succeeds/)).toBeInTheDocument();
  expect(screen.queryByTestId('runner')).not.toBeInTheDocument();
  discovery.isError = false;
  discovery.data = { count: 1, operations: [{ operation: 'ca.inspect', family: 'PKI_OPERATION',
    mutating: false, resourceType: 'CA', approval: 'NONE', dataView: 'METADATA_REDACTED' }] };
  view.rerender(<OperationBrowser operations={OPERATIONS} />);
  expect(screen.getByTestId('runner')).toBeInTheDocument();
  // TanStack retains the last successful data when a later refetch fails.
  discovery.isError = true;
  view.rerender(<OperationBrowser operations={OPERATIONS} />);
  expect(screen.queryByTestId('runner')).not.toBeInTheDocument();
  discovery.isError = false;
  discovery.data = { count: 0, operations: [] };
  view.rerender(<OperationBrowser operations={OPERATIONS} />);
  expect(screen.queryByTestId('runner')).not.toBeInTheDocument();
});
