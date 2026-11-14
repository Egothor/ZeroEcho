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

import { fireEvent, render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { expect, it, vi } from 'vitest';
import { OperationForm } from '@/components/operation/OperationForm';
import { operationSpec } from '@/api/operationCatalog';
vi.mock('@/hooks/useDerivedValues', () => ({ useDerivedValues: () => ({ values: {}, loading: false }) }));
vi.mock('@/hooks/useSubjectInput', () => ({ useSubjectInput: () => ({ metadata: undefined, invalid: false, loading: false, error: null }) }));
vi.mock('@/components/operation/OperationField', () => ({ OperationField: ({ field, value, onChange }: {
  field: { name: string }; value: unknown; onChange: (value: string) => void;
}) => <label>{field.name}<input aria-label={field.name} value={String(value ?? '')} onChange={event => onChange(event.target.value)} /></label> }));
function mount(targetArguments: string) {
  const submit = vi.fn();
  const client = new QueryClient();
  render(<QueryClientProvider client={client}><OperationForm spec={operationSpec('security.approval.request')!} initialValues={{ approvalId: 'legacy-only', targetOperation: 'ca.create', targetArguments, targetAuthorityId: 'ca:scope' }} onSubmit={submit} /></QueryClientProvider>);
  return { submit, client };
}
it('retains exact arguments and scope in the low-level legacy approval-only form', () => {
  const args = { subjectRef: 'CN=Legacy', nested: { preserved: true } };
  const view = mount(JSON.stringify(args));
  expect(screen.getByRole('region', { name: 'Prepared approval target' })).toHaveTextContent('ca:scope');
  expect(screen.queryByLabelText('subjectRef')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Create approval request' }));
  expect(JSON.parse(view.submit.mock.calls[0]?.[0].targetArguments)).toEqual(args);
  view.client.clear();
});
it('blocks malformed prepared JSON in the low-level legacy form', () => {
  const view = mount('{broken');
  expect(screen.getByText(/Prepared arguments are invalid/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'Create approval request' })).toBeDisabled();
  view.client.clear();
});
