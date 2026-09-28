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

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { EntityAutocomplete } from '@/components/operation/EntityAutocomplete';
vi.mock('@/hooks/useEntityOptions', () => ({ useEntityOptions: () => ({ data: { items: [{ id: 'profile-exact-id', label: 'TLS server certificate', description: 'profile-exact-id', record: {} }] }, isFetching: false, isError: false }) }));

describe('known-value picker', () => {
  it('typing searches but only selecting submits the exact known identity', async () => {
    const onChange = vi.fn(), user = userEvent.setup();
    render(<EntityAutocomplete field={{ name: 'profileId', type: 'text', required: true, ref: 'profile' }} value="" onChange={onChange} />);
    await user.type(screen.getByRole('combobox'), 'TLS');
    expect(onChange).not.toHaveBeenCalled();
    await user.click(screen.getByRole('option', { name: /TLS server certificate/ }));
    expect(onChange).toHaveBeenLastCalledWith('profile-exact-id');
  });
  it('allows a new reference only for a field explicitly supporting unknown keys', async () => {
    const onChange = vi.fn(), user = userEvent.setup();
    render(<EntityAutocomplete field={{ name: 'keyRef', type: 'text', required: true, ref: 'key', allowNew: true }} value="" onChange={onChange} />);
    await user.type(screen.getByRole('combobox'), 'external-key');
    expect(onChange).toHaveBeenLastCalledWith('external-key');
  });
});
