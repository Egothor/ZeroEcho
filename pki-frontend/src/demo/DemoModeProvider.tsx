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

import { useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { resetTransport, setTransport } from '@/api/transport';
import { createDemoTransport } from '@/demo/demoBackend';
import {
  DemoModeContext,
  detectDemoEnabled,
  loadDemoRole,
  persistDemoRole,
  type DemoModeContextValue,
} from '@/demo/demoModeContext';
import type { DemoRole } from '@/demo/roles';

/**
 * Installs the in-browser demo transport when demo mode is enabled, and exposes
 * the active persona. Changing persona re-filters what the mock server exposes
 * and invalidates cached queries so the console reflects the new identity.
 * Transport setup precedes descendant query effects and cleanup restores live
 * transport, including React StrictMode replay; rendering does not change it.
 *
 * @param children descendant console content
 * @returns the demo persona context around the supplied content
 */
export function DemoModeProvider({ children }: { readonly children: ReactNode }) {
  const enabled = useMemo(() => detectDemoEnabled(), []);
  const [role, setRoleState] = useState<DemoRole>(() => (enabled ? loadDemoRole() : 'ADMINISTRATOR'));
  const roleRef = useRef(role);
  const queryClient = useQueryClient();

  // Layout setup precedes descendant query effects and reinstalls the transport
  // after StrictMode cleanup; discarded renders never change global transport.
  useLayoutEffect(() => {
    if (!enabled) return undefined;
    setTransport(createDemoTransport(() => roleRef.current));
    return () => resetTransport();
  }, [enabled]);

  const value = useMemo<DemoModeContextValue>(
    () => ({
      enabled,
      role,
      setRole: (next) => {
        // Refetches must see the new persona before React commits the state update.
        roleRef.current = next;
        persistDemoRole(next);
        setRoleState(next);
        void queryClient.invalidateQueries();
      },
    }),
    [enabled, role, queryClient],
  );

  return <DemoModeContext.Provider value={value}>{children}</DemoModeContext.Provider>;
}
