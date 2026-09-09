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

import { useState } from 'react';
import { Link as RouterLink, Outlet, useLocation } from 'react-router-dom';
import {
  Alert,
  AppBar,
  Box,
  Chip,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  ListSubheader,
  MenuItem,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';
import DarkModeIcon from '@mui/icons-material/DarkModeOutlined';
import LightModeIcon from '@mui/icons-material/LightModeOutlined';
import ShieldIcon from '@mui/icons-material/ShieldOutlined';
import { NAV_GROUP_ORDER, NAV_ITEMS, type NavItem } from '@/app/navigation';
import { useColorMode } from '@/theme/colorModeContext';
import { useRealm } from '@/hooks/useRealm';
import { useOperationDescriptors } from '@/api/operations';
import { useDemoMode } from '@/demo/demoModeContext';
import { DEMO_ROLES, type DemoRole } from '@/demo/roles';

const DRAWER_WIDTH = 264;

function NavList({ onNavigate }: { readonly onNavigate?: () => void }) {
  const location = useLocation();
  const descriptors = useOperationDescriptors();
  const ops = descriptors.data?.operations ?? [];

  // An area is shown when it has no operation gating (dashboard, realm, explorer,
  // public) or the identity can invoke at least one of its operations. Until the
  // catalog loads, show everything.
  const shown = (item: NavItem) =>
    item.operationPrefixes.length === 0 ||
    ops.length === 0 ||
    ops.some((d) => item.operationPrefixes.some((p) => d.operation === p || d.operation.startsWith(p)));

  return (
    <Box role="navigation" aria-label="Primary" sx={{ overflowY: 'auto' }}>
      {NAV_GROUP_ORDER.map((group) => {
        const items = NAV_ITEMS.filter((i) => i.group === group && shown(i));
        if (items.length === 0) return null;
        return (
          <List key={group} dense subheader={<ListSubheader disableSticky>{group}</ListSubheader>}>
            {items.map((item) => {
              const selected =
                item.path === '/' ? location.pathname === '/' : location.pathname.startsWith(item.path);
              const Icon = item.icon;
              return (
                <ListItemButton
                  key={item.id}
                  component={RouterLink}
                  to={item.path}
                  selected={selected}
                  onClick={onNavigate}
                >
                  <ListItemIcon sx={{ minWidth: 40 }}>
                    <Icon fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={item.label} />
                </ListItemButton>
              );
            })}
          </List>
        );
      })}
    </Box>
  );
}

export function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { mode, toggle } = useColorMode();
  const realm = useRealm();
  const demo = useDemoMode();

  const drawer = (
    <>
      <Toolbar sx={{ gap: 1 }}>
        <ShieldIcon color="primary" />
        <Typography variant="h6" noWrap sx={{ fontWeight: 700 }}>
          ZeroEcho PKI
        </Typography>
      </Toolbar>
      <Divider />
      <NavList onNavigate={() => setMobileOpen(false)} />
    </>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <AppBar
        position="fixed"
        color="default"
        elevation={0}
        sx={{ zIndex: (t) => t.zIndex.drawer + 1, borderBottom: 1, borderColor: 'divider' }}
      >
        <Toolbar sx={{ gap: 1 }}>
          <IconButton
            edge="start"
            aria-label="Open navigation"
            onClick={() => setMobileOpen((o) => !o)}
            sx={{ display: { md: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, flexGrow: 1 }}>
            Administration
          </Typography>
          {demo.enabled && (
            <TextField
              select
              size="small"
              label="Demo persona"
              value={demo.role}
              onChange={(e) => demo.setRole(e.target.value as DemoRole)}
              sx={{ minWidth: 180, mr: 1, display: { xs: 'none', sm: 'block' } }}
            >
              {DEMO_ROLES.map((r) => (
                <MenuItem key={r.id} value={r.id}>
                  {r.label}
                </MenuItem>
              ))}
            </TextField>
          )}
          {realm.data && (
            <Tooltip title={`Realm ${realm.data.realmId}`}>
              <Chip size="small" color="primary" variant="outlined" label={realm.data.displayName} />
            </Tooltip>
          )}
          <Tooltip title={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
            <IconButton onClick={toggle} aria-label="Toggle color mode">
              {mode === 'dark' ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Tooltip>
        </Toolbar>
      </AppBar>

      <Box component="nav" sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}>
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          open
          sx={{
            display: { xs: 'none', md: 'block' },
            '& .MuiDrawer-paper': { width: DRAWER_WIDTH, boxSizing: 'border-box' },
          }}
        >
          {drawer}
        </Drawer>
      </Box>

      <Box component="main" sx={{ flexGrow: 1, width: { md: `calc(100% - ${DRAWER_WIDTH}px)` }, p: { xs: 2, md: 3 } }}>
        <Toolbar />
        {demo.enabled && (
          <Alert severity="info" variant="outlined" sx={{ mb: 2 }}>
            Demo mode — an in-browser mock backend, no server or client certificate. Acting as{' '}
            <strong>{DEMO_ROLES.find((r) => r.id === demo.role)?.label ?? demo.role}</strong>. Switch persona to see how
            available operations change per identity.
          </Alert>
        )}
        <Outlet />
      </Box>
    </Box>
  );
}
