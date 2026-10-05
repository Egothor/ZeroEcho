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

import type { ComponentType } from 'react';
import type { SvgIconProps } from '@mui/material';
import DashboardIcon from '@mui/icons-material/DashboardOutlined';
import AccountBalanceIcon from '@mui/icons-material/AccountBalanceOutlined';
import AccountTreeIcon from '@mui/icons-material/AccountTreeOutlined';
import DescriptionIcon from '@mui/icons-material/DescriptionOutlined';
import UploadFileIcon from '@mui/icons-material/UploadFileOutlined';
import VerifiedIcon from '@mui/icons-material/VerifiedOutlined';
import AutorenewIcon from '@mui/icons-material/AutorenewOutlined';
import FactCheckIcon from '@mui/icons-material/FactCheckOutlined';
import BlockIcon from '@mui/icons-material/BlockOutlined';
import ListAltIcon from '@mui/icons-material/ListAltOutlined';
import PublishIcon from '@mui/icons-material/PublishOutlined';
import PeopleIcon from '@mui/icons-material/PeopleOutlined';
import SecurityIcon from '@mui/icons-material/SecurityOutlined';
import ApprovalIcon from '@mui/icons-material/ApprovalOutlined';
import LockOpenIcon from '@mui/icons-material/LockOpenOutlined';
import HistoryIcon from '@mui/icons-material/HistoryOutlined';
import LanguageIcon from '@mui/icons-material/LanguageOutlined';
import GppGoodIcon from '@mui/icons-material/GppGoodOutlined';
import FolderIcon from '@mui/icons-material/FolderOutlined';
import VisibilityIcon from '@mui/icons-material/VisibilityOutlined';
import TuneIcon from '@mui/icons-material/TuneOutlined';
import PublicIcon from '@mui/icons-material/PublicOutlined';
import TerminalIcon from '@mui/icons-material/TerminalOutlined';
import SyncAltIcon from '@mui/icons-material/SyncAltOutlined';
import ManageAccountsIcon from '@mui/icons-material/ManageAccountsOutlined';
import VpnKeyIcon from '@mui/icons-material/VpnKeyOutlined';
import AssignmentIcon from '@mui/icons-material/AssignmentOutlined';

/** A navigable domain area, each backed by a group of catalog operations. */
export interface NavItem {
  readonly id: string;
  readonly label: string;
  readonly path: string;
  readonly icon: ComponentType<SvgIconProps>;
  readonly group: NavGroup;
  /**
   * Operation-id prefixes this area governs. Used to hide an area when the
   * principal can invoke none of its operations (discoverability-driven nav).
   * Empty = always shown (e.g. public/read-only areas).
   */
  readonly operationPrefixes: readonly string[];
}

export type NavGroup = 'Overview' | 'Issuance' | 'Lifecycle' | 'Trust & Access' | 'Operations' | 'Public';

export const NAV_ITEMS: readonly NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', path: '/', icon: DashboardIcon, group: 'Overview', operationPrefixes: [] },
  { id: 'realm', label: 'Realm', path: '/realm', icon: LanguageIcon, group: 'Overview', operationPrefixes: [] },

  { id: 'authorities', label: 'Certificate Authorities', path: '/authorities', icon: AccountBalanceIcon, group: 'Issuance', operationPrefixes: ['ca.'] },
  { id: 'issuers', label: 'Issuer Generations & Paths', path: '/issuers', icon: AccountTreeIcon, group: 'Issuance', operationPrefixes: ['issuer.'] },
  { id: 'profiles', label: 'Certificate Profiles', path: '/profiles', icon: DescriptionIcon, group: 'Issuance', operationPrefixes: ['profile.'] },
  { id: 'requests', label: 'Requests (CSRs)', path: '/requests', icon: UploadFileIcon, group: 'Issuance', operationPrefixes: ['request.'] },
  { id: 'issuance', label: 'Issuance', path: '/issuance', icon: VerifiedIcon, group: 'Issuance', operationPrefixes: ['credential.issue', 'credential.inspect'] },

  { id: 'lifecycle', label: 'Lifecycle', path: '/lifecycle', icon: AutorenewIcon, group: 'Lifecycle', operationPrefixes: ['credential.renew', 'credential.replace', 'credential.reissue'] },
  { id: 'confirmations', label: 'Credential Confirmation', path: '/confirmations', icon: FactCheckIcon, group: 'Lifecycle', operationPrefixes: ['credential.confirmation.'] },
  { id: 'revocation', label: 'Revocation', path: '/revocation', icon: BlockIcon, group: 'Lifecycle', operationPrefixes: ['credential.revoke', 'revocation.'] },
  { id: 'status', label: 'Status & CRLs', path: '/status', icon: ListAltIcon, group: 'Lifecycle', operationPrefixes: ['status.', 'inventory.status'] },
  { id: 'publication', label: 'Publication', path: '/publication', icon: PublishIcon, group: 'Lifecycle', operationPrefixes: ['publication.'] },

  { id: 'principals', label: 'Principals', path: '/principals', icon: PeopleIcon, group: 'Trust & Access', operationPrefixes: ['security.principal.'] },
  { id: 'access', label: 'Roles & Grants', path: '/access', icon: SecurityIcon, group: 'Trust & Access', operationPrefixes: ['security.role-', 'security.grant.', 'security.authorization.'] },
  { id: 'approvals', label: 'Approvals', path: '/approvals', icon: ApprovalIcon, group: 'Trust & Access', operationPrefixes: ['security.approval.'] },
  { id: 'break-glass', label: 'Break-glass', path: '/break-glass', icon: LockOpenIcon, group: 'Trust & Access', operationPrefixes: ['security.break-glass.'] },
  { id: 'disclosure', label: 'Disclosure & Capabilities', path: '/disclosure', icon: VisibilityIcon, group: 'Trust & Access', operationPrefixes: ['security.disclosure.', 'certificate.publication.enroll'] },
  { id: 'audit', label: 'Audit', path: '/audit', icon: HistoryIcon, group: 'Trust & Access', operationPrefixes: ['security.audit'] },

  { id: 'acme', label: 'ACME', path: '/acme', icon: GppGoodIcon, group: 'Operations', operationPrefixes: ['acme.'] },
  { id: 'ocsp', label: 'OCSP', path: '/ocsp', icon: VerifiedIcon, group: 'Operations', operationPrefixes: ['ocsp.'] },
  { id: 'scep', label: 'SCEP', path: '/scep', icon: SyncAltIcon, group: 'Operations', operationPrefixes: ['scep.'] },
  { id: 'cmp', label: 'CMP', path: '/cmp', icon: ManageAccountsIcon, group: 'Operations', operationPrefixes: ['cmp.'] },
  { id: 'est', label: 'EST', path: '/est', icon: VpnKeyIcon, group: 'Operations', operationPrefixes: ['est.'] },
  { id: 'enrollment', label: 'Enrollment Profiles', path: '/enrollment', icon: AssignmentIcon, group: 'Operations', operationPrefixes: ['enrollment.'] },
  { id: 'repository', label: 'Repository Aliases', path: '/repository', icon: FolderIcon, group: 'Operations', operationPrefixes: ['repository.alias.'] },
  { id: 'configuration', label: 'Algorithm Bindings & Config', path: '/configuration', icon: TuneIcon, group: 'Operations', operationPrefixes: ['algorithm.binding.', 'configuration.'] },
  { id: 'operations', label: 'Operations Explorer', path: '/operations', icon: TerminalIcon, group: 'Operations', operationPrefixes: [] },

  { id: 'public', label: 'Public Repository', path: '/public', icon: PublicIcon, group: 'Public', operationPrefixes: [] },
];

export const NAV_GROUP_ORDER: readonly NavGroup[] = [
  'Overview',
  'Issuance',
  'Lifecycle',
  'Trust & Access',
  'Operations',
  'Public',
];
