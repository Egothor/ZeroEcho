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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Windows (NTFS/ACL) implementation of {@link PlatformFsOps}.
 *
 * <h2>Directory durability</h2>
 * <p>
 * Windows cannot open a directory as a channel and offers no directory
 * {@code fsync}. Directory-entry durability at a publication commit point is
 * instead carried by the atomic publish itself: the JDK maps
 * {@link java.nio.file.StandardCopyOption#ATOMIC_MOVE} to
 * {@code MoveFileEx(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)}
 * (or without {@code REPLACE_EXISTING} for a create-only publish), and
 * {@code MOVEFILE_WRITE_THROUGH} flushes the rename's metadata transaction to
 * disk before returning. Consequently {@link #forceDirectory(Path)} is a correct
 * no-op here — the durability it would provide has already been established.
 * </p>
 *
 * <h2>Owner-only protection</h2>
 * <p>
 * Owner-only access is expressed as an NTFS ACL. {@link #restrictToOwner(Path)}
 * replaces the directory's discretionary ACL with a single inheritable
 * allow-full-control entry for the directory owner; the JDK marks the ACL
 * protected, so inherited parent entries are dropped and descendant files and
 * directories become owner-only by inheritance.
 * </p>
 */
final class WindowsPlatformFsOps implements PlatformFsOps {

    private static final FileAttribute<?>[] NO_ATTRIBUTES = new FileAttribute<?>[0];

    @Override
    public void forceDirectory(final Path directory) {
        // Correct no-op: durability is carried by the write-through atomic publish.
    }

    @Override
    public FileAttribute<?>[] directoryCreateAttributes() {
        return NO_ATTRIBUTES;
    }

    @Override
    public FileAttribute<?>[] fileCreateAttributes() {
        return NO_ATTRIBUTES;
    }

    @Override
    public void restrictToOwner(final Path directory) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(directory, AclFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new IOException("owner-only protection unavailable: ACL view unsupported for " + directory);
        }
        UserPrincipal owner = view.getOwner();
        Set<AclEntryPermission> fullControl = EnumSet.allOf(AclEntryPermission.class);
        Set<AclEntryFlag> inheritToChildren = EnumSet.of(AclEntryFlag.DIRECTORY_INHERIT, AclEntryFlag.FILE_INHERIT);
        AclEntry ownerFullControl = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(fullControl)
                .setFlags(inheritToChildren)
                .build();
        // Replacing the ACL marks the DACL protected in the JDK's Windows
        // implementation, dropping inherited parent entries so the directory and
        // its future descendants are owner-only.
        view.setAcl(List.of(ownerFullControl));
    }

    @Override
    public String platformId() {
        return "windows-acl";
    }

    @Override
    public boolean enterpriseGrade() {
        return true;
    }
}
