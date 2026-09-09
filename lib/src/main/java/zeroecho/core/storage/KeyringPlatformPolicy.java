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
package zeroecho.core.storage;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import zeroecho.core.storage.KeyringException.Code;

/**
 * Platform-variant owner-only protection and directory-durability policy for the
 * encrypted keyring.
 *
 * <p>
 * The keyring stores CA private-key material and therefore demands owner-only
 * access and crash-consistent atomic replacement. POSIX expresses owner-only
 * access as {@code 0700}/{@code 0600} permission bits and single-link
 * ({@code nlink == 1}) files; Windows expresses it as an NTFS ACL. This seam
 * isolates the operations whose semantics differ so the keyring engine stays
 * platform-neutral. One policy is resolved per process from the default
 * filesystem.
 * </p>
 *
 * <h2>Windows residuals (documented)</h2>
 * <ul>
 * <li>The Windows {@code Administrators} group and {@code SYSTEM} can always take
 * ownership or access regardless of ACL; this is an inherent property of the
 * platform and cannot be prevented, so "owner-only" on Windows means "no
 * principal other than the owner and the platform's privileged accounts".</li>
 * <li>The POSIX hard-link ({@code nlink == 1}) defence is replaced by the
 * owner-only, inheritance-protected ACL on the containing directory: no other
 * principal can create a hard link to the keyring inside an owner-only
 * directory.</li>
 * </ul>
 */
interface KeyringPlatformPolicy {

    KeyringPlatformPolicy INSTANCE = resolve();

    /**
     * Normalises and validates the requested keyring path, establishing and
     * verifying an owner-only parent directory.
     *
     * @param requested    caller-supplied keyring path
     * @param createParent whether a missing parent directory may be created
     * @return the normalised absolute keyring path
     * @throws IOException if the path or its parent cannot be made owner-only
     */
    Path securePath(Path requested, boolean createParent) throws IOException;

    /**
     * Validates that {@code file} is an owner-only regular file owned by
     * {@code expectedOwner} with no additional hard links reachable by other
     * principals.
     *
     * @param file          keyring or lock file to validate
     * @param expectedOwner the required owner principal
     * @throws IOException if the file is not owner-only or not owned as expected
     */
    void validateExistingFile(Path file, UserPrincipal expectedOwner) throws IOException;

    /**
     * Validates that {@code path} currently enforces owner-only protection.
     *
     * @param path      path to validate
     * @param directory whether {@code path} is a directory
     * @throws IOException if protection is not owner-only
     */
    void validateOwnerOnly(Path path, boolean directory) throws IOException;

    /**
     * Applies owner-only protection to an existing path.
     *
     * <p>
     * On POSIX this is a no-op because the create-time permission bits already
     * enforce it. On Windows this installs an owner-only ACL (inheritable for a
     * directory).
     * </p>
     *
     * @param path      path to protect
     * @param directory whether {@code path} is a directory
     * @throws IOException if protection cannot be established
     */
    void restrictToOwner(Path path, boolean directory) throws IOException;

    /**
     * Forces one directory's entry updates durable, or performs a correct no-op
     * on platforms that carry directory durability through the write-through
     * atomic publish.
     *
     * @param parent existing directory whose entry updates must be durable
     * @throws IOException on a genuine directory durability failure
     */
    void forceDirectory(Path parent) throws IOException;

    /**
     * @return create-time attributes for a new owner-only keyring file
     */
    FileAttribute<?>[] fileCreateAttributes();

    /**
     * @return create-time attributes for a new owner-only keyring directory
     */
    FileAttribute<?>[] directoryCreateAttributes();

    private static KeyringPlatformPolicy resolve() {
        Set<String> views = FileSystems.getDefault().supportedFileAttributeViews();
        if (views.contains("posix")) {
            return new PosixKeyringPolicy();
        }
        if (views.contains("acl")) {
            return new WindowsKeyringPolicy();
        }
        throw new IllegalStateException(
                "unsupported platform: default filesystem provides neither POSIX nor ACL owner-only enforcement");
    }
}

/** POSIX keyring policy — identical to the keyring's original inlined behaviour. */
final class PosixKeyringPolicy implements KeyringPlatformPolicy {

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public Path securePath(final Path requested, final boolean createParent) throws IOException {
        Objects.requireNonNull(requested, "path must not be null");
        Path absolute = requested.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent == null) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        if (!Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
            if (!createParent) {
                throw new KeyringException(Code.KEYRING_IO_FAILED);
            }
            try {
                Files.createDirectories(parent, KeyringStore.DIRECTORY_ATTRIBUTE);
            } catch (UnsupportedOperationException exception) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        }
        if (Files.isSymbolicLink(parent)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        FileStore store = Files.getFileStore(parent);
        if (!store.supportsFileAttributeView(PosixFileAttributeView.class)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        validateOwnerOnly(parent, true);
        if (Files.isSymbolicLink(absolute)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        return absolute;
    }

    // The public keyring boundary deliberately exposes only its redacted stable error code.
    @SuppressWarnings("PMD.PreserveStackTrace")
    @Override
    public void validateExistingFile(final Path file, final UserPrincipal expectedOwner) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        validateOwnerOnly(file, false);
        PosixFileAttributes attributes = Files.readAttributes(file, PosixFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.owner().equals(expectedOwner)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        try {
            Object links = Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
            if (!(links instanceof Number number) || number.longValue() != 1L) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        } catch (UnsupportedOperationException exception) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
    }

    @Override
    public void validateOwnerOnly(final Path path, final boolean directory) throws IOException {
        PosixFileAttributes attributes = Files.readAttributes(path, PosixFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        Set<java.nio.file.attribute.PosixFilePermission> expected = directory ? KeyringStore.DIRECTORY_PERMISSIONS
                : KeyringStore.FILE_PERMISSIONS;
        if (!attributes.permissions().equals(expected)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
    }

    @Override
    public void restrictToOwner(final Path path, final boolean directory) {
        // No-op: the create-time POSIX permission bits already enforce owner-only.
    }

    @Override
    public void forceDirectory(final Path parent) throws IOException {
        try (java.nio.channels.FileChannel directory = java.nio.channels.FileChannel.open(parent,
                java.nio.file.StandardOpenOption.READ)) {
            directory.force(true);
        }
    }

    @Override
    public FileAttribute<?>[] fileCreateAttributes() {
        return new FileAttribute<?>[] { KeyringStore.FILE_ATTRIBUTE };
    }

    @Override
    public FileAttribute<?>[] directoryCreateAttributes() {
        return new FileAttribute<?>[] { KeyringStore.DIRECTORY_ATTRIBUTE };
    }
}

/** Windows (NTFS/ACL) keyring policy. */
final class WindowsKeyringPolicy implements KeyringPlatformPolicy {

    private static final FileAttribute<?>[] NO_ATTRIBUTES = new FileAttribute<?>[0];

    @Override
    @SuppressWarnings("PMD.PreserveStackTrace")
    public Path securePath(final Path requested, final boolean createParent) throws IOException {
        Objects.requireNonNull(requested, "path must not be null");
        Path absolute = requested.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent == null) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        if (!Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
            if (!createParent) {
                throw new KeyringException(Code.KEYRING_IO_FAILED);
            }
            try {
                Files.createDirectories(parent);
            } catch (UnsupportedOperationException exception) {
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        }
        if (Files.isSymbolicLink(parent)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        FileStore store = Files.getFileStore(parent);
        if (!store.supportsFileAttributeView(AclFileAttributeView.class)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        // Unlike POSIX (where a non-0700 parent is rejected), a Windows directory is
        // never owner-only by default: it inherits SYSTEM/Administrators/user ACEs.
        // The keyring therefore establishes owner-only protection on its parent
        // directory on every open, then verifies it took effect.
        restrictToOwner(parent, true);
        validateOwnerOnly(parent, true);
        if (Files.isSymbolicLink(absolute)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        return absolute;
    }

    @Override
    public void validateExistingFile(final Path file, final UserPrincipal expectedOwner) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        validateOwnerOnly(file, false);
        UserPrincipal owner = Files.getOwner(file, LinkOption.NOFOLLOW_LINKS);
        if (!owner.equals(expectedOwner)) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        // The POSIX nlink == 1 check is replaced by the owner-only, inheritance-
        // protected ACL on the containing directory: no other principal can
        // create a hard link to the keyring inside an owner-only directory.
    }

    @Override
    public void validateOwnerOnly(final Path path, final boolean directory) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        UserPrincipal owner = view.getOwner();
        for (AclEntry entry : view.getAcl()) {
            if (!entry.principal().equals(owner)) {
                // Any principal other than the owner appearing in the ACL means the
                // path is not owner-only (inheritance was not broken).
                throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
            }
        }
    }

    @Override
    public void restrictToOwner(final Path path, final boolean directory) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class,
                LinkOption.NOFOLLOW_LINKS);
        if (view == null) {
            throw new KeyringException(Code.KEYRING_FILESYSTEM_UNSUPPORTED);
        }
        UserPrincipal owner = view.getOwner();
        Set<AclEntryPermission> fullControl = EnumSet.allOf(AclEntryPermission.class);
        AclEntry.Builder builder = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(fullControl);
        if (directory) {
            builder.setFlags(EnumSet.of(AclEntryFlag.DIRECTORY_INHERIT, AclEntryFlag.FILE_INHERIT));
        }
        view.setAcl(List.of(builder.build()));
    }

    @Override
    public void forceDirectory(final Path parent) {
        // Correct no-op: durability is carried by the write-through atomic publish.
    }

    @Override
    public FileAttribute<?>[] fileCreateAttributes() {
        return NO_ATTRIBUTES;
    }

    @Override
    public FileAttribute<?>[] directoryCreateAttributes() {
        return NO_ATTRIBUTES;
    }
}
