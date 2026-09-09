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
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;

/**
 * Platform-variant filesystem primitives for the durable PKI store.
 *
 * <p>
 * The store's crash-consistency and owner-only protection contracts are
 * implemented differently on POSIX and Windows. This seam isolates the handful
 * of operations whose semantics genuinely differ so that the durability-critical
 * store code stays platform-neutral. All other filesystem behaviour (write to a
 * temporary sibling, {@code FileChannel.force(true)} for file-content durability,
 * {@link java.nio.file.StandardCopyOption#ATOMIC_MOVE} for the publication commit
 * point) is byte-for-byte identical across platforms and therefore lives in the
 * shared helpers, not here.
 * </p>
 *
 * <h2>Durability model</h2>
 * <p>
 * On POSIX the commit point is {@code rename(2)} followed by an explicit
 * {@code fsync} of the parent directory. On Windows a directory cannot be opened
 * as a channel and there is no directory {@code fsync}; instead the JDK maps
 * {@code ATOMIC_MOVE} to {@code MoveFileEx(..., MOVEFILE_WRITE_THROUGH)}, which
 * flushes the rename's metadata transaction to disk before returning. The
 * explicit directory force is therefore a correct no-op on Windows: the
 * durability it would provide has already been carried by the write-through
 * atomic publish. This is why {@link #forceDirectory(Path)} must be routed
 * through this seam at every publication site rather than inlined.
 * </p>
 *
 * <h2>Owner-only protection</h2>
 * <p>
 * POSIX enforces owner-only access with {@code 0700}/{@code 0600} permission
 * bits set at create time. Windows has no POSIX permission bits; owner-only
 * access is expressed as an NTFS ACL. The Windows implementation grants the
 * store owner full control on the store root with an inheritable ACL and removes
 * inherited and third-party entries, so descendant files and directories are
 * owner-only by inheritance rather than by a per-file permission set.
 * </p>
 *
 * <p>
 * Implementations are stateless and thread-safe; one instance is resolved per
 * process by {@link PlatformFs}.
 * </p>
 */
interface PlatformFsOps {

    /**
     * Forces one directory's entry updates durable, or performs a correct no-op
     * on platforms that carry directory durability through the write-through
     * atomic publish rather than an explicit directory {@code fsync}.
     *
     * @param directory existing directory whose entry updates must be durable
     * @throws IOException if the platform supports directory forcing but the
     *                     force itself fails (a genuine durability failure)
     */
    void forceDirectory(Path directory) throws IOException;

    /**
     * Create-time attributes for a new owner-only directory.
     *
     * @return POSIX {@code 0700} attribute on POSIX; an empty array on platforms
     *         that establish owner-only access by ACL inheritance instead
     */
    FileAttribute<?>[] directoryCreateAttributes();

    /**
     * Create-time attributes for a new owner-only file.
     *
     * @return POSIX {@code 0600} attribute on POSIX; an empty array on platforms
     *         that establish owner-only access by ACL inheritance instead
     */
    FileAttribute<?>[] fileCreateAttributes();

    /**
     * Establishes owner-only protection on an existing directory that is the
     * protection root for its subtree.
     *
     * <p>
     * On POSIX the create-time permission bits already enforce this, so the
     * implementation verifies rather than mutates. On Windows this applies an
     * inheritable owner-only ACL so descendants are protected by inheritance.
     * </p>
     *
     * @param directory existing directory to protect
     * @throws IOException if protection cannot be established or verified
     */
    void restrictToOwner(Path directory) throws IOException;

    /**
     * @return a stable platform identifier for diagnostics (never sensitive)
     */
    String platformId();

    /**
     * @return {@code true} when this platform provides the enterprise-grade
     *         durability and owner-only protection guarantees the store
     *         requires
     */
    boolean enterpriseGrade();
}
