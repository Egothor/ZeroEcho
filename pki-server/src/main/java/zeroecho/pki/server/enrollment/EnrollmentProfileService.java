/* *****************************************************************************
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
package zeroecho.pki.server.enrollment;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.server.ServerControlStore;

/**
 * Durable, thread-safe enrollment profile registry owned by one realm.
 *
 * <p>Writes use the server-control transaction boundary and compare-and-set
 * commitments. Concurrent replacement conflicts fail rather than losing an
 * update. Every stored replacement advances a revision, including a replacement
 * with identical policy, so an intervening change cannot evade the comparison.
 * The caller owns and closes the supplied store. Construction validates all
 * persisted profiles before the realm accepts requests.</p>
 *
 * @since 1.0
 */
public final class EnrollmentProfileService {

    private static final int VERSION = 1;
    private static final int MAXIMUM_STRING_BYTES = 16_384;
    private static final int MAXIMUM_COLLECTION = 256;
    private static final int MAXIMUM_PAYLOAD_BYTES = 524_288;
    private final ServerControlStore control;

    /**
     * Opens and validates the realm's durable registry.
     * @param control open realm-owned server-control store
     * @throws IllegalStateException if a stored profile is corrupt or unsupported
     */
    public EnrollmentProfileService(ServerControlStore control) {
        this.control = Objects.requireNonNull(control, "control");
        ServerControlStore.Page<EnrollmentProfile> page;
        int offset = 0;
        do {
            page = list(offset, 128);
            offset = page.nextOffset();
        } while (page.hasMore());
    }

    /**
     * Durably creates a profile; existing identities cannot be overwritten.
     * @param profile non-null immutable profile to persist
     * @throws IllegalStateException if the identity exists or persistence fails
     */
    public void register(EnrollmentProfile profile) {
        Objects.requireNonNull(profile, "profile");
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                record(profile, 1), Optional.empty())));
    }

    /**
     * Updates an existing enrollment profile.
     * Active endpoint bindings must remain compatible with the certificate profile
     * and allowed authorities. Deregister incompatible endpoints before changing
     * those fields; suspension itself is always permitted. Validation and commit
     * share the control-store monitor with endpoint registration.
     *
     * @param profile non-null replacement profile
     * @return the durably committed replacement
     * @throws IllegalArgumentException if no profile with the given id exists
     * @throws IllegalStateException if an active endpoint would become incompatible,
     *         a concurrent change conflicts, or persistence fails
     */
    public EnrollmentProfile update(EnrollmentProfile profile) {
        Objects.requireNonNull(profile, "profile");
        return replace(require(profile.id()), profile);
    }

    /**
     * Looks up the current profile by identifier.
     * @param id non-null identifier
     * @return the observed profile, or empty if absent
     */
    public Optional<EnrollmentProfile> find(String id) {
        return control.protocolRecord(ServerControlStore.ENROLLMENT_PROFILE,
                Objects.requireNonNull(id, "id")).map(value -> decode(value).profile());
    }

    /**
     * Collects all current profiles in deterministic store-key order.
     * Concurrent writes between pages need not form one atomic snapshot.
     * @return immutable profiles; O(N) retained profile memory
     */
    public List<EnrollmentProfile> list() {
        List<EnrollmentProfile> profiles = new ArrayList<>();
        ServerControlStore.Page<EnrollmentProfile> page;
        int offset = 0;
        do {
            page = list(offset, 128);
            profiles.addAll(page.values());
            offset = page.nextOffset();
        } while (page.hasMore());
        return List.copyOf(profiles);
    }

    /**
     * Resolves a compatible enrollment binding under the shared control monitor.
     * @param id enrollment policy identity
     * @param certificateProfileId distinct certificate policy identity
     * @param authorityId selected logical authority
     * @param active whether admission requires an active policy
     * @return exact current compatible policy
     */
    public EnrollmentProfile requireBinding(String id, String certificateProfileId, String authorityId, boolean active) {
        return requireBinding(control, id, certificateProfileId, authorityId, active);
    }

    /**
     * Resolves one policy without constructing another registry or scanning it.
     * Protocol registries use the same control monitor for validation and mutation.
     * @param control owning realm authority
     * @param id enrollment policy identity
     * @param certificateProfileId selected certificate profile
     * @param authorityId selected authority
     * @param active whether the profile must be active
     * @return exact compatible profile
     */
    public static EnrollmentProfile requireBinding(ServerControlStore control, String id, String certificateProfileId,
            String authorityId, boolean active) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            EnrollmentProfile profile = control.protocolRecord(ServerControlStore.ENROLLMENT_PROFILE, id)
                    .map(value -> decode(value).profile()).orElseThrow(() -> new IllegalStateException("Enrollment profile is unavailable"));
            if (active && profile.state() != EnrollmentProfileState.ACTIVE
                    || !profile.certificateProfileId().equals(certificateProfileId)
                    || !profile.allowedAuthorityIds().isEmpty() && !profile.allowedAuthorityIds().contains(authorityId)) {
                throw new IllegalStateException("Enrollment profile binding is unavailable");
            }
            return profile;
        }
    }

    /**
     * Reads a bounded page without retaining the complete registry.
     * @param offset nonnegative store-key offset
     * @param limit page size accepted by the server-control store
     * @return immutable page in deterministic store-key order
     */
    public ServerControlStore.Page<EnrollmentProfile> list(int offset, int limit) {
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page =
                control.protocolRecords(ServerControlStore.ENROLLMENT_PROFILE, offset, limit);
        return new ServerControlStore.Page<>(page.values().stream()
                .map(value -> decode(value).profile()).toList(), page.nextOffset(), page.hasMore());
    }

    /**
     * Transitions the profile to the given state.
     *
     * @param id non-null profile identifier
     * @param state non-null replacement state
     * @return the durably committed profile
     * @throws IllegalArgumentException if no profile with the given id exists
     * @throws IllegalStateException if a concurrent change conflicts or persistence fails
     */
    public EnrollmentProfile setState(String id, EnrollmentProfileState state) { // NOPMD LinguisticNaming - Public atomic state transition returns the stored immutable profile; preserve consumer API.
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(state, "state");
        ServerControlStore.ProtocolRecord existing = require(id);
        return replace(existing, decode(existing).profile().withState(state));
    }

    /**
     * Commits every policy field using the same canonical encoding as persistence.
     * Set ordering is normalized; list ordering and optional-value presence are preserved.
     * @param profile exact proposed policy
     * @return lowercase SHA-256 commitment, independent of its storage revision
     * @throws IllegalArgumentException if the profile exceeds the finite encoding bounds
     */
    public static String commitment(EnrollmentProfile profile) {
        return sha256(encode(Objects.requireNonNull(profile, "profile"), 1));
    }

    private ServerControlStore.ProtocolRecord require(String id) {
        return control.protocolRecord(ServerControlStore.ENROLLMENT_PROFILE, id)
                .orElseThrow(() -> new IllegalArgumentException("Enrollment profile not found: " + id));
    }

    private EnrollmentProfile replace(ServerControlStore.ProtocolRecord existing, EnrollmentProfile profile) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            EnrollmentEndpointRegistry.requireCompatibleProfile(control, profile);
            long revision = Math.incrementExact(decode(existing).revision());
            control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                    record(profile, revision), Optional.of(existing.commitment()))));
            return profile;
        }
    }

    private static ServerControlStore.ProtocolRecord record(EnrollmentProfile profile, long revision) {
        byte[] payload = encode(profile, revision);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_PROFILE,
                profile.id(), sha256(payload), payload);
    }

    private static byte[] encode(EnrollmentProfile profile, long revision) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(VERSION);
            output.writeLong(revision);
            write(output, profile.id());
            write(output, profile.displayName());
            write(output, profile.state().name());
            write(output, profile.certificateProfileId());
            writeCollection(output, profile.allowedAuthorityIds().stream().sorted().toList());
            output.writeBoolean(profile.subjectDnPattern().isPresent());
            if (profile.subjectDnPattern().isPresent()) {
                write(output, profile.subjectDnPattern().orElseThrow());
            }
            writeCollection(output, profile.requiredSanDomains());
            output.writeBoolean(profile.requireApproval());
            output.flush();
            if (bytes.size() > MAXIMUM_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("Enrollment profile exceeds payload bound");
            }
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("Enrollment profile encoding failed", impossible);
        }
    }

    private static Stored decode(ServerControlStore.ProtocolRecord record) {
        byte[] payload = record.payload();
        if (!sha256(payload).equals(record.commitment())) {
            throw corrupt();
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (input.readInt() != VERSION) {
                throw corrupt();
            }
            long revision = input.readLong();
            if (revision <= 0) {
                throw corrupt();
            }
            String id = read(input);
            String displayName = read(input);
            EnrollmentProfileState state = EnrollmentProfileState.valueOf(read(input));
            String certificateProfileId = read(input);
            List<String> authorities = readCollection(input);
            Set<String> authorityIds = new HashSet<>(authorities);
            if (authorities.size() != authorityIds.size()) {
                throw corrupt();
            }
            Optional<String> subjectPattern = input.readBoolean() ? Optional.of(read(input)) : Optional.empty();
            List<String> domains = readCollection(input);
            boolean approval = input.readBoolean();
            EnrollmentProfile profile = new EnrollmentProfile(id, displayName, state, certificateProfileId,
                    authorityIds, subjectPattern, domains, approval);
            if (!id.equals(record.recordId()) || input.read() != -1
                    || !Arrays.equals(payload, encode(profile, revision))) {
                throw corrupt();
            }
            return new Stored(profile, revision);
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalStateException("Enrollment profile record is corrupt or unsupported", failure);
        }
    }

    private static void writeCollection(DataOutputStream output, List<String> values) throws IOException {
        if (values.size() > MAXIMUM_COLLECTION) {
            throw new IllegalArgumentException("Enrollment profile collection exceeds bound");
        }
        output.writeInt(values.size());
        for (String value : values) {
            write(output, value);
        }
    }

    private static List<String> readCollection(DataInputStream input) throws IOException {
        int count = input.readInt();
        if (count < 0 || count > MAXIMUM_COLLECTION) {
            throw corrupt();
        }
        List<String> values = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            values.add(read(input));
        }
        return values;
    }

    private static void write(DataOutputStream output, String value) throws IOException {
        if (value.length() > MAXIMUM_STRING_BYTES) {
            throw new IllegalArgumentException("Enrollment profile string exceeds bound");
        }
        ByteBuffer bytes;
        try {
            bytes = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(value));
        } catch (CharacterCodingException invalid) {
            throw new IllegalArgumentException("Enrollment profile string is not valid Unicode", invalid);
        }
        int length = bytes.remaining();
        if (length > MAXIMUM_STRING_BYTES || output.size() + Integer.BYTES + length > MAXIMUM_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("Enrollment profile encoding exceeds bound");
        }
        output.writeInt(length);
        output.write(bytes.array(), bytes.position(), length);
    }

    private static String read(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAXIMUM_STRING_BYTES || length > input.available()) {
            throw corrupt();
        }
        return new String(input.readNBytes(length), StandardCharsets.UTF_8);
    }

    private static String sha256(byte[] payload) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static IllegalStateException corrupt() {
        return new IllegalStateException("Enrollment profile record is corrupt or unsupported");
    }

    private record Stored(EnrollmentProfile profile, long revision) { }
}
