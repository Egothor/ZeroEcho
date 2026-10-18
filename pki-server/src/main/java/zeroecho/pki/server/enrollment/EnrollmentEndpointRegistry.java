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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.cmp.CmpProtectionPolicy;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.est.KeygenPolicy;
import zeroecho.pki.server.scep.ScepEndpoint;

/**
 * Realm-owned, thread-safe durable endpoint registry.
 *
 * <p>Every replacement or removal advances a monotonic revision. Removal retains
 * a tombstone; re-registration cannot reuse an earlier revision or commitment.
 * Writes use the control store's atomic compare-and-set boundary. The caller
 * owns the store and must keep it open throughout registry use.</p>
 */
public final class EnrollmentEndpointRegistry { // NOPMD CyclomaticComplexity - One endpoint registry owns validated policy encoding and control-store publication; individual methods remain checked.
    private static final int MAXIMUM_ALGORITHM_COUNT = 16;
    private static final int MAXIMUM_TEXT_LENGTH = 4_096;

    private static final int VERSION = 1;
    private static final int MAXIMUM_PAYLOAD = 65_536;
    private final ServerControlStore control;
    private final EnrollmentProfileService profiles;
    private EnrollmentRuntime runtime;
    /** Closed protocols sharing the durable enrollment endpoint authority. */
    public enum Protocol {
        /** Enrollment over Secure Transport. */ EST,
        /** Simple Certificate Enrollment Protocol. */ SCEP,
        /** Certificate Management Protocol. */ CMP
    }

    /**
     * Exact persisted endpoint snapshot suitable for binding an approval request.
     * @param endpoint immutable complete configuration
     * @param revision positive monotonic record revision
     * @param active false for a removed endpoint
     * @param commitment SHA-256 commitment of the exact persisted snapshot
     */
    public record Snapshot(EnrollmentEndpoint endpoint, long revision, boolean active, String commitment) {
        /** Validates snapshot metadata. */
        public Snapshot {
            Objects.requireNonNull(endpoint, "endpoint");
            if (revision < 1 || commitment == null || !commitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Invalid enrollment endpoint snapshot");
            }
        }
    }

    /**
     * Validates every active endpoint, durably pins the credential identities,
     * and installs custody under the same control-store monitor. A validation
     * failure writes no pin; uncertain persistence is never rolled back.
     * Validation uses immutable provisioned metadata, never key-provider calls.
     * @param capability fully validated runtime owner
     */
    public void installRuntime(EnrollmentRuntime capability) {
        Objects.requireNonNull(capability, "capability");
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            if (runtime != null) {
                throw new IllegalStateException("Enrollment runtime already installed");
            }
            for (Protocol protocol : Protocol.values()) {
                for (EnrollmentEndpoint endpoint : list(protocol)) {
                    capability.validateEndpoint(endpoint);
                }
            }
            capability.pinCredentials(control);
            runtime = capability;
        }
    }

    /**
     * Opens the registry and validates every persisted record and active binding.
     * A suspended profile is permitted at startup so administrators can reactivate it.
     * @param control realm-owned open persistence authority
     * @param profiles realm-owned enrollment profile registry
     * @throws IllegalStateException if persisted records or active references are invalid
     */
    public EnrollmentEndpointRegistry(ServerControlStore control, EnrollmentProfileService profiles) {
        this.control = Objects.requireNonNull(control, "control");
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        int offset = 0;
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page;
        do {
            page = control.protocolRecords(ServerControlStore.ENROLLMENT_ENDPOINT, offset, 128);
            for (ServerControlStore.ProtocolRecord record : page.values()) {
                Snapshot snapshot = decode(record);
                if (snapshot.active()) {
                    requireBinding(snapshot.endpoint(), false);
                }
            }
            offset = page.nextOffset();
        } while (page.hasMore());
    }

    /**
     * Creates or atomically replaces an endpoint after validating its active policy.
     * @param endpoint complete immutable endpoint with an explicit enrollment policy
     * @return exact committed snapshot
     * @throws IllegalStateException if binding validation, CAS, or persistence fails
     */
    public Snapshot register(EnrollmentEndpoint endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            requireBinding(endpoint, true);
            if (runtime != null) {
                runtime.validateEndpoint(endpoint);
            }
            Optional<ServerControlStore.ProtocolRecord> previous = stored(protocol(endpoint), endpoint.label());
            long revision = previous.map(value -> Math.incrementExact(decode(value).revision())).orElse(1L);
            return persist(endpoint, revision, true, previous.map(ServerControlStore.ProtocolRecord::commitment));
        }
    }

    /**
     * Atomically tombstones an active endpoint without discarding its revision.
     * @param protocol exact protocol family
     * @param label canonical label
     * @return removed configuration, or empty if absent or already removed
     */
    public Optional<EnrollmentEndpoint> deregister(Protocol protocol, String label) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            Optional<ServerControlStore.ProtocolRecord> previous = stored(protocol, label);
            if (previous.isEmpty()) {
                return Optional.empty();
            }
            Snapshot snapshot = decode(previous.orElseThrow());
            if (!snapshot.active()) {
                return Optional.empty();
            }
            persist(snapshot.endpoint(), Math.incrementExact(snapshot.revision()), false,
                    Optional.of(snapshot.commitment()));
            return Optional.of(snapshot.endpoint());
        }
    }

    /**
     * Reads one active endpoint without admitting an enrollment request.
     * @param protocol exact protocol family
     * @param label canonical label
     * @return active configuration, or empty for absent/tombstoned identities
     */
    public Optional<EnrollmentEndpoint> find(Protocol protocol, String label) {
        return stored(protocol, label).map(EnrollmentEndpointRegistry::decode)
                .filter(Snapshot::active).map(Snapshot::endpoint);
    }

    /**
     * Collects active endpoints in deterministic control-store order.
     * Concurrent writes across pages do not form one atomic snapshot.
     * @param protocol exact protocol family
     * @return immutable configurations; O(N) retained output memory
     */
    public List<EnrollmentEndpoint> list(Protocol protocol) {
        Objects.requireNonNull(protocol, "protocol");
        List<EnrollmentEndpoint> result = new ArrayList<>();
        int offset = 0;
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page;
        do {
            page = control.protocolRecords(ServerControlStore.ENROLLMENT_ENDPOINT, offset, 128);
            for (ServerControlStore.ProtocolRecord record : page.values()) {
                Snapshot snapshot = decode(record);
                if (snapshot.active() && protocol(snapshot.endpoint()) == protocol) {
                    result.add(snapshot.endpoint());
                }
            }
            offset = page.nextOffset();
        } while (page.hasMore());
        return List.copyOf(result);
    }

    /**
     * Revalidates the exact endpoint and current active enrollment policy at admission.
     * The returned revision must be frozen by workflows that outlive this call.
     * @param endpoint configuration resolved for the incoming protocol request
     * @return exact current active endpoint snapshot
     * @throws IllegalStateException if removed, replaced, unbound, suspended, or unauthorized
     */
    public Snapshot requireCurrent(EnrollmentEndpoint endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            Snapshot snapshot = stored(protocol(endpoint), endpoint.label()).map(EnrollmentEndpointRegistry::decode)
                    .filter(Snapshot::active).orElseThrow(() -> new IllegalStateException("Enrollment endpoint is unavailable"));
            if (!snapshot.endpoint().equals(endpoint)) {
                throw new IllegalStateException("Enrollment endpoint changed");
            }
            requireBinding(endpoint, true);
            if (runtime != null) {
                runtime.validateEndpoint(endpoint);
            }
            return snapshot;
        }
    }

    // The caller holds the same control-store monitor used by endpoint registration.
    // This prevents a validated reverse-reference scan from racing with a new binding.
    /* default */ static void requireCompatibleProfile(ServerControlStore control, EnrollmentProfile replacement) {
        new zeroecho.pki.server.acme.AcmeControlStore(control).requireCompatibleEnrollmentProfile(replacement);
        int offset = 0;
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page;
        do {
            page = control.protocolRecords(ServerControlStore.ENROLLMENT_ENDPOINT, offset, 128);
            for (ServerControlStore.ProtocolRecord record : page.values()) {
                Snapshot snapshot = decode(record);
                EnrollmentEndpoint endpoint = snapshot.endpoint();
                if (snapshot.active() && endpoint.enrollmentProfileId().equals(replacement.id())
                        && (!endpoint.profileId().equals(replacement.certificateProfileId())
                        || !replacement.allowedAuthorityIds().isEmpty()
                        && !replacement.allowedAuthorityIds().contains(endpoint.authorityId()))) {
                    throw new IllegalStateException("Deregister incompatible enrollment endpoints before updating the profile");
                }
            }
            offset = page.nextOffset();
        } while (page.hasMore());
    }

    /**
     * Commits all endpoint fields independently of the storage revision.
     * @param endpoint complete proposed configuration
     * @return lowercase SHA-256 content commitment
     */
    public static String commitment(EnrollmentEndpoint endpoint) {
        return sha256(encode(Objects.requireNonNull(endpoint, "endpoint"), 1, true));
    }

    private void requireBinding(EnrollmentEndpoint endpoint, boolean requireActive) {
        EnrollmentProfile profile = profiles.find(endpoint.enrollmentProfileId())
                .orElseThrow(() -> new IllegalStateException("Enrollment endpoint policy is unavailable"));
        if (requireActive && profile.state() != EnrollmentProfileState.ACTIVE) {
            throw new IllegalStateException("Enrollment endpoint policy is suspended");
        }
        if (!profile.certificateProfileId().equals(endpoint.profileId())) {
            throw new IllegalStateException("Enrollment endpoint certificate profile differs from policy");
        }
        if (!profile.allowedAuthorityIds().isEmpty() && !profile.allowedAuthorityIds().contains(endpoint.authorityId())) {
            throw new IllegalStateException("Enrollment endpoint authority is not permitted");
        }
    }

    private Optional<ServerControlStore.ProtocolRecord> stored(Protocol protocol, String label) {
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(label, "label");
        if (!label.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalArgumentException("Invalid enrollment endpoint label");
        }
        return control.protocolRecord(ServerControlStore.ENROLLMENT_ENDPOINT, protocol.name() + ":" + label);
    }

    private Snapshot persist(EnrollmentEndpoint endpoint, long revision, boolean active, Optional<String> expected) {
        byte[] payload = encode(endpoint, revision, active);
        String digest = sha256(payload);
        ServerControlStore.ProtocolRecord record = new ServerControlStore.ProtocolRecord(
                ServerControlStore.ENROLLMENT_ENDPOINT, protocol(endpoint).name() + ":" + endpoint.label(), digest, payload);
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record, expected)));
        return new Snapshot(endpoint, revision, active, digest);
    }

    private static Protocol protocol(EnrollmentEndpoint endpoint) {
        return switch (endpoint) {
            case EstEndpoint ignored -> Protocol.EST;
            case ScepEndpoint ignored -> Protocol.SCEP;
            case CmpEndpoint ignored -> Protocol.CMP;
        };
    }

    private static byte[] encode(EnrollmentEndpoint endpoint, long revision, boolean active) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(VERSION);
            output.writeLong(revision);
            output.writeBoolean(active);
            write(output, protocol(endpoint).name());
            write(output, endpoint.label());
            write(output, endpoint.authorityId());
            write(output, endpoint.profileId());
            write(output, endpoint.enrollmentProfileId());
            switch (endpoint) {
                case EstEndpoint est -> {
                    KeygenPolicy policy = est.keygen();
                    if (policy.permittedAlgorithms().size() > MAXIMUM_ALGORITHM_COUNT) {
                        throw new IllegalArgumentException("Too many key algorithms");
                    }
                    output.writeBoolean(policy.enabled());
                    output.writeInt(policy.permittedAlgorithms().size());
                    for (String algorithm : policy.permittedAlgorithms()) {
                        write(output, algorithm);
                    }
                    output.writeInt(policy.maximumKeySizeBits());
                    output.writeBoolean(policy.storeGeneratedKeys());
                }
                case ScepEndpoint scep -> write(output, scep.challengePasswordHash());
                case CmpEndpoint cmp -> write(output, cmp.protectionPolicy().name());
            }
            output.flush();
            if (bytes.size() > MAXIMUM_PAYLOAD) {
                throw new IllegalArgumentException("Enrollment endpoint exceeds payload bound");
            }
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("Enrollment endpoint encoding failed", impossible);
        }
    }

    private static Snapshot decode(ServerControlStore.ProtocolRecord record) {
        byte[] payload = record.payload();
        if (payload.length > MAXIMUM_PAYLOAD || !sha256(payload).equals(record.commitment())) {
            throw corrupt();
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (input.readInt() != VERSION) {
                throw corrupt();
            }
            long revision = input.readLong();
            boolean active = input.readBoolean();
            Protocol protocol = Protocol.valueOf(read(input));
            String label = read(input);
            String authority = read(input);
            String certificateProfile = read(input);
            String enrollmentProfile = read(input);
            EnrollmentEndpoint endpoint = switch (protocol) {
                case EST -> {
                    yield new EstEndpoint(label, authority, certificateProfile, enrollmentProfile, readKeygenPolicy(input));
                }
                case SCEP -> new ScepEndpoint(label, authority, certificateProfile, enrollmentProfile, read(input));
                case CMP -> new CmpEndpoint(label, authority, certificateProfile, enrollmentProfile,
                        CmpProtectionPolicy.valueOf(read(input)));
            };
            if (!record.recordId().equals(protocol.name() + ":" + label) || input.read() != -1
                    || !Arrays.equals(payload, encode(endpoint, revision, active))) {
                throw corrupt();
            }
            return new Snapshot(endpoint, revision, active, record.commitment());
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalStateException("Enrollment endpoint record is corrupt or unsupported", failure);
        }
    }

    private static KeygenPolicy readKeygenPolicy(DataInputStream input) throws IOException {
        boolean enabled = input.readBoolean();
        int count = input.readInt();
        if (count < 0 || count > 16) {
            throw corrupt();
        }
        List<String> algorithms = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            algorithms.add(read(input));
        }
        return new KeygenPolicy(enabled, algorithms, input.readInt(), input.readBoolean());
    }

    private static void write(DataOutputStream output, String value) throws IOException {
        if (value.length() > MAXIMUM_TEXT_LENGTH) {
            throw new IllegalArgumentException("Enrollment endpoint string exceeds bound");
        }
        output.writeUTF(value);
        if (output.size() > MAXIMUM_PAYLOAD) {
            throw new IllegalArgumentException("Enrollment endpoint exceeds payload bound");
        }
    }

    private static String read(DataInputStream input) throws IOException {
        String value = input.readUTF();
        if (value.length() > MAXIMUM_TEXT_LENGTH) {
            throw corrupt();
        }
        return value;
    }

    private static String sha256(byte[] payload) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static IllegalStateException corrupt() {
        return new IllegalStateException("Enrollment endpoint record is corrupt or unsupported");
    }
}
