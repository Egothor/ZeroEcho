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
package zeroecho.pki.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.spi.crypto.ManagedKeyGeneration;

/**
 * Durable public receipts around one provider-owned generate-only capability.
 */
final class ManagedKeyGenerationService {
    private static final int MAGIC = 0x5a4d4b31;
    private static final int MAX_PUBLIC_BYTES = 16384;
    private final RealmId realm;
    private final Optional<String> initialAdministrator;
    private final ServerControlStore store;
    private final Optional<ManagedKeyGeneration> provider;
    private final ReentrantLock lane = new ReentrantLock();

    /**
     * Composes generate-only managed-key admission over durable public receipts.
     *
     * @param configuration trusted realm and configured initial administrator
     * @param store durable server-control authority
     * @param provider optional provider-owned generation/observation capability
     * @throws NullPointerException if a required reference is null
     */
    ManagedKeyGenerationService(ServerRealmConfiguration configuration, ServerControlStore store,
            Optional<ManagedKeyGeneration> provider) {
        this.realm = configuration.realmId();
        this.initialAdministrator = configuration.initialAdministratorPrincipalId();
        this.store = Objects.requireNonNull(store, "store");
        this.provider = Objects.requireNonNull(provider, "provider");
    }

    /**
     * Checks whether managed generation is configured and the initial administrator is durably pinned.
     *
     * @return whether both the provider capability and matching immutable administrator pin exist
     */
    boolean available() { return initialAdministrator.isPresent() && provider.isPresent() && pinned(); }

    /**
     * Requires the enabled pinned initial administrator and a configured generation provider.
     *
     * @param actor authenticated requesting principal
     * @throws SecurityException if the actor is not the enabled pinned initial administrator
     * @throws IllegalStateException if no generation provider is configured
     */
    void requireAdministrator(String actor) {
        if (!initialAdministrator.filter(actor::equals).isPresent() || !pinned() || !store.requirePrincipal(actor).enabled()) {
            throw new SecurityException("Managed key generation requires the initial administrator");
        }
        if (provider.isEmpty()) throw new IllegalStateException("MANAGED_KEY_GENERATION_NOT_CONFIGURED");
    }

    /**
     * Creates or checks the immutable realm-bound initial-administrator pin.
     *
     * @param configuration trusted realm and optional configured initial administrator
     * @param store durable server-control authority
     * @param administrator bootstrap-selected principal identity
     * @throws SecurityException if bootstrap identity differs from configuration or a retained pin
     */
    static void pinInitialAdministrator(ServerRealmConfiguration configuration, ServerControlStore store, String administrator) {
        if (configuration.initialAdministratorPrincipalId().isEmpty()) return;
        if (!configuration.initialAdministratorPrincipalId().orElseThrow().equals(administrator)) {
            throw new SecurityException("Configured initial administrator differs from bootstrap");
        }
        byte[] value = (configuration.realmId().value() + "\n" + administrator).getBytes(StandardCharsets.UTF_8);
        var existing = store.protocolRecord(ServerControlStore.MANAGED_KEY_GENERATION, "initial-administrator");
        if (existing.isPresent()) {
            if (!MessageDigest.isEqual(value, existing.orElseThrow().payload())) throw new SecurityException("Initial administrator is immutable");
            return;
        }
        store.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                ServerControlStore.MANAGED_KEY_GENERATION, "initial-administrator", digest(value), value), Optional.empty())));
    }

    private boolean pinned() {
        if (initialAdministrator.isEmpty()) return false;
        byte[] expected = (realm.value() + "\n" + initialAdministrator.orElseThrow()).getBytes(StandardCharsets.UTF_8);
        return store.protocolRecord(ServerControlStore.MANAGED_KEY_GENERATION, "initial-administrator")
                .filter(record -> MessageDigest.isEqual(expected, record.payload())).isPresent();
    }

    /**
     * Reserves, generates or observes one idempotently identified managed-key generation.
     *
     * <p>An ambiguous retained reservation is observed through the provider; it never
     * causes blind regeneration. Authorization is rechecked immediately before key creation.</p>
     *
     * @param generationId stable bounded generation identity
     * @param parameters exact supported key-generation parameter set
     * @param actor authenticated initial administrator principal
     * @return public managed-key result; no private key material is returned
     * @throws IllegalArgumentException if generation identity is invalid
     * @throws NullPointerException if parameters are null
     * @throws SecurityException if the actor is not the enabled pinned administrator
     * @throws IllegalStateException if configuration, capacity, concurrency, identity or reconciliation
     *         prerequisites fail
     */
    ManagedKeyGeneration.Result generate(String generationId, ManagedKeyGeneration.Parameters parameters, String actor) {
        Permission.requireId(generationId, "generation identity");
        Objects.requireNonNull(parameters, "parameters");
        requireAdministrator(actor);
        if (!lane.tryLock()) throw new IllegalStateException("MANAGED_KEY_GENERATION_BUSY");
        try {
            requireAdministrator(actor);
            String reservation = digest((realm.value() + "\n" + generationId).getBytes(StandardCharsets.UTF_8));
            Optional<ServerControlStore.ProtocolRecord> previous = store.protocolRecord(
                    ServerControlStore.MANAGED_KEY_GENERATION, reservation);
            if (previous.isPresent()) {
                Receipt receipt = decode(previous.orElseThrow().payload());
                if (!receipt.actor().equals(actor) || receipt.parameters() != parameters) {
                    throw new IllegalStateException("MANAGED_KEY_IDENTITY_CONFLICT");
                }
                if (receipt.result().isPresent()) return receipt.result().orElseThrow();
                // A durable claim may have reached cryptography. Observation must never become re-generation.
                ManagedKeyGeneration.Result result = provider.orElseThrow().observe(reservation, parameters)
                        .orElseThrow(() -> new IllegalStateException("MANAGED_KEY_RECONCILIATION_REQUIRED"));
                publish(reservation, actor, parameters, result, previous.orElseThrow());
                return result;
            }
            requireReservationCapacity();
            var claimed = record(reservation, new Receipt(actor, parameters, Optional.empty()));
            store.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(claimed, Optional.empty())));
            // Recheck current authorization after reservation, immediately before irreversible key creation.
            requireAdministrator(actor);
            ManagedKeyGeneration.Result result = provider.orElseThrow().generate(reservation, parameters);
            publish(reservation, actor, parameters, result, claimed);
            return result;
        } finally {
            lane.unlock();
        }
    }

    private void requireReservationCapacity() {
        int count = 0;
        try (var snapshot = store.protocolSnapshot(ServerControlStore.MANAGED_KEY_GENERATION)) {
            while (snapshot.next().isPresent()) {
                if (++count >= 1000) throw new IllegalStateException("MANAGED_KEY_QUOTA_EXCEEDED");
            }
        }
    }

    private void publish(String id, String actor, ManagedKeyGeneration.Parameters parameters,
            ManagedKeyGeneration.Result result, ServerControlStore.ProtocolRecord expected) {
        if (result.parameters() != parameters || result.subjectPublicKeyInfo().encoding() != Encoding.DER
                || result.subjectPublicKeyInfo().byteLength() > MAX_PUBLIC_BYTES) {
            throw new IllegalStateException("Managed key provider result differs from reservation");
        }
        store.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                record(id, new Receipt(actor, parameters, Optional.of(result))), Optional.of(expected.commitment()))));
    }

    private static ServerControlStore.ProtocolRecord record(String id, Receipt receipt) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(MAGIC); output.writeInt(1); output.writeUTF(receipt.actor());
                output.writeUTF(receipt.parameters().name()); output.writeBoolean(receipt.result().isPresent());
                if (receipt.result().isPresent()) {
                    var result = receipt.result().orElseThrow();
                    output.writeUTF(result.keyRef().value());
                    byte[] publicBytes = result.subjectPublicKeyInfo().bytes();
                    output.writeInt(publicBytes.length); output.write(publicBytes);
                }
            }
            byte[] encoded = bytes.toByteArray();
            return new ServerControlStore.ProtocolRecord(ServerControlStore.MANAGED_KEY_GENERATION, id, digest(encoded), encoded);
        } catch (IOException impossible) { throw new IllegalStateException("Managed key receipt encoding failed"); }
    }

    private static Receipt decode(byte[] encoded) {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readInt() != MAGIC || input.readInt() != 1) throw new IOException("Unsupported receipt");
            String actor = input.readUTF(); Permission.requirePrincipal(actor);
            ManagedKeyGeneration.Parameters parameters = ManagedKeyGeneration.Parameters.valueOf(input.readUTF());
            Optional<ManagedKeyGeneration.Result> result = Optional.empty();
            if (input.readBoolean()) {
                KeyRef ref = new KeyRef(input.readUTF());
                int length = input.readInt();
                if (length < 1 || length > MAX_PUBLIC_BYTES || input.available() != length) throw new IOException("Invalid public material");
                result = Optional.of(new ManagedKeyGeneration.Result(ref, parameters, new EncodedObject(Encoding.DER, input.readNBytes(length))));
            }
            if (input.available() != 0) throw new IOException("Trailing receipt data");
            return new Receipt(actor, parameters, result);
        } catch (IOException | IllegalArgumentException invalid) {
            throw new IllegalStateException("Managed key receipt is invalid");
        }
    }

    private static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private record Receipt(String actor, ManagedKeyGeneration.Parameters parameters,
            Optional<ManagedKeyGeneration.Result> result) { }
}
