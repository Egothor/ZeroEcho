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

package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.application.PkiSessionConfiguration.SigningCoordinatorLimits;
import zeroecho.pki.application.PkiSessionConfiguration.SigningKeyGroup;
import zeroecho.pki.application.PkiSessionConfiguration.SigningLanePool;
import zeroecho.pki.application.PkiSessionConfiguration.SigningTopology;
import zeroecho.pki.spi.ProviderConfig;

final class PkiSessionConfigurationSigningTopologyTest {
    private static final Duration PROVIDER_TIMEOUT = Duration.ofSeconds(5L);
    private static final Duration CLAIM_LEASE = Duration.ofSeconds(6L);
    private static final Duration IDLE_POLL = Duration.ofMillis(1L);
    private static final Duration CLOSE_TIMEOUT = Duration.ofSeconds(2L);

    @Test
    void currentVersionSixSigningConfigurationCarriesValidatedTopology() {
        SigningTopology topology = new SigningTopology(coordinator(1), List.of(),
                new SigningLanePool(1, 1));
        PkiSessionConfiguration.SigningConfiguration signing =
                new PkiSessionConfiguration.SigningConfiguration(
                        new ProviderConfig("signing-provider", Map.of()), "SHA256withRSA",
                        Duration.ofMinutes(1L), Optional.empty(), topology, OptionalLong.empty());

        assertEquals(6, PkiSessionConfiguration.CURRENT_VERSION);
        assertEquals(topology, signing.topology());
    }

    @Test
    void resolvesExplicitAndFiftyPercentConcurrencyAwarePureEdDsaLimits() {
        SigningTopology oneLane = new SigningTopology(coordinator(1), List.of(),
                new SigningLanePool(1, 1));
        PkiSessionConfiguration.SigningConfiguration automatic = signing(oneLane, OptionalLong.empty());
        long fourGiB = 4L * 1024L * 1024L * 1024L;

        assertEquals((fourGiB / 2L - 16L * 1024L) / 3L,
                automatic.resolvePureEdDsaMaximumTbsBytes(fourGiB));

        SigningKeyGroup threeLanes = new SigningKeyGroup(List.of(new KeyRef("exact-a")),
                new SigningLanePool(3, 3));
        SigningTopology fourLanes = new SigningTopology(coordinator(4), List.of(threeLanes),
                new SigningLanePool(1, 1));
        assertEquals((fourGiB / 2L / 4L - 16L * 1024L) / 3L,
                signing(fourLanes, OptionalLong.empty()).resolvePureEdDsaMaximumTbsBytes(fourGiB));
        assertEquals(900_000_000L,
                signing(fourLanes, OptionalLong.of(900_000_000L))
                        .resolvePureEdDsaMaximumTbsBytes(1L));
        assertEquals(Integer.MAX_VALUE - 8L,
                signing(oneLane, OptionalLong.of(Integer.MAX_VALUE - 8L))
                        .resolvePureEdDsaMaximumTbsBytes(1L));
        assertEquals(Integer.MAX_VALUE - 8L,
                automatic.resolvePureEdDsaMaximumTbsBytes(Long.MAX_VALUE));
        assertEquals(4, fourLanes.totalLaneCount());
    }

    @Test
    void rejectsInvalidPureEdDsaLimitInputs() {
        SigningTopology topology = new SigningTopology(coordinator(1), List.of(),
                new SigningLanePool(1, 1));

        assertThrows(NullPointerException.class, () -> new PkiSessionConfiguration.SigningConfiguration(
                new ProviderConfig("signing-provider", Map.of()), "Ed25519", Duration.ofMinutes(1L),
                Optional.empty(), topology, null));
        assertThrows(IllegalArgumentException.class, () -> signing(topology, OptionalLong.of(0L)));
        assertThrows(IllegalArgumentException.class,
                () -> signing(topology, OptionalLong.of(Integer.MAX_VALUE)));
        assertThrows(IllegalArgumentException.class,
                () -> signing(topology, OptionalLong.empty()).resolvePureEdDsaMaximumTbsBytes(0L));
        assertThrows(IllegalArgumentException.class,
                () -> signing(topology, OptionalLong.empty()).resolvePureEdDsaMaximumTbsBytes(32L * 1024L));
    }

    private static PkiSessionConfiguration.SigningConfiguration signing(
            SigningTopology topology, OptionalLong maximum) {
        return new PkiSessionConfiguration.SigningConfiguration(
                new ProviderConfig("signing-provider", Map.of()), "Ed25519",
                Duration.ofMinutes(1L), Optional.empty(), topology, maximum);
    }

    @Test
    void acceptsEmptyExactGroupsAndSnapshotsEveryList() {
        List<KeyRef> mutableKeys = new ArrayList<>(List.of(new KeyRef("key-sensitive")));
        SigningKeyGroup group = new SigningKeyGroup(mutableKeys, new SigningLanePool(1, 2));
        List<SigningKeyGroup> mutableGroups = new ArrayList<>(List.of(group));
        SigningTopology topology = new SigningTopology(coordinator(3), mutableGroups,
                new SigningLanePool(1, 1));

        mutableKeys.clear();
        mutableGroups.clear();

        assertEquals(List.of(new KeyRef("key-sensitive")),
                topology.exactGroups().getFirst().keyRefs());
        assertThrows(UnsupportedOperationException.class,
                () -> topology.exactGroups().add(group));
        assertThrows(UnsupportedOperationException.class,
                () -> topology.exactGroups().getFirst().keyRefs().add(new KeyRef("other")));
        assertEquals(new SigningTopology(coordinator(1), List.of(), new SigningLanePool(1, 1)),
                new SigningTopology(coordinator(1), List.of(), new SigningLanePool(1, 1)));
    }

    @Test
    void rejectsMissingOrInvalidTopologyPartsAndDuplicateKeys() {
        SigningLanePool pool = new SigningLanePool(1, 1);
        KeyRef secret = new KeyRef("duplicate-sensitive-key");

        assertThrows(NullPointerException.class,
                () -> new SigningTopology(null, List.of(), pool));
        assertThrows(NullPointerException.class,
                () -> new SigningTopology(coordinator(1), null, pool));
        assertThrows(NullPointerException.class,
                () -> new SigningTopology(coordinator(1), List.of(), null));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningKeyGroup(List.of(), pool));
        assertThrows(NullPointerException.class,
                () -> new SigningKeyGroup(List.of(secret), null));
        assertThrows(NullPointerException.class,
                () -> new SigningKeyGroup(new ArrayList<>(java.util.Arrays.asList(secret, null)), pool));

        IllegalArgumentException within = assertThrows(IllegalArgumentException.class,
                () -> new SigningKeyGroup(List.of(secret, secret), pool));
        SigningKeyGroup first = new SigningKeyGroup(List.of(secret), pool);
        SigningKeyGroup second = new SigningKeyGroup(List.of(secret), pool);
        IllegalArgumentException across = assertThrows(IllegalArgumentException.class,
                () -> new SigningTopology(coordinator(2), List.of(first, second), pool));

        assertFalse(within.getMessage().contains(secret.value()));
        assertFalse(across.getMessage().contains(secret.value()));
    }

    @Test
    void enforcesPerPoolAndAggregateLaneAndPrefetchBounds() {
        assertThrows(IllegalArgumentException.class, () -> new SigningLanePool(0, 1));
        assertThrows(IllegalArgumentException.class, () -> new SigningLanePool(257, 1));
        assertThrows(IllegalArgumentException.class, () -> new SigningLanePool(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new SigningLanePool(1, 4097));
        assertEquals(new SigningLanePool(256, 4096), new SigningLanePool(256, 4096));

        SigningKeyGroup oneLane = new SigningKeyGroup(List.of(new KeyRef("exact-a")),
                new SigningLanePool(1, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningTopology(coordinator(1), List.of(oneLane),
                        new SigningLanePool(256, 1)));
        SigningKeyGroup onePrefetch = new SigningKeyGroup(List.of(new KeyRef("exact-b")),
                new SigningLanePool(1, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningTopology(coordinator(1), List.of(onePrefetch),
                        new SigningLanePool(1, 4096)));

        SigningKeyGroup exactMaximum = new SigningKeyGroup(uniqueKeys(4096),
                new SigningLanePool(1, 1));
        new SigningTopology(coordinator(1), List.of(exactMaximum), new SigningLanePool(1, 1));
        SigningKeyGroup overflowKey = new SigningKeyGroup(List.of(new KeyRef("overflow-key")),
                new SigningLanePool(1, 1));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningTopology(coordinator(1), List.of(exactMaximum, overflowKey),
                        new SigningLanePool(1, 1)));
    }

    @Test
    void rejectsOversizedTopologyCollectionsBeforeTraversalCopyOrHashing() {
        SigningLanePool pool = new SigningLanePool(1, 1);

        assertThrows(IllegalArgumentException.class,
                () -> new SigningKeyGroup(new NonTraversableList<>(4097), pool));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningTopology(coordinator(1),
                        new NonTraversableList<>(256), pool));
    }

    @Test
    void enforcesUtf8KeyReferenceBytesAtMultibyteAndSurrogateBoundaries() {
        SigningLanePool pool = new SigningLanePool(1, 1);
        String threeByteMaximum = "\u20ac".repeat(349_525) + 'a';
        String supplementaryMaximum = "\ud83d\ude00".repeat(262_144);

        new SigningKeyGroup(List.of(new KeyRef(threeByteMaximum)), pool);
        new SigningKeyGroup(List.of(new KeyRef(supplementaryMaximum)), pool);
        assertThrows(IllegalArgumentException.class,
                () -> new SigningKeyGroup(
                        List.of(new KeyRef(threeByteMaximum + 'a')), pool));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningKeyGroup(
                        List.of(new KeyRef(supplementaryMaximum + 'a')), pool));

        String malformedSurrogates = "x\ud800y\udc00z";
        assertEquals(malformedSurrogates.getBytes(java.nio.charset.StandardCharsets.UTF_8).length,
                new KeyRef(malformedSurrogates).utf8Length());
    }

    @Test
    void enforcesPageAndDurationBoundsIncludingAggregatePrefetch() {
        assertThrows(IllegalArgumentException.class,
                () -> limits(0, CLAIM_LEASE, PROVIDER_TIMEOUT, IDLE_POLL, CLOSE_TIMEOUT));
        assertThrows(IllegalArgumentException.class,
                () -> limits(4097, CLAIM_LEASE, PROVIDER_TIMEOUT, IDLE_POLL, CLOSE_TIMEOUT));
        assertThrows(NullPointerException.class,
                () -> limits(1, null, PROVIDER_TIMEOUT, IDLE_POLL, CLOSE_TIMEOUT));
        assertThrows(IllegalArgumentException.class,
                () -> limits(1, Duration.ZERO, PROVIDER_TIMEOUT, IDLE_POLL, CLOSE_TIMEOUT));
        assertThrows(IllegalArgumentException.class,
                () -> limits(1, CLAIM_LEASE, Duration.ofSeconds(-1L), IDLE_POLL, CLOSE_TIMEOUT));
        assertThrows(IllegalArgumentException.class,
                () -> limits(1, CLAIM_LEASE, PROVIDER_TIMEOUT, Duration.ofNanos(999_999L),
                        CLOSE_TIMEOUT));
        assertThrows(IllegalArgumentException.class,
                () -> limits(1, CLAIM_LEASE, PROVIDER_TIMEOUT, IDLE_POLL,
                        Duration.ofDays(1L).plusNanos(1L)));
        assertThrows(IllegalArgumentException.class,
                () -> limits(1, PROVIDER_TIMEOUT, PROVIDER_TIMEOUT, IDLE_POLL, CLOSE_TIMEOUT));

        SigningCoordinatorLimits maximumDurations = limits(4096, Duration.ofDays(1L),
                Duration.ofDays(1L).minusNanos(1L), Duration.ofDays(1L), Duration.ofDays(1L));
        assertEquals(4096, maximumDurations.pageSize());
        assertThrows(IllegalArgumentException.class,
                () -> new SigningTopology(coordinator(3), List.of(), new SigningLanePool(1, 2)));
        assertEquals(3, new SigningTopology(coordinator(3), List.of(),
                new SigningLanePool(1, 3)).coordinator().pageSize());
    }

    @Test
    void redactsEveryKeyFromGroupAndTopologyDiagnostics() {
        String secret = "never-render-this-key";
        SigningKeyGroup group = new SigningKeyGroup(List.of(new KeyRef(secret)),
                new SigningLanePool(1, 1));
        SigningTopology topology = new SigningTopology(coordinator(1), List.of(group),
                new SigningLanePool(1, 1));

        assertFalse(group.toString().contains(secret));
        assertFalse(topology.toString().contains(secret));
    }

    private static SigningCoordinatorLimits coordinator(int pageSize) {
        return limits(pageSize, CLAIM_LEASE, PROVIDER_TIMEOUT, IDLE_POLL, CLOSE_TIMEOUT);
    }

    private static SigningCoordinatorLimits limits(int pageSize, Duration claimLease,
            Duration providerTimeout, Duration idlePoll, Duration closeTimeout) {
        return new SigningCoordinatorLimits(pageSize, claimLease, providerTimeout, idlePoll,
                closeTimeout);
    }

    private static List<KeyRef> uniqueKeys(int count) {
        List<KeyRef> keys = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            keys.add(new KeyRef("key-" + index));
        }
        return keys;
    }

    private static final class NonTraversableList<T> extends AbstractList<T> {
        private final int size;

        private NonTraversableList(int size) {
            this.size = size;
        }

        @Override public T get(int index) {
            throw new AssertionError("oversized list must not be traversed");
        }

        @Override public int size() {
            return size;
        }

        @Override public Iterator<T> iterator() {
            throw new AssertionError("oversized list must not allocate an iterator");
        }

        @Override public Object[] toArray() {
            throw new AssertionError("oversized list must not be copied");
        }

        @Override public int hashCode() {
            throw new AssertionError("oversized list must not be hashed");
        }
    }
}
