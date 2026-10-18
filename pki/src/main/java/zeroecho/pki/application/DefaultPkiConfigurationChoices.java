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
package zeroecho.pki.application;

import java.util.List;
import java.util.Optional;
import java.util.TreeSet;
import java.util.function.Consumer;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSigningProvider;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;

/** Borrowed runtime metadata; owns no provider, store, keyring, or lifecycle. */
final class DefaultPkiConfigurationChoices implements PkiConfigurationChoicesSource {
    private final List<KeyRef> configuredKeys;
    private final PkiStore store;
    private final Optional<SigningProvider> provider;
    private final List<PublicationTarget> targets;
    private final Runnable openCheck;

    /* default */ DefaultPkiConfigurationChoices(PkiSessionConfiguration configuration, PkiStore store,
            Optional<SigningProvider> provider, List<PublicationTarget> targets, Runnable openCheck) {
        this(configuration.signing().stream().flatMap(signing -> signing.topology().exactGroups().stream())
                .flatMap(group -> group.keyRefs().stream()).toList(), store, provider, targets, openCheck);
    }

    /* default */ DefaultPkiConfigurationChoices(List<KeyRef> configuredKeys, PkiStore store,
            Optional<SigningProvider> provider, List<PublicationTarget> targets, Runnable openCheck) {
        this.configuredKeys = List.copyOf(configuredKeys);
        this.store = store;
        this.provider = provider;
        this.targets = List.copyOf(targets);
        this.openCheck = openCheck;
    }

    @Override
    public Choices configurationChoices(int limit, Optional<String> after, CancellationSignal cancellation) {
        openCheck.run();
        if (limit < 1 || limit > 1000) { throw new IllegalArgumentException("Key page limit must be 1 through 1000"); }
        java.util.Objects.requireNonNull(after, "after").ifPresent(KeyRef::new);
        java.util.Objects.requireNonNull(cancellation, "cancellation");
        if (cancellation.isCancelled()) { throw new java.util.concurrent.CancellationException("Configuration selection cancelled"); }
        java.util.NavigableSet<String> selected = new TreeSet<>();
        Consumer<KeyRef> consider = key -> {
            if (cancellation.isCancelled()) { throw new java.util.concurrent.CancellationException("Configuration selection cancelled"); }
            String id = key.value();
            if (after.isPresent() && id.compareTo(after.orElseThrow()) <= 0) { return; }
            selected.add(id);
            if (selected.size() > limit + 1) { selected.pollLast(); }
        };
        configuredKeys.forEach(consider);
        provider.filter(ZeroEchoLibSigningProvider.class::isInstance)
                .map(ZeroEchoLibSigningProvider.class::cast).ifPresent(local -> local.visitKnownKeyReferences(consider));
        store.visitAuthorityKeyReferences(consider, cancellation);
        boolean more = selected.size() > limit;
        if (more) { selected.pollLast(); }
        Optional<String> next = more ? Optional.of(selected.last()) : Optional.empty();
        return new Choices(List.of(BcX509CredentialFramework.FORMAT_ID),
                provider.map(value -> List.of(value.id())).orElseGet(List::of), targets,
                selected.stream().map(KeyRef::new).toList(), next,
                provider.map(value -> value.supportedAlgorithms().stream().sorted().toList()).orElseGet(List::of));
    }
}
