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
package zeroecho.pki.impl.publish;

import java.nio.file.Path;
import java.util.Set;

import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.publish.Publisher;
import zeroecho.pki.spi.publish.PublisherProvider;

/** Explicit filesystem publication-destination provider. */
public final class FilesystemPublisherProvider implements PublisherProvider {
    private static final String ROOT = "root";
    private static final String TARGET_ID = "targetId";

    /** Creates a filesystem publisher provider descriptor. */
    public FilesystemPublisherProvider() {
        // Stateless provider descriptor.
    }

    @Override
    public String id() {
        return "filesystem";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of(ROOT, TARGET_ID);
    }

    @Override
    public void validateConfig(ProviderConfig config) {
        PublisherProvider.super.validateConfig(config);
        Path.of(config.require(ROOT));
        new PublicationTarget(PublicationTargetType.FILESYSTEM, config.require(TARGET_ID));
    }

    @Override
    public Publisher allocate(ProviderConfig config) {
        validateConfig(config);
        PublicationTarget target = new PublicationTarget(PublicationTargetType.FILESYSTEM,
                config.require(TARGET_ID));
        return new FilesystemPublisher(target, Path.of(config.require(ROOT)));
    }
}
