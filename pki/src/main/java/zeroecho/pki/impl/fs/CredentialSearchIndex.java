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
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Predicate;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialSearchQuery;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;

/** Derived, disposable search projection; the filesystem credential authority remains authoritative. */
final class CredentialSearchIndex implements AutoCloseable { // NOPMD CyclomaticComplexity - One JDBC index owns visibility, reconciliation and query bounds; individual methods remain checked.
    private static final int EXPECTED_INSERTED_ROW_COUNT = 1;
    private static final int BATCH = 128;
    private static final ThreadLocal<Boolean> PUBLICATION_FAULT = new ThreadLocal<>();
    private final ReentrantLock visibility = new ReentrantLock();
    private final Connection connection;
    private final FsPkiStoreOptions.CredentialSearch options;
    private final CertificateReader certificates;
    private volatile boolean available; // NOPMD AvoidUsingVolatile - Publishes index failure to discovery readers that do not acquire the visibility lock.

    /** Reads an integrity-checked certificate from authoritative credential storage. */
    /* default */ @FunctionalInterface
    interface CertificateReader {
        /**
         * Reads the issued certificate for one credential.
         * @param credential authoritative credential metadata
         * @return issued X.509 certificate
         * @throws IOException if the stored object cannot be validated or read
         */
        X509Certificate read(Credential credential) throws IOException;
    }

    /* default */ CredentialSearchIndex(Path root, FsPkiStoreOptions.CredentialSearch options,
            CertificateReader certificates) throws IOException {
        this.options = Objects.requireNonNull(options, "options");
        this.certificates = Objects.requireNonNull(certificates, "certificates");
        Path directory = root.resolve("credential-search");
        if (Files.isSymbolicLink(directory)) {
            throw new IOException("Search directory must not be a symbolic link");
        }
        Files.createDirectories(directory);
        Path database = directory.resolve("index").toAbsolutePath().normalize();
        String location = database.toString();
        if (location.indexOf(';') >= 0 || location.indexOf('\n') >= 0 || location.indexOf('\r') >= 0) {
            throw new IOException("Search database location is unsupported");
        }
        for (String suffix : List.of(".mv.db", ".trace.db", ".lock.db")) {
            Path file = directory.resolve("index" + suffix);
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)
                    && (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(file))) {
                throw new IOException("Search database file is not a regular owned file");
            }
        }
        // Process ownership and authoritative recovery precede construction. The
        // derivative has no recoverable authority: discard it even if H2 cannot open it.
        for (String suffix : List.of(".mv.db", ".trace.db", ".lock.db")) {
            Files.deleteIfExists(directory.resolve("index" + suffix));
        }
        Connection opened = null;
        try {
            opened = new org.h2.Driver().connect("jdbc:h2:file:" + location
                    + ";AUTO_SERVER=FALSE;DB_CLOSE_ON_EXIT=FALSE;TRACE_LEVEL_FILE=0", new java.util.Properties());
            opened.setAutoCommit(false);
            try (Statement statement = opened.createStatement()) {
                statement.execute("SET CACHE_SIZE " + options.cacheKiB());
                statement.execute("SET QUERY_TIMEOUT " + options.queryTimeoutMillis());
                statement.execute("SET MAX_MEMORY_ROWS 128");
                statement.execute("SET LAZY_QUERY_EXECUTION TRUE");
                statement.execute("DROP ALL OBJECTS");
                statement.execute("CREATE TABLE credentials (id VARCHAR PRIMARY KEY, authority VARCHAR NOT NULL,"
                        + " subject_text VARCHAR NOT NULL, serial_text VARCHAR NOT NULL, id_lower VARCHAR NOT NULL,"
                        + " inventory_status VARCHAR NOT NULL, profile_id VARCHAR NOT NULL)");
                statement.execute("CREATE INDEX credentials_authority ON credentials(authority, id)");
                statement.execute("CREATE TABLE sans (credential_id VARCHAR NOT NULL, san_type VARCHAR NOT NULL,"
                        + " san_value VARCHAR NOT NULL, PRIMARY KEY(credential_id, san_type, san_value))");
                statement.execute("CREATE INDEX sans_exact ON sans(san_type, san_value, credential_id)");
            }
            opened.commit();
            connection = opened;
        } catch (SQLException failure) {
            if (opened != null) {
                try { opened.close(); } catch (SQLException ignored) { /* original failure remains authoritative */ }
            }
            throw new IOException("Search index initialization failed"); // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        }
    }

    /* default */ void rebuild(CredentialMetadataAuthority authority) throws IOException {
        int[] pending = {0};
        try {
            authority.validateAll(credential -> {
                insert(credential);
                if (++pending[0] == BATCH) {
                    commit();
                    pending[0] = 0;
                }
            });
            commit();
            available = true;
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            available = false;
            throw failure;
        }
    }

    /* default */ boolean available() { return available; }

    /* default */ void lockPublication() { visibility.lock(); }

    /* default */ void unlockPublication() { visibility.unlock(); }

    /** Called only after primary publication; never propagates derivative failure as an issuance failure. */
    /* default */ void published(Credential credential) {
        if (!available) {
            return;
        }
        try {
            if (Boolean.TRUE.equals(PUBLICATION_FAULT.get())) {
                throw new IOException("Injected derived publication failure");
            }
            insert(credential);
            commit();
        } catch (IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            available = false;
            try { connection.rollback(); } catch (SQLException ignored) { /* fenced until reopen */ }
        }
    }

    /* default */ void fence() { available = false; }

    /* default */ static void failPublicationForTest(boolean fail) {
        if (fail) {
            PUBLICATION_FAULT.set(Boolean.TRUE);
        }
        else {
            PUBLICATION_FAULT.remove();
        }
    }

    private void insert(Credential credential) throws IOException {
        List<SubjectAlternativeName> names = names(credential);
        String profile = switch (credential.profileBinding()) {
            case EndEntityProfileBinding binding -> binding.reference().profileId();
            case CaProfileBinding binding -> binding.reference().profileId();
        };
        try (Statement settings = connection.createStatement()) {
            settings.execute("SET QUERY_TIMEOUT " + options.queryTimeoutMillis());
        } catch (SQLException failure) { throw new IOException("Search index configuration failed"); } // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        try (PreparedStatement row = connection.prepareStatement("INSERT INTO credentials VALUES(?,?,?,?,?,?,?)");
                PreparedStatement san = connection.prepareStatement("MERGE INTO sans KEY(credential_id,san_type,san_value) VALUES(?,?,?)")) {
            row.setString(1, credential.credentialId().value());
            row.setString(2, credential.issuerRef().caId().value());
            row.setString(3, credential.subjectRef().value().toLowerCase(Locale.ROOT));
            row.setString(4, credential.serialOrUniqueId().toLowerCase(Locale.ROOT));
            row.setString(5, credential.credentialId().value().toLowerCase(Locale.ROOT));
            row.setString(6, credential.status().name());
            row.setString(7, profile);
            if (row.executeUpdate() != EXPECTED_INSERTED_ROW_COUNT) {
                throw new SQLException("Unexpected insert count");
            }
            for (SubjectAlternativeName name : names) {
                san.setString(1, credential.credentialId().value());
                san.setString(2, name.type().name());
                san.setString(3, value(name));
                san.executeUpdate();
            }
        } catch (SQLException failure) { // NOPMD ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            throw new IOException("Search index publication failed"); // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        }
    }

    private void commit() throws IOException {
        try { connection.commit(); }
        catch (SQLException failure) { throw new IOException("Search index commit failed"); } // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
    }

    /* default */ List<Credential> search(CredentialSearchQuery query, Optional<String> after, int limit,
            Function<PkiId, Optional<Credential>> load, Predicate<Credential> include, CancellationSignal cancellation,
            long deadline) {
        Objects.requireNonNull(query, "query");
        Objects.requireNonNull(after, "after");
        Objects.requireNonNull(load, "load");
        Objects.requireNonNull(include, "include");
        Objects.requireNonNull(cancellation, "cancellation");
        if (limit < 1 || limit > 1001) {
            throw new IllegalArgumentException("Search limit must be 1 through 1001");
        }
        SearchRequest request = new SearchRequest(query, limit, load, include, cancellation, deadline);
        boolean locked = false;
        try {
            while (!locked) {
                int remaining = remaining(deadline, cancellation);
                locked = visibility.tryLock(Math.min(remaining, 25), TimeUnit.MILLISECONDS);
            }
            if (!available) {
                throw new IllegalStateException("Credential search is unavailable");
            }
            return searchPages(request, after.orElse(""));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Restores caller cancellation after interruption; this standalone component creates no thread.
            throw new java.util.concurrent.CancellationException("Credential search cancelled"); // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        } catch (java.io.InterruptedIOException interrupted) {
            throw new java.util.concurrent.CancellationException("Credential search cancelled"); // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        } catch (SQLException | IOException failure) {
            if (cancellation.isCancelled()) {
                throw new java.util.concurrent.CancellationException("Credential search cancelled"); // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
            }
            throw new IllegalStateException("Credential search failed"); // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        } finally {
            if (locked) {
                visibility.unlock();
            }
        }
    }

    private List<Credential> searchPages(SearchRequest request, String initialCursor) throws SQLException, IOException {
        List<Credential> result = new ArrayList<>(request.limit());
        QueryPlan plan = queryPlan(request.query());
        String cursor = initialCursor;
        while (result.size() < request.limit()) {
            PageProgress page = appendPage(request, plan, cursor, result);
            cursor = page.cursor();
            if (page.count() < BATCH) {
                break;
            }
        }
        remaining(request.deadline(), request.cancellation());
        return List.copyOf(result);
    }

    private PageProgress appendPage(SearchRequest request, QueryPlan plan, String initialCursor,
            List<Credential> result) throws SQLException, IOException {
        try (Statement settings = connection.createStatement()) {
            settings.execute("SET QUERY_TIMEOUT " + remaining(request.deadline(), request.cancellation()));
        }
        String cursor = initialCursor;
        int count = 0;
        try (PreparedStatement statement = connection.prepareStatement(plan.sql())) {
            statement.setString(1, request.query().authorityId().value());
            statement.setString(2, cursor);
            for (int index = 0; index < plan.values().size(); index++) {
                statement.setString(index + 3, plan.values().get(index));
            }
            statement.setFetchSize(BATCH);
            try (ResultSet rows = statement.executeQuery()) {
                while (rows.next()) {
                    remaining(request.deadline(), request.cancellation());
                    cursor = rows.getString(1);
                    count++;
                    appendAuthorized(request, cursor, result);
                    remaining(request.deadline(), request.cancellation());
                    if (result.size() == request.limit()) {
                        break;
                    }
                }
            }
        }
        return new PageProgress(cursor, count);
    }

    private void appendAuthorized(SearchRequest request, String id, List<Credential> result) throws IOException {
        Credential credential = request.load().apply(new PkiId(id)).orElseThrow(this::inconsistent);
        if (!id.equals(credential.credentialId().value()) || !request.query().matchesMetadata(credential)) {
            throw inconsistent();
        }
        if (request.include().test(credential)) {
            if (request.query().sanFilter().isPresent()
                    && !names(credential).contains(request.query().sanFilter().orElseThrow())) {
                throw inconsistent();
            }
            result.add(credential);
        }
    }

    private static QueryPlan queryPlan(CredentialSearchQuery query) {
        StringBuilder sql = new StringBuilder(400).append("SELECT c.id FROM credentials c WHERE c.authority=? AND c.id>?");
        List<String> values = new ArrayList<>();
        if (query.subjectFilter().isPresent()) {
            sql.append(" AND LOCATE(?,c.subject_text)>0");
            values.add(lower(query.subjectFilter()));
        }
        if (query.serialFilter().isPresent()) {
            sql.append(" AND LOCATE(?,c.serial_text)>0");
            values.add(lower(query.serialFilter()));
        }
        if (query.fingerprintFilter().isPresent()) {
            sql.append(" AND LEFT(c.id_lower,CHAR_LENGTH(?))=?");
            values.add(lower(query.fingerprintFilter()));
            values.add(lower(query.fingerprintFilter()));
        }
        if (query.statusFilter().isPresent()) {
            sql.append(" AND c.inventory_status=?");
            values.add(query.statusFilter().orElseThrow());
        }
        if (query.profileIdFilter().isPresent()) {
            sql.append(" AND c.profile_id=?");
            values.add(query.profileIdFilter().orElseThrow());
        }
        if (query.sanFilter().isPresent()) {
            sql.append(" AND EXISTS(SELECT 1 FROM sans s WHERE s.credential_id=c.id AND s.san_type=? AND s.san_value=?)");
            values.add(query.sanFilter().orElseThrow().type().name());
            values.add(value(query.sanFilter().orElseThrow()));
        }
        sql.append(" ORDER BY c.id LIMIT 128");
        return new QueryPlan(sql.toString(), List.copyOf(values));
    }

    private record SearchRequest(CredentialSearchQuery query, int limit, Function<PkiId, Optional<Credential>> load,
            Predicate<Credential> include, CancellationSignal cancellation, long deadline) { }

    private record QueryPlan(String sql, List<String> values) { }

    private record PageProgress(String cursor, int count) { }

    private static int remaining(long deadline, CancellationSignal cancellation) throws IOException {
        cancellation.throwIfCancelled();
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) {
            throw new IllegalStateException("Credential search deadline exceeded");
        }
        return (int) Math.max(1, TimeUnit.NANOSECONDS.toMillis(nanos));
    }

    private static String lower(Optional<String> value) { return value.orElseThrow().toLowerCase(Locale.ROOT); }

    private IllegalStateException inconsistent() {
        available = false;
        return new IllegalStateException("Credential search index is inconsistent; reopen is required");
    }

    private List<SubjectAlternativeName> names(Credential credential) throws IOException {
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
            return List.of();
        }
        if (credential.content().length() <= 0 || credential.content().length() > options.maximumCertificateBytes()) {
            throw new IOException("Search certificate exceeds configured limit");
        }
        try {
            Collection<List<?>> names = certificates.read(credential).getSubjectAlternativeNames();
            if (names == null) {
                return List.of();
            }
            List<SubjectAlternativeName> result = new ArrayList<>();
            for (List<?> name : names) {
                if (name.size() != 2 || !(name.getFirst() instanceof Integer type)) {
                    throw new IOException("Malformed certificate SAN");
                }
                SubjectAlternativeName supported = decodeSan(type, name.get(1));
                if (supported != null) {
                    result.add(supported);
                }
            }
            return List.copyOf(result);
        } catch (CertificateParsingException | IllegalArgumentException | ClassCastException malformed) {
            throw new IOException("Search certificate SAN is invalid"); // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        }
    }

    private static SubjectAlternativeName decodeSan(int type, Object value) {
        return switch (type) {
            case 1 -> new SubjectAlternativeName.Rfc822Name((String) value);
            case 2 -> new SubjectAlternativeName.DnsName((String) value);
            case 6 -> new SubjectAlternativeName.UriName((String) value);
            case 7 -> new SubjectAlternativeName.IpAddress(InetAddress.ofLiteral((String) value).getAddress());
            default -> null;
        };
    }

    private static String value(SubjectAlternativeName name) {
        return switch (name) {
            case SubjectAlternativeName.DnsName dns -> dns.value();
            case SubjectAlternativeName.IpAddress ip -> HexFormat.of().formatHex(ip.bytes());
            case SubjectAlternativeName.UriName uri -> uri.value();
            case SubjectAlternativeName.Rfc822Name mailbox -> mailbox.value();
        };
    }

    @Override
    public void close() throws IOException {
        visibility.lock();
        try {
            available = false;
            try { connection.close(); }
            catch (SQLException failure) { throw new IOException("Search index close failed"); } // NOPMD PreserveStackTrace - Search failures omit SQL values, stored certificate content and provider diagnostics.
        } finally { visibility.unlock(); }
    }
}
