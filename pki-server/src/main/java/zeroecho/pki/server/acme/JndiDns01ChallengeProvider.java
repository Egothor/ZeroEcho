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
package zeroecho.pki.server.acme;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Production DNS-01 validator using one explicit absolute-name JNDI DNS resolver. */
@SuppressWarnings("PMD")
public final class JndiDns01ChallengeProvider implements AcmeChallengeProvider {
    /** Stable built-in provider identity. */
    public static final String ID = "zeroecho.dns-01.jndi.v1";

    /** Creates the stateless built-in JNDI DNS-01 challenge provider. */
    public JndiDns01ChallengeProvider() {
    }

    @Override public String id() { return ID; }
    @Override public Set<AcmeState.ChallengeType> challengeTypes() { return Set.of(AcmeState.ChallengeType.DNS_01); }

    @Override
    public Result validate(Context context, ProviderConfig configuration, CancellationSignal cancellation) {
        Settings settings = settings(configuration);
        String expected = digest(context.expectedKeyAuthorization());
        String name = "_acme-challenge." + context.identifier().value() + ".";
        try {
            Set<String> seen = new HashSet<>();
            for (int depth = 0; ; depth++) {
                cancellation.throwIfCancelled();
                if (!seen.add(name) || depth > settings.maximumCnameDepth()) {
                    return invalid(context, "DNS_DELEGATION_REJECTED");
                }
                Lookup lookup = lookup(name, settings);
                for (String value : lookup.txt()) {
                    if (MessageDigestSupport.equalAscii(value, expected)) return valid(context);
                }
                if (lookup.cname().isEmpty() || depth == settings.maximumCnameDepth()) {
                    return invalid(context, "DNS_VALUE_MISMATCH");
                }
                name = canonicalAbsolute(lookup.cname().get(0));
            }
        } catch (Exception failure) {
            return invalid(context, "DNS_VALIDATION_FAILED");
        }
    }

    private static Lookup lookup(String name, Settings settings) throws Exception {
        Hashtable<String, String> environment = new Hashtable<>();
        environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        environment.put("java.naming.provider.url", settings.providerUrl());
        environment.put("com.sun.jndi.dns.timeout.initial", Integer.toString(settings.timeoutMillis()));
        environment.put("com.sun.jndi.dns.timeout.retries", "1");
        DirContext context = new InitialDirContext(environment);
        try {
            Attributes attributes = context.getAttributes(name, new String[] { "TXT", "CNAME" });
            List<String> txt = values(attributes.get("TXT"), settings.maximumRecords(), settings.maximumRecordBytes(), true);
            List<String> cname = values(attributes.get("CNAME"), 1, 253, false);
            return new Lookup(txt, cname);
        } finally {
            context.close();
        }
    }

    private static List<String> values(Attribute attribute, int maximum, int maximumBytes, boolean txt) throws Exception {
        if (attribute == null) return List.of(); List<String> result = new ArrayList<>();
        NamingEnumeration<?> values = attribute.getAll();
        try {
            while (values.hasMore()) {
                if (result.size() >= maximum) throw new IllegalArgumentException("DNS record bound exceeded");
                String value = String.valueOf(values.next());
                String canonical = txt ? txt(value) : value;
                if (canonical.getBytes(StandardCharsets.US_ASCII).length > maximumBytes) {
                    throw new IllegalArgumentException("DNS record size exceeded");
                }
                result.add(canonical);
            }
        } finally {
            values.close();
        }
        return List.copyOf(result);
    }

    private static String txt(String value) {
        StringBuilder result = new StringBuilder(); int index = 0;
        while (index < value.length()) {
            while (index < value.length() && value.charAt(index) == ' ') index++;
            if (index >= value.length() || value.charAt(index++) != '"') throw new IllegalArgumentException("DNS TXT framing invalid");
            while (index < value.length() && value.charAt(index) != '"') {
                char character = value.charAt(index++);
                if (character == '\\' || character < 0x21 || character > 0x7e) throw new IllegalArgumentException("DNS TXT value invalid");
                result.append(character);
            }
            if (index >= value.length() || value.charAt(index++) != '"') throw new IllegalArgumentException("DNS TXT framing invalid");
        }
        return result.toString();
    }

    private static String canonicalAbsolute(String value) {
        String lower = value.toLowerCase(java.util.Locale.ROOT);
        if (!lower.endsWith(".") || lower.length() > 254 || !lower.matches("[a-z0-9.-]+\\.")) {
            throw new IllegalArgumentException("DNS CNAME is invalid");
        }
        return lower;
    }

    private static Settings settings(ProviderConfig config) {
        if (!ID.equals(config.backendId()) || !Set.of("providerUrl", "timeoutMillis", "maximumRecords",
                "maximumRecordBytes", "maximumCnameDepth").equals(config.properties().keySet())) {
            throw new IllegalArgumentException("DNS-01 provider configuration is invalid");
        }
        String providerUrl = config.require("providerUrl");
        if (!providerUrl.matches("dns://[0-9A-Fa-f:.]+(?::[0-9]{1,5})?/?")) {
            throw new IllegalArgumentException("DNS resolver URL is invalid");
        }
        return new Settings(providerUrl, integer(config, "timeoutMillis", 100, 60_000),
                integer(config, "maximumRecords", 1, 64), integer(config, "maximumRecordBytes", 43, 4_096),
                integer(config, "maximumCnameDepth", 0, 8));
    }
    private static int integer(ProviderConfig config, String key, int minimum, int maximum) {
        try { int value = Integer.parseInt(config.require(key)); if (value < minimum || value > maximum) throw new NumberFormatException(); return value; }
        catch (NumberFormatException failure) { throw new IllegalArgumentException("DNS-01 provider bound is invalid"); }
    }
    private static String digest(String value) { try { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII))); } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); } }
    private static Result valid(Context context) { Instant now = context.validationTime(); return new Result(true, "VALID", now, now.plus(Duration.ofHours(1))); }
    private static Result invalid(Context context, String code) { Instant now = context.validationTime(); return new Result(false, code, now, now.plus(Duration.ofMinutes(5))); }
    private record Settings(String providerUrl, int timeoutMillis, int maximumRecords, int maximumRecordBytes, int maximumCnameDepth) { }
    private record Lookup(List<String> txt, List<String> cname) { }
}
