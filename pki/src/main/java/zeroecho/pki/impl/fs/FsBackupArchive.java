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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.backup.BackupLimits;
import zeroecho.pki.api.backup.BackupSink;
import zeroecho.pki.api.backup.BackupSource;

/** Version-1 envelope; ZIP32 regular files, STORED or DEFLATED, no extra fields. */
final class FsBackupArchive { // NOPMD CyclomaticComplexity - Aggregate lifecycle/coordinator complexity; individual methods remain checked.
    private static final String FORMAT = "zeroecho-pki-backup";
    private static final int VERSION = 1;
    private static final int UTF8_FLAG = 0x800;
    private static final int DESCRIPTOR_FLAG = 8;
    private static final int CENTRAL_SIGNATURE = 0x02014b50;
    private FsBackupArchive() { }

    /* default */ record Item(String path, long length, long crc, byte[] digest, long modifiedMillis) { }
    /* default */ record Entry(String path, long length, long compressed, long crc, int method,
            int flags, long offset, long dataOffset) { }
    /* default */ record Manifest(PkiId id, Instant createdAt, List<Item> items, String digest) { }

    /* default */ static BackupSource write(Path frozen, Path work, PkiId id, Instant instant, BackupLimits limits)
            throws IOException {
        List<Item> items = inventory(frozen, limits);
        Path manifest = frozen.resolve(FsBackupFiles.MANIFEST);
        try (OutputStream file = Files.newOutputStream(manifest, StandardOpenOption.CREATE_NEW);
                DataOutputStream output = new DataOutputStream(new LimitedOutput(file, limits.manifestBytes()))) {
            output.writeUTF(FORMAT);
            output.writeInt(VERSION);
            output.writeUTF(FilesystemPkiStore.CURRENT_STORE_VERSION);
            output.writeUTF(id.value());
            output.writeLong(instant.getEpochSecond());
            output.writeInt(instant.getNano());
            output.writeInt(items.size());
            for (Item item : items) {
                output.writeUTF(item.path());
                output.writeLong(item.length());
                output.write(item.digest());
                output.writeLong(item.modifiedMillis());
            }
        }
        List<Item> complete = new ArrayList<>(items);
        complete.add(measure(frozen, manifest, limits));
        complete.sort(Comparator.comparing(Item::path));
        long total = 0;
        for (Item item : complete) {
            if (item.length() > limits.expandedBytes() - total) { throw FsBackupFiles.invalid("BACKUP_EXPANDED_LIMIT"); }
            total += item.length();
        }
        FsBackupFiles.forceTree(frozen);
        try (BackupSink sink = BackupSink.create(work, id, limits)) {
            try (ZipOutputStream zip = new ZipOutputStream(sink.outputStream(), StandardCharsets.UTF_8)) {
                for (Item item : complete) {
                    ZipEntry entry = new ZipEntry(item.path()); // NOPMD AvoidInstantiatingObjectsInLoops - Each ZIP entry needs distinct per-record metadata.
                    entry.setMethod(ZipEntry.STORED);
                    entry.setSize(item.length());
                    entry.setCompressedSize(item.length());
                    entry.setCrc(item.crc());
                    zip.putNextEntry(entry);
                    try (InputStream input = Files.newInputStream(frozen.resolve(item.path()))) {
                        FsBackupFiles.copyExact(input, zip, item.length());
                    }
                    zip.closeEntry();
                }
            }
            return sink.complete();
        }
    }

    private static List<Item> inventory(Path root, BackupLimits limits) throws IOException {
        List<Item> items = new ArrayList<>();
        FsBackupFiles.Inventory names = new FsBackupFiles.Inventory();
        FsBackupFiles.Budget budget = new FsBackupFiles.Budget(limits);
        try (java.util.stream.Stream<Path> walker = Files.walk(root)) {
            java.util.Iterator<Path> iterator = walker.iterator();
            while (iterator.hasNext()) {
                Path path = iterator.next();
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) { continue; }
                String relative = root.relativize(path).toString().replace(java.io.File.separatorChar, '/');
                names.add(relative, limits);
                Item item = measure(root, path, limits);
                budget.add(item.length());
                items.add(item);
            }
        }
        items.sort(Comparator.comparing(Item::path));
        return items;
    }

    private static Item measure(Path root, Path path, BackupLimits limits) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { throw FsBackupFiles.invalid("BACKUP_SOURCE_TYPE"); }
        long length = Files.size(path);
        if (length > limits.entryBytes()) { throw FsBackupFiles.invalid("BACKUP_ENTRY_LIMIT"); }
        MessageDigest digest = FsBackupFiles.digest();
        CRC32 crc = new CRC32();
        byte[] buffer = new byte[FsBackupFiles.BUFFER_BYTES];
        long read = 0;
        try (InputStream input = Files.newInputStream(path)) {
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count == 0 || count > length - read) { throw FsBackupFiles.invalid("BACKUP_LENGTH"); }
                digest.update(buffer, 0, count);
                crc.update(buffer, 0, count);
                read += count;
            }
        }
        if (read != length) { throw FsBackupFiles.invalid("BACKUP_LENGTH"); }
        return new Item(root.relativize(path).toString().replace(java.io.File.separatorChar, '/'),
                length, crc.getValue(), digest.digest(), Files.getLastModifiedTime(path).toMillis());
    }

    /* default */ static List<Entry> directory(Path archive, BackupLimits limits) throws IOException {
        try (FileChannel channel = FileChannel.open(archive, StandardOpenOption.READ)) {
            ByteBuffer end = directoryEnd(channel, limits);
            int count = u16(end, 10);
            long directorySize = u32(end, 12);
            long directoryOffset = u32(end, 16);
            List<Entry> entries = centralEntries(channel, count, directoryOffset, directorySize, limits);
            entries.sort(Comparator.comparingLong(Entry::offset));
            List<Entry> checked = new ArrayList<>();
            long next = 0;
            for (Entry entry : entries) {
                if (entry.offset() != next) { throw FsBackupFiles.invalid("BACKUP_ZIP_OVERLAP_OR_GAP"); }
                Entry local = localEntry(channel, entry, limits);
                next = endOfEntry(channel, local);
                if (next > directoryOffset) { throw FsBackupFiles.invalid("BACKUP_ZIP_OVERLAP_OR_GAP"); }
                checked.add(local);
            }
            if (next != directoryOffset) { throw FsBackupFiles.invalid("BACKUP_ZIP_OVERLAP_OR_GAP"); }
            return List.copyOf(checked);
        } catch (ArithmeticException | CharacterCodingException failure) {
            throw new IOException("BACKUP_ZIP_INVALID", failure);
        }
    }

    private static ByteBuffer directoryEnd(FileChannel channel, BackupLimits limits) throws IOException {
        long size = channel.size();
        if (size < 22 || size > limits.compressedBytes()) { throw FsBackupFiles.invalid("BACKUP_ZIP_SIZE"); }
        ByteBuffer end = read(channel, size - 22, 22);
        validateEnd(end);
        int count = u16(end, 10);
        long directorySize = u32(end, 12);
        long directoryOffset = u32(end, 16);
        if (count == 0 || count >= 65_535 || count > limits.entryCount()
                || directoryOffset + directorySize != size - 22) { throw FsBackupFiles.invalid("BACKUP_ZIP_DIRECTORY"); }
        return end;
    }


    private static void validateEnd(ByteBuffer end) throws IOException {
        if (end.getInt(0) != 0x06054b50 || u16(end, 4) != 0 || u16(end, 6) != 0
                || u16(end, 8) != u16(end, 10) || u16(end, 20) != 0) {
            throw FsBackupFiles.invalid("BACKUP_ZIP_DIRECTORY");
        }
    }

    private static List<Entry> centralEntries(FileChannel channel, int count, long offset,
            long size, BackupLimits limits) throws IOException {
        List<Entry> entries = new ArrayList<>();
        FsBackupFiles.Inventory inventory = new FsBackupFiles.Inventory();
        long cursor = offset;
        long expanded = 0;
        for (int index = 0; index < count; index++) {
            ByteBuffer header = read(channel, cursor, 46);
            if (header.getInt(0) != CENTRAL_SIGNATURE) { throw FsBackupFiles.invalid("BACKUP_ZIP_DIRECTORY"); }
            validateCentralFormat(header, limits);
            validateCentralSize(header, expanded, limits);
            int nameLength = u16(header, 28);
            expanded += u32(header, 24);
            String name = name(read(channel, cursor + 46, nameLength).array());
            inventory.add(name, limits);
            cursor += 46L + nameLength;
            if (cursor > offset + size) { throw FsBackupFiles.invalid("BACKUP_ZIP_DIRECTORY"); }
            entries.add(centralEntry(header, name));
        }
        if (cursor != offset + size) { throw FsBackupFiles.invalid("BACKUP_ZIP_DIRECTORY"); }
        return entries;
    }

    private static Entry centralEntry(ByteBuffer header, String name) {
        return new Entry(name, u32(header, 24), u32(header, 20), u32(header, 16),
                u16(header, 10), u16(header, 8), u32(header, 42), 0);
    }

    private static void validateCentralFormat(ByteBuffer header, BackupLimits limits) throws IOException {
        int flags = u16(header, 8);
        int method = u16(header, 10);
        int platform = u16(header, 4) >>> 8;
        int mode = (int) (u32(header, 38) >>> 16) & 0xf000;
        long dos = u32(header, 38) & 0xffff;
        int nameLength = u16(header, 28);
        if ((flags & ~(UTF8_FLAG | DESCRIPTOR_FLAG)) != 0 || (method != 0 && method != 8)
                || u16(header, 6) > 20 || u16(header, 34) != 0 || u16(header, 30) != 0 || u16(header, 32) != 0
                || (platform != 0 && platform != 3) || (mode != 0 && mode != 0x8000)
                || (dos & (0x10 | 0x400)) != 0 || nameLength == 0 || nameLength > limits.pathBytes()) {
            throw FsBackupFiles.invalid("BACKUP_ZIP_UNSUPPORTED_OR_LIMIT");
        }
    }

    private static void validateCentralSize(ByteBuffer header, long expanded, BackupLimits limits) throws IOException {
        long compressed = u32(header, 20);
        long length = u32(header, 24);
        long offset = u32(header, 42);
        if (length == 0xffffffffL || compressed == 0xffffffffL || offset == 0xffffffffL
                || length > limits.entryBytes() || length > limits.expandedBytes() - expanded
                || (u16(header, 10) == 0 && compressed != length)
                || (length > 0 && (compressed == 0 || (length - 1) / compressed + 1 > limits.compressionRatio()))) {
            throw FsBackupFiles.invalid("BACKUP_ZIP_UNSUPPORTED_OR_LIMIT");
        }
    }

    private static Entry localEntry(FileChannel channel, Entry entry, BackupLimits limits) throws IOException {
        long offset = entry.offset();
        ByteBuffer local = read(channel, offset, 30);
        int nameLength = u16(local, 26);
        if (local.getInt(0) != 0x04034b50 || u16(local, 4) > 20
                || u16(local, 6) != entry.flags() || u16(local, 8) != entry.method()
                || u16(local, 28) != 0 || nameLength == 0 || nameLength > limits.pathBytes()
                || !name(read(channel, offset + 30, nameLength).array()).equals(entry.path())) {
            throw FsBackupFiles.invalid("BACKUP_ZIP_LOCAL");
        }
        validateLocalSizes(local, entry);
        return new Entry(entry.path(), entry.length(), entry.compressed(), entry.crc(),
                entry.method(), entry.flags(), offset, offset + 30 + nameLength);
    }

    private static void validateLocalSizes(ByteBuffer local, Entry entry) throws IOException {
        boolean descriptor = (entry.flags() & DESCRIPTOR_FLAG) != 0;
        if (!descriptor && (u32(local, 14) != entry.crc() || u32(local, 18) != entry.compressed()
                || u32(local, 22) != entry.length())) { throw FsBackupFiles.invalid("BACKUP_ZIP_LOCAL"); }
        if (descriptor && (u32(local, 14) != 0 || u32(local, 18) != 0 || u32(local, 22) != 0)) {
            throw FsBackupFiles.invalid("BACKUP_ZIP_LOCAL");
        }
    }

    private static long endOfEntry(FileChannel channel, Entry entry) throws IOException {
        long next = entry.dataOffset() + entry.compressed();
        if ((entry.flags() & DESCRIPTOR_FLAG) != 0) {
            ByteBuffer trailer = read(channel, next, 16);
            if (trailer.getInt(0) != 0x08074b50 || u32(trailer, 4) != entry.crc()
                    || u32(trailer, 8) != entry.compressed() || u32(trailer, 12) != entry.length()) {
                throw FsBackupFiles.invalid("BACKUP_ZIP_DESCRIPTOR");
            }
            next += 16;
        }
        return next;
    }

    private static String name(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }
    private static int u16(ByteBuffer buffer, int index) { return Short.toUnsignedInt(buffer.getShort(index)); }
    private static long u32(ByteBuffer buffer, int index) { return Integer.toUnsignedLong(buffer.getInt(index)); }
    private static ByteBuffer read(FileChannel channel, long offset, int count) throws IOException {
        if (offset < 0 || count < 0 || offset > channel.size() - count) { throw FsBackupFiles.invalid("BACKUP_TRUNCATED"); }
        ByteBuffer buffer = ByteBuffer.allocate(count).order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer, offset + buffer.position());
            if (read <= 0) { throw FsBackupFiles.invalid("BACKUP_TRUNCATED"); }
        }
        buffer.flip();
        return buffer;
    }

    /* default */ static Manifest extract(Path archive, Path target, PkiId expectedId, BackupLimits limits) throws IOException {
        List<Entry> entries = directory(archive, limits); // No extraction writes before structural preflight.
        Entry manifestEntry = entries.stream().filter(e -> FsBackupFiles.MANIFEST.equals(e.path()))
                .findFirst().orElseThrow(() -> FsBackupFiles.invalid("BACKUP_MANIFEST_MISSING"));
        if (manifestEntry.length() > limits.manifestBytes()) { throw FsBackupFiles.invalid("BACKUP_MANIFEST_LIMIT"); }
        ByteArrayOutputStream manifestBytes = new ByteArrayOutputStream((int) manifestEntry.length());
        Item manifestItem = expand(archive, manifestEntry, manifestBytes);
        Manifest manifest = decodeManifest(manifestBytes.toByteArray(), expectedId, limits,
                HexFormat.of().formatHex(manifestItem.digest()));
        Map<String, Item> expected = new LinkedHashMap<>();
        for (Item item : manifest.items()) {
            expected.put(item.path(), item);
        }
        if (entries.size() != expected.size() + 1) { throw FsBackupFiles.invalid("BACKUP_INVENTORY"); }
        for (Entry entry : entries) {
            if (FsBackupFiles.MANIFEST.equals(entry.path())) { continue; }
            Item item = expected.get(entry.path());
            if (item == null || item.length() != entry.length()) { throw FsBackupFiles.invalid("BACKUP_INVENTORY"); }
        }
        requireInventory(expected);
        Files.createDirectories(target.resolve("staged-content"));
        for (Entry entry : entries) {
            if (FsBackupFiles.MANIFEST.equals(entry.path())) { continue; }
            Path destination = target.resolve(entry.path());
            Files.createDirectories(destination.getParent());
            try (OutputStream output = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
                Item actual = expand(archive, entry, output);
                if (!MessageDigest.isEqual(actual.digest(), expected.get(entry.path()).digest())) {
                    throw FsBackupFiles.invalid("BACKUP_DIGEST");
                }
            }
            Files.setLastModifiedTime(destination, java.nio.file.attribute.FileTime.fromMillis(
                    expected.get(entry.path()).modifiedMillis()));
        }
        if (!FilesystemPkiStore.CURRENT_STORE_VERSION.equals(Files.readString(target.resolve("VERSION"), StandardCharsets.US_ASCII))) { throw FsBackupFiles.invalid("BACKUP_STORE_VERSION"); }
        return manifest;
    }

    private static void requireInventory(Map<String, Item> entries) throws IOException {
        for (String required : List.of("VERSION", "SIGNING_NAMESPACE", "metadata/FORMAT",
                "metadata/manifest.zem", "revocations/transitions.log")) {
            if (!entries.containsKey(required)) { throw FsBackupFiles.invalid("BACKUP_REQUIRED_STATE"); }
        }
        if (entries.get("VERSION").length() != FilesystemPkiStore.CURRENT_STORE_VERSION.length()
                || entries.get("SIGNING_NAMESPACE").length() != 32) { throw FsBackupFiles.invalid("BACKUP_REQUIRED_STATE"); }
    }

    private static Manifest decodeManifest(byte[] bytes, PkiId expectedId, BackupLimits limits, String digest)
            throws IOException {
        try (DataInputStream input = new DataInputStream(new java.io.ByteArrayInputStream(bytes))) {
            validateManifestHeader(input, expectedId);
            long seconds = input.readLong();
            int nanos = input.readInt();
            if (nanos < 0 || nanos >= 1_000_000_000) { throw FsBackupFiles.invalid("BACKUP_MANIFEST_INSTANT"); }
            Instant instant = Instant.ofEpochSecond(seconds, nanos);
            int count = input.readInt();
            if (count <= 0 || count >= limits.entryCount()) { throw FsBackupFiles.invalid("BACKUP_MANIFEST_COUNT"); }
            List<Item> items = manifestItems(input, bytes.length, count, limits);
            if (input.read() != -1) { throw FsBackupFiles.invalid("BACKUP_MANIFEST_TRAILING"); }
            return new Manifest(expectedId, instant, List.copyOf(items), digest);
        } catch (RuntimeException failure) { throw new IOException("BACKUP_MANIFEST_INVALID", failure); } // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
    }

    private static void validateManifestHeader(DataInputStream input, PkiId expectedId) throws IOException {
        if (!FORMAT.equals(input.readUTF()) || input.readInt() != VERSION
                || !FilesystemPkiStore.CURRENT_STORE_VERSION.equals(input.readUTF())) {
            throw FsBackupFiles.invalid("BACKUP_FORMAT_VERSION");
        }
        String id = input.readUTF();
        if (id.length() > 256 || !expectedId.value().equals(id)) { throw FsBackupFiles.invalid("BACKUP_ID"); }
    }

    private static List<Item> manifestItems(DataInputStream input, long initialBytes, int count,
            BackupLimits limits) throws IOException {
        List<Item> items = new ArrayList<>();
        FsBackupFiles.Inventory inventory = new FsBackupFiles.Inventory();
        String previous = "";
        long total = initialBytes;
        for (int index = 0; index < count; index++) {
            String path = input.readUTF();
            inventory.add(path, limits);
            long length = input.readLong();
            byte[] commitment = input.readNBytes(32);
            long modifiedMillis = input.readLong();
            if (path.compareTo(previous) <= 0 || FsBackupFiles.MANIFEST.equals(path)
                    || length < 0 || length > limits.entryBytes() || length > limits.expandedBytes() - total
                    || commitment.length != 32) { throw FsBackupFiles.invalid("BACKUP_MANIFEST_ENTRY"); }
            previous = path;
            total += length;
            items.add(new Item(path, length, 0, commitment, modifiedMillis));
        }
        return items;
    }


    private static Item expand(Path archive, Entry entry, OutputStream output) throws IOException {
        Inflater inflater = entry.method() == 8 ? new Inflater(true) : null;
        MessageDigest digest = FsBackupFiles.digest();
        CRC32 crc = new CRC32();
        long expanded = 0;
        try (InputStream compressed = new RangeInput(archive, entry.dataOffset(), entry.compressed());
                InputStream input = inflater == null ? compressed
                        : new InflaterInputStream(compressed, inflater, FsBackupFiles.BUFFER_BYTES)) {
            byte[] buffer = new byte[FsBackupFiles.BUFFER_BYTES];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (count == 0 || count > entry.length() - expanded) { throw FsBackupFiles.invalid("BACKUP_EXPANSION"); }
                output.write(buffer, 0, count);
                digest.update(buffer, 0, count);
                crc.update(buffer, 0, count);
                expanded += count;
            }
            if (expanded != entry.length() || crc.getValue() != entry.crc()
                    || (inflater != null && (!inflater.finished() || inflater.getBytesRead() != entry.compressed()))) {
                throw FsBackupFiles.invalid("BACKUP_LENGTH_OR_CRC");
            }
            return new Item(entry.path(), expanded, crc.getValue(), digest.digest(), 0);
        } finally { if (inflater != null) { inflater.end(); } }
    }

    /** Reads a bounded compressed-entry range without crossing ZIP framing. */
    private static final class RangeInput extends InputStream {
        private final FileChannel channel;
        private long remaining;
        /* default */ RangeInput(Path path, long offset, long length) throws IOException {
            super();
            channel = FileChannel.open(path, StandardOpenOption.READ);
            channel.position(offset);
            remaining = length;
        }
        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            int count = read(one, 0, 1);
            return count < 0 ? -1 : one[0] & 255;
        }
        @Override public int read(byte[] bytes, int offset, int length) throws IOException {
            java.util.Objects.checkFromIndexSize(offset, length, bytes.length);
            if (length == 0) { return 0; }
            if (remaining == 0) { return -1; }
            int count = channel.read(ByteBuffer.wrap(bytes, offset, (int) Math.min(length, remaining)));
            if (count <= 0) { throw FsBackupFiles.invalid("BACKUP_TRUNCATED"); }
            remaining -= count;
            return count;
        }
        @Override public void close() throws IOException { channel.close(); }
    }

    /** Enforces a byte limit before forwarding any oversized write. */
    private static final class LimitedOutput extends OutputStream {
        private final OutputStream delegate;
        private final long maximum;
        private long written;
        /* default */ LimitedOutput(OutputStream delegate, long maximum) {
            super();
            this.delegate = delegate;
            this.maximum = maximum;
        }
        @Override public void write(int value) throws IOException { write(new byte[] { (byte) value }); }
        @Override public void write(byte[] bytes, int offset, int length) throws IOException {
            if (length > maximum - written) { throw FsBackupFiles.invalid("BACKUP_MANIFEST_LIMIT"); }
            delegate.write(bytes, offset, length);
            written += length;
        }
        @Override public void close() throws IOException { delegate.close(); }
    }
}
