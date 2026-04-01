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
package zeroecho.ext.integrations.covert.jpeg;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.imaging.formats.tiff.constants.ExifTagConstants;
import org.apache.commons.imaging.formats.tiff.constants.TiffDirectoryType;
import org.apache.commons.imaging.formats.tiff.fieldtypes.AbstractFieldType;
import org.apache.commons.imaging.formats.tiff.taginfos.TagInfo;
import org.apache.commons.imaging.formats.tiff.taginfos.TagInfoAscii;
import org.apache.commons.imaging.formats.tiff.taginfos.TagInfoUndefined;

/**
 * Represents a target slot in an EXIF/TIFF metadata directory for covert data
 * embedding.
 * <p>
 * A {@code Slot} defines where and how binary payloads may be hidden within the
 * structure of JPEG metadata. It supports both predefined slots (registered by
 * name) and fully custom slots specified via tag metadata.
 * </p>
 *
 * <p>
 * Slot specifications can be written as strings using the following syntax:
 * </p>
 *
 * <pre>{@code
 * [group.]name[/tag=tagId,type,count,dir][:capacity]
 * }</pre>
 *
 * <ul>
 * <li><b>group</b>: Optional slot group, one of EXIF, GPS, INTEROP, TIFF, or
 * THUMBNAIL. Default is EXIF.</li>
 * <li><b>name</b>: Slot name (must match a registered name or be part of a tag
 * definition).</li>
 * <li><b>tag=...</b>: Optional explicit tag definition for custom slots.</li>
 * <li><b>capacity</b>: Optional maximum capacity in bytes (default is
 * 1024).</li>
 * </ul>
 *
 * <p>
 * Predefined slots are stored in a registry and provide convenient aliases for
 * common EXIF tags. Custom slots can be created dynamically using tag
 * information and are parsed using the {@link #parse(String)} method.
 * </p>
 *
 * <p>
 * This class is immutable and not intended to be extended.
 * </p>
 *
 * @author Leo Galambos
 */
public final class Slot { // NOPMD
    private static final Map<String, Slot> REGISTRY = new HashMap<>();

    static {
        register("usercomment", SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_USER_COMMENT, 4096);
        register("makernote", SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_MAKER_NOTE, 4096);
        register("exifversion", SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_EXIF_VERSION, 1024);
        register("software", SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_SOFTWARE, 2048);
        register("interoptag", SlotGroup.INTEROP,
                new TagInfoUndefined("CustomInterop", 0xC4A6, TiffDirectoryType.EXIF_DIRECTORY_INTEROP_IFD), 2048);
        register("thumbcomment", SlotGroup.THUMBNAIL,
                new TagInfoAscii("ThumbComment", 0xC4A7, 64, TiffDirectoryType.TIFF_DIRECTORY_IFD1), 1024);
    }

    private static final Map<String, TiffDirectoryType> DIRECTORY_MAP = Map.ofEntries(
            Map.entry("ifd0", TiffDirectoryType.TIFF_DIRECTORY_IFD0),
            Map.entry("ifd1", TiffDirectoryType.TIFF_DIRECTORY_IFD1),
            Map.entry("ifd2", TiffDirectoryType.TIFF_DIRECTORY_IFD2),
            Map.entry("ifd3", TiffDirectoryType.TIFF_DIRECTORY_IFD3),
            Map.entry("exif", TiffDirectoryType.EXIF_DIRECTORY_EXIF_IFD),
            Map.entry("gps", TiffDirectoryType.EXIF_DIRECTORY_GPS),
            Map.entry("interop", TiffDirectoryType.EXIF_DIRECTORY_INTEROP_IFD),
            Map.entry("maker", TiffDirectoryType.EXIF_DIRECTORY_MAKER_NOTES),
            Map.entry("root", TiffDirectoryType.TIFF_DIRECTORY_ROOT),
            Map.entry("sub_ifd", TiffDirectoryType.EXIF_DIRECTORY_SUB_IFD));

    private static final Map<String, AbstractFieldType> FIELD_TYPE_MAP = new HashMap<>();

    static {
        for (AbstractFieldType t : AbstractFieldType.ANY) {
            FIELD_TYPE_MAP.put(t.getName().toLowerCase(Locale.ROOT), t);
        }
    }

    /**
     * Logical groupings of EXIF/TIFF directories used to categorize slots.
     * <p>
     * Each group corresponds to a specific metadata section within an image file,
     * typically used in image metadata standards such as EXIF and TIFF.
     */
    public enum SlotGroup {
        /**
         * EXIF metadata group, containing tags related to camera settings, image
         * capture information, and other extended image metadata defined by the EXIF
         * standard.
         */
        EXIF,
        /**
         * TIFF metadata group, which includes baseline TIFF tags such as image
         * dimensions, compression type, and color format.
         */
        TIFF,
        /**
         * GPS metadata group, storing geolocation information like latitude, longitude,
         * altitude, and GPS timestamp.
         */
        GPS,
        /**
         * Interoperability metadata group, used to ensure compatibility across
         * different file formats or devices. Typically contains a few specific tags.
         */
        INTEROP,
        /**
         * Thumbnail metadata group, storing metadata and image data for embedded
         * preview thumbnails.
         */
        THUMBNAIL
    }

    /**
     * The logical group (e.g., EXIF, GPS, TIFF) this slot belongs to.
     */
    public final SlotGroup group;
    /**
     * Metadata tag info describing the structure of this slot.
     */
    public final TagInfo tagInfo;
    /**
     * The default capacity, in bytes, of this slot for data embedding.
     */
    public final int defaultCapacity;

    private Slot(SlotGroup group, TagInfo tagInfo, int defaultCapacity) {
        this.group = group;
        this.tagInfo = tagInfo;
        this.defaultCapacity = defaultCapacity;
    }

    /**
     * Registers a named predefined slot in the internal registry. This allows slots
     * to be referenced later by name in shorthand form.
     *
     * @param name            the lowercase name used for lookup
     * @param group           the logical slot group
     * @param tagInfo         the tag metadata for the slot
     * @param defaultCapacity the default maximum capacity for this slot in bytes
     * @return the registered {@code Slot} instance
     */
    public static Slot register(String name, SlotGroup group, TagInfo tagInfo, int defaultCapacity) {
        Slot slot = new Slot(group, tagInfo, defaultCapacity);
        REGISTRY.put(name.toLowerCase(Locale.ROOT), slot);
        return slot;
    }

    /**
     * Parses a slot specification string into a {@code Slot} object.
     * <p>
     * The input may refer to a predefined slot by name, or a custom slot defined
     * with full tag details. See class-level documentation for the full
     * specification syntax.
     * </p>
     *
     * @param spec the slot specification string
     * @return a {@code Slot} representing the parsed definition
     * @throws IllegalArgumentException if the input format is invalid or references
     *                                  unknown components
     */
    public static Slot parse(String spec) {
        Pattern pattern = Pattern.compile(
                "(?:(\\w+)\\.)?(\\w+)(?:/tag=([\\d]+),([a-z0-9_]+),(\\d+),(\\w+))?(?::(\\d+))?",
                Pattern.CASE_INSENSITIVE);
        Matcher m = pattern.matcher(spec);
        if (!m.matches()) {
            throw new IllegalArgumentException("Invalid slot spec: " + spec);
        }

        String groupStr = m.group(1);
        String name = m.group(2);
        String tagIdStr = m.group(3);
        String typeStr = m.group(4);
        String countStr = m.group(5);
        String dirStr = m.group(6);
        String sizeStr = m.group(7);

        SlotGroup group = groupStr != null ? SlotGroup.valueOf(groupStr.toUpperCase(Locale.ROOT)) : SlotGroup.EXIF;
        int size = sizeStr != null ? Integer.parseInt(sizeStr) : 1024;

        if (tagIdStr == null) {
            Slot predefined = REGISTRY.get(name.toLowerCase(Locale.ROOT));
            if (predefined == null) {
                throw new IllegalArgumentException("No predefined slot found: " + name);
            }
            return predefined;
        }

        int tagId = Integer.parseInt(tagIdStr);
        int count = Integer.parseInt(countStr);

        TiffDirectoryType dir = Optional.ofNullable(DIRECTORY_MAP.get(dirStr.toLowerCase(Locale.ROOT)))
                .orElseThrow(() -> new IllegalArgumentException("Unknown directory: " + dirStr));

        AbstractFieldType fieldType = Optional.ofNullable(FIELD_TYPE_MAP.get(typeStr.toLowerCase(Locale.ROOT)))
                .orElseThrow(() -> new IllegalArgumentException("Unsupported type: " + typeStr));

        TagInfo tagInfo = new TagInfo(name, tagId, fieldType, count, dir);
        return new Slot(group, tagInfo, size);
    }

    /**
     * Returns a human-readable representation of the slot, including its tag name
     * and capacity.
     *
     * @return string representation of the slot
     */
    @Override
    public String toString() {
        return tagInfo.name + ":" + defaultCapacity;
    }

    /**
     * Compares this slot to another for equality based on tag ID and directory
     * type.
     *
     * @param o the object to compare
     * @return true if the other object is a slot with the same tag and directory
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Slot slot = (Slot) o;
        return tagInfo.tag == slot.tagInfo.tag && tagInfo.directoryType == slot.tagInfo.directoryType;
    }

    /**
     * Computes a hash code based on the slot's tag and directory.
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return Objects.hash(tagInfo.tag, tagInfo.directoryType);
    }

    /**
     * Returns a list of default slot configurations commonly available in standard
     * EXIF metadata. These slots are selected for compatibility and relatively high
     * storage capacity.
     *
     * @return list of default {@code Slot} instances
     */
    public static List<Slot> defaults() {
        return List.of(new Slot(SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_USER_COMMENT, 4096),
                new Slot(SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_MAKER_NOTE, 4096),
                new Slot(SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_EXIF_VERSION, 1024),
                new Slot(SlotGroup.EXIF, ExifTagConstants.EXIF_TAG_SOFTWARE, 2048));
    }
}
