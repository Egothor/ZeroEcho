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
package zeroecho.apispec;

/**
 * Minimal YAML emitter using a {@link StringBuilder}.
 *
 * <p>Supports only the YAML subset needed by the OpenAPI generator: nested block
 * mappings, sequence items, quoted string values, and unquoted literal values. No
 * external dependencies. Not general-purpose — strings with embedded newlines that
 * would require block or folded scalar representation are not handled.</p>
 *
 * <p>This class is not thread-safe; one instance per generation run.</p>
 *
 * @since 1.0
 */
final class YamlBuilder {

    private static final int INDENT_SIZE = 2;
    private static final int FIRST_PRINTABLE = 0x20;

    private final StringBuilder buf = new StringBuilder(8192); // NOPMD AvoidStringBufferField - One confined builder retains exactly one generated document.
    private int indentLevel;

    /**
     * Returns the accumulated YAML document as a string.
     *
     * @return complete YAML document text
     */
    /* default */ String build() {
        return buf.toString();
    }

    /**
     * Emits a block mapping key with a quoted string value on one line.
     *
     * @param key   YAML mapping key (must be a safe identifier or quoted key)
     * @param value string value; will be double-quoted and escaped
     */
    /* default */ void mapping(String key, String value) {
        writeIndent();
        buf.append(key).append(": \"").append(escapeYaml(value)).append("\"\n");
    }

    /**
     * Emits a block mapping key with an unquoted literal value on one line.
     *
     * <p>Use for boolean, integer, null, or simple string values that do not require
     * quoting (e.g. {@code true}, {@code 1}, or a plain identifier).</p>
     *
     * @param key   YAML mapping key
     * @param value literal value emitted verbatim
     */
    /* default */ void mappingLiteral(String key, String value) {
        writeIndent();
        buf.append(key).append(": ").append(value).append('\n');
    }

    /**
     * Emits a mapping key followed by a nested block, indented by one level.
     *
     * @param key  YAML mapping key
     * @param body nested content producer; called at {@code indentLevel + 1}
     */
    /* default */ void blockMapping(String key, Runnable body) {
        writeIndent();
        buf.append(key).append(":\n");
        indentLevel++;
        body.run();
        indentLevel--;
    }

    /**
     * Emits a sequence item containing a simple quoted string.
     *
     * @param value string value; will be double-quoted and escaped
     */
    /* default */ void sequenceItemString(String value) {
        writeIndent();
        buf.append("- \"").append(escapeYaml(value)).append("\"\n");
    }

    /**
     * Emits a sequence item block containing structured content.
     *
     * <p>The dash ({@code -}) is written at the current indentation. The body
     * executes at {@code indentLevel + 1}, as required by the YAML block sequence
     * specification. The first mapping key in the body will therefore appear two
     * spaces to the right of the dash.</p>
     *
     * @param body nested content producer for this sequence item
     */
    /* default */ void sequenceItem(Runnable body) {
        writeIndent();
        buf.append("-\n");
        indentLevel++;
        body.run();
        indentLevel--;
    }

    /**
     * Emits a comment line at the current indentation.
     *
     * @param text comment text without the leading {@code #}
     */
    /* default */ void comment(String text) {
        writeIndent();
        buf.append("# ").append(text).append('\n');
    }

    /**
     * Emits a blank line.
     */
    /* default */ void blank() {
        buf.append('\n');
    }

    /**
     * Emits a {@code $ref} mapping under {@code key}.
     *
     * @param key  YAML mapping key (the containing object's field name)
     * @param ref  JSON Reference value, e.g. {@code "#/components/schemas/Foo"}
     */
    /* default */ void refMapping(String key, String ref) {
        blockMapping(key, () -> mapping("$ref", ref));
    }

    // -- package-private helpers used by OpenApiGenerator

    /**
     * Increases the indentation level by one.
     */
    /* default */ void push() {
        indentLevel++;
    }

    /**
     * Decreases the indentation level by one.
     *
     * @throws IllegalStateException if already at level zero
     */
    /* default */ void pop() {
        if (indentLevel == 0) {
            throw new IllegalStateException("Indentation underflow");
        }
        indentLevel--;
    }

    /**
     * Emits the given text verbatim, followed by a newline.
     *
     * <p>Callers are responsible for correct indentation when using this method.</p>
     *
     * @param line raw text line to append
     */
    /* default */ void rawLine(String line) {
        buf.append(line).append('\n');
    }

    // -- private helpers

    private void writeIndent() {
        int spaces = indentLevel * INDENT_SIZE;
        buf.append(" ".repeat(spaces));
    }

    /**
     * Escapes a string value for use inside YAML double-quoted scalars.
     *
     * @param value raw string value
     * @return escaped string safe for embedding between double-quote delimiters
     */
    /* default */ static String escapeYaml(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> {
                    if (c < FIRST_PRINTABLE) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
