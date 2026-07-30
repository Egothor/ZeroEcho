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
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Instant;
import java.time.DateTimeException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.Util;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialProfileBinding;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.orch.OrchestrationDurabilityPolicy;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.policy.PolicyTraceStep;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.SubjectAlternativeNameType;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Closed binary codec for the current filesystem persistence schema.
 *
 * <p>
 * Every payload carries a fixed magic value, one current codec version, and one
 * of ten explicit top-level type identifiers. Nested values are decoded only
 * through the schema selected by trusted store code. Java class names are never
 * persisted or resolved, and this codec performs no runtime class loading,
 * reflective construction, or factory discovery.
 * </p>
 *
 * <p>
 * Pre-release payloads written by earlier class-name-based codecs are rejected.
 * No compatibility or migration decoder is provided. Lists and optional values
 * carry their exact element schema, and attribute sets are represented
 * structurally and decoded to {@link SimpleAttributeSet}.
 * </p>
 */
// The closed codec keeps every strict schema in one non-reflective authority.
@SuppressWarnings("PMD.CouplingBetweenObjects")
final class FsCodec {

    /* package */ static final int MAX_COMPONENT_BYTES = 256 * 1024;
    /* package */ static final int CURRENT_CODEC_VERSION = 2;

    private static final int CODEC_MAGIC = 0x5A454346;
    private static final int MAX_COLLECTION_ELEMENTS = MAX_COMPONENT_BYTES;

    private static final int TOP_CA_RECORD = 1;
    private static final int TOP_CREDENTIAL = 2;
    private static final int TOP_PARSED_REQUEST = 3;
    private static final int TOP_REVOCATION = 4;
    private static final int TOP_STATUS_OBJECT = 5;
    private static final int TOP_PUBLICATION = 6;
    private static final int TOP_POLICY_TRACE = 8;
    private static final int TOP_WORKFLOW_STATE = 9;
    private static final int TOP_SIGN_WORKFLOW_RECORD = 10;
    private static final int TOP_PROFILE_VERSION = 11;
    private static final int TOP_ACTIVE_PROFILE_REF = 12;

    private static final int TYPE_STRING = 1;
    private static final int TYPE_BOOLEAN = 2;
    private static final int TYPE_LONG = 3;
    private static final int TYPE_BYTES = 4;
    private static final int TYPE_INSTANT = 5;
    private static final int TYPE_LIST = 7;
    private static final int TYPE_OPTIONAL = 8;
    private static final int TYPE_PKI_ID = 20;
    private static final int TYPE_KEY_REF = 21;
    private static final int TYPE_SUBJECT_REF = 22;
    private static final int TYPE_ISSUER_REF = 23;
    private static final int TYPE_FORMAT_ID = 24;
    private static final int TYPE_VALIDITY = 25;
    private static final int TYPE_ENCODED_OBJECT = 26;
    private static final int TYPE_PRINCIPAL = 27;
    private static final int TYPE_ATTRIBUTE_ID = 28;
    private static final int TYPE_POLICY_TRACE_STEP = 29;
    private static final int TYPE_PUBLICATION_TARGET = 30;
    private static final int TYPE_ATTRIBUTE_SET = 31;
    private static final int TYPE_ATTRIBUTE_VALUE = 33;
    private static final int TYPE_CREDENTIAL_RECORD = 34;
    private static final int TYPE_ENCODING_ENUM = 50;
    private static final int TYPE_CA_KIND_ENUM = 51;
    private static final int TYPE_CA_STATE_ENUM = 52;
    private static final int TYPE_CREDENTIAL_STATUS_ENUM = 53;
    private static final int TYPE_REVOCATION_REASON_ENUM = 54;
    private static final int TYPE_STATUS_OBJECT_TYPE_ENUM = 55;
    private static final int TYPE_PUBLICATION_TARGET_TYPE_ENUM = 56;
    private static final int TYPE_PUBLICATION_STATUS_ENUM = 57;
    private static final int TYPE_DURABILITY_POLICY_ENUM = 58;
    private static final int TYPE_SIGN_STATE_ENUM = 59;
    private static final int TYPE_REVOCATION_STATE_ENUM = 60;
    private static final int TYPE_REVOCATION_TRANSITION = 61;
    private static final int TYPE_SUBJECT_RDN_TYPE_ENUM = 62;
    private static final int TYPE_SAN_TYPE_ENUM = 63;
    private static final int TYPE_SUBJECT_RDN = 65;
    private static final int TYPE_SAN = 66;
    private static final int TYPE_PROFILE_REF = 72;
    private static final int TYPE_PROFILE_BINDING = 73;

    private static final int ATTRIBUTE_STRING = 1;
    private static final int ATTRIBUTE_BOOLEAN = 2;
    private static final int ATTRIBUTE_INTEGER = 3;
    private static final int ATTRIBUTE_INSTANT = 4;
    private static final int ATTRIBUTE_BYTES = 5;
    private static final int MARKER_ABSENT = 0;
    private static final int MARKER_PRESENT = 1;

    private static final ValueSchema<String> STRING = valueSchema(TYPE_STRING, Writer::writeString,
            Reader::readString);
    private static final ValueSchema<Boolean> BOOLEAN = valueSchema(TYPE_BOOLEAN, Writer::writeBoolean,
            Reader::readBoolean);
    private static final ValueSchema<Long> LONG = valueSchema(TYPE_LONG, Writer::writeLong, Reader::readLong);
    private static final ValueSchema<byte[]> BYTES = valueSchema(TYPE_BYTES, Writer::writeBytes, Reader::readBytes);
    private static final ValueSchema<Instant> INSTANT = valueSchema(TYPE_INSTANT, Writer::writeInstant,
            Reader::readInstant);
    private static final ValueSchema<CertificateProfileRef> PROFILE_REF = valueSchema(TYPE_PROFILE_REF,
            (writer, value) -> {
                writer.writeValue(STRING, value.profileId());
                writer.writeValue(LONG, value.profileVersion());
                writer.writeValue(BYTES, value.canonicalSha256());
            },
            reader -> new CertificateProfileRef(reader.readValue(STRING), reader.readValue(LONG),
                    reader.readValue(BYTES)));
    private static final ValueSchema<CredentialProfileBinding> PROFILE_BINDING =
            valueSchema(TYPE_PROFILE_BINDING, FsCodec::writeProfileBinding, FsCodec::readProfileBinding);

    private static final ValueSchema<Encoding> ENCODING = enumSchema(TYPE_ENCODING_ENUM,
            value -> switch (value) {
                case DER -> 1;
                case PEM -> 2;
                case BINARY -> 3;
            },
            code -> switch (code) {
                case 1 -> Encoding.DER;
                case 2 -> Encoding.PEM;
                case 3 -> Encoding.BINARY;
                default -> throw unknownEnum("Encoding", code);
            });
    private static final ValueSchema<CaKind> CA_KIND = enumSchema(TYPE_CA_KIND_ENUM,
            value -> switch (value) {
                case ROOT -> 1;
                case INTERMEDIATE -> 2;
            },
            code -> switch (code) {
                case 1 -> CaKind.ROOT;
                case 2 -> CaKind.INTERMEDIATE;
                default -> throw unknownEnum("CaKind", code);
            });
    private static final ValueSchema<CaState> CA_STATE = enumSchema(TYPE_CA_STATE_ENUM,
            value -> switch (value) {
                case ACTIVE -> 1;
                case RETIRED -> 2;
                case COMPROMISED -> 3;
                case DISABLED -> 4;
            },
            code -> switch (code) {
                case 1 -> CaState.ACTIVE;
                case 2 -> CaState.RETIRED;
                case 3 -> CaState.COMPROMISED;
                case 4 -> CaState.DISABLED;
                default -> throw unknownEnum("CaState", code);
            });
    private static final ValueSchema<CredentialStatus> CREDENTIAL_STATUS = enumSchema(TYPE_CREDENTIAL_STATUS_ENUM,
            value -> switch (value) {
                case ISSUED -> 1;
                case REVOKED -> 2;
                case EXPIRED -> 3;
            },
            code -> switch (code) {
                case 1 -> CredentialStatus.ISSUED;
                case 2 -> CredentialStatus.REVOKED;
                case 3 -> CredentialStatus.EXPIRED;
                default -> throw unknownEnum("CredentialStatus", code);
            });
    private static final ValueSchema<RevocationReason> REVOCATION_REASON = enumSchema(TYPE_REVOCATION_REASON_ENUM,
            value -> switch (value) {
                case UNSPECIFIED -> 1;
                case KEY_COMPROMISE -> 2;
                case CA_COMPROMISE -> 3;
                case AFFILIATION_CHANGED -> 4;
                case SUPERSEDED -> 5;
                case CESSATION_OF_OPERATION -> 6;
                case CERTIFICATE_HOLD -> 7;
                case REMOVE_FROM_CRL -> 8;
                case PRIVILEGE_WITHDRAWN -> 9;
                case AA_COMPROMISE -> 10;
            },
            code -> switch (code) {
                case 1 -> RevocationReason.UNSPECIFIED;
                case 2 -> RevocationReason.KEY_COMPROMISE;
                case 3 -> RevocationReason.CA_COMPROMISE;
                case 4 -> RevocationReason.AFFILIATION_CHANGED;
                case 5 -> RevocationReason.SUPERSEDED;
                case 6 -> RevocationReason.CESSATION_OF_OPERATION;
                case 7 -> RevocationReason.CERTIFICATE_HOLD;
                case 8 -> RevocationReason.REMOVE_FROM_CRL;
                case 9 -> RevocationReason.PRIVILEGE_WITHDRAWN;
                case 10 -> RevocationReason.AA_COMPROMISE;
                default -> throw unknownEnum("RevocationReason", code);
            });
    private static final ValueSchema<RevocationState> REVOCATION_STATE = enumSchema(TYPE_REVOCATION_STATE_ENUM,
            value -> switch (value) {
                case CLEAR -> 1;
                case HELD -> 2;
                case PERMANENTLY_REVOKED -> 3;
            },
            code -> switch (code) {
                case 1 -> RevocationState.CLEAR;
                case 2 -> RevocationState.HELD;
                case 3 -> RevocationState.PERMANENTLY_REVOKED;
                default -> throw unknownEnum("RevocationState", code);
            });
    private static final ValueSchema<StatusObjectType> STATUS_OBJECT_TYPE = enumSchema(TYPE_STATUS_OBJECT_TYPE_ENUM,
            value -> switch (value) {
                case CRL -> 1;
                case DELTA_CRL -> 2;
                case OCSP -> 3;
                case REVOCATION_LIST -> 4;
            },
            code -> switch (code) {
                case 1 -> StatusObjectType.CRL;
                case 2 -> StatusObjectType.DELTA_CRL;
                case 3 -> StatusObjectType.OCSP;
                case 4 -> StatusObjectType.REVOCATION_LIST;
                default -> throw unknownEnum("StatusObjectType", code);
            });
    private static final ValueSchema<PublicationTargetType> PUBLICATION_TARGET_TYPE = enumSchema(
            TYPE_PUBLICATION_TARGET_TYPE_ENUM,
            value -> switch (value) {
                case FILESYSTEM -> 1;
                case LDAP -> 2;
                case HTTP -> 3;
                case OBJECT_STORE -> 4;
                case CUSTOM -> 5;
            },
            code -> switch (code) {
                case 1 -> PublicationTargetType.FILESYSTEM;
                case 2 -> PublicationTargetType.LDAP;
                case 3 -> PublicationTargetType.HTTP;
                case 4 -> PublicationTargetType.OBJECT_STORE;
                case 5 -> PublicationTargetType.CUSTOM;
                default -> throw unknownEnum("PublicationTargetType", code);
            });
    private static final ValueSchema<PublicationStatus> PUBLICATION_STATUS = enumSchema(TYPE_PUBLICATION_STATUS_ENUM,
            value -> switch (value) {
                case PUBLISHED -> 1;
                case SKIPPED -> 2;
                case FAILED -> 3;
            },
            code -> switch (code) {
                case 1 -> PublicationStatus.PUBLISHED;
                case 2 -> PublicationStatus.SKIPPED;
                case 3 -> PublicationStatus.FAILED;
                default -> throw unknownEnum("PublicationStatus", code);
            });
    private static final ValueSchema<OrchestrationDurabilityPolicy> DURABILITY_POLICY = enumSchema(
            TYPE_DURABILITY_POLICY_ENUM,
            value -> switch (value) {
                case STRICT_ABORT_ON_RESTART -> 1;
                case DURABLE_MIN_STATE -> 2;
                case DURABLE_ENCRYPTED_STATE -> 3;
            },
            code -> switch (code) {
                case 1 -> OrchestrationDurabilityPolicy.STRICT_ABORT_ON_RESTART;
                case 2 -> OrchestrationDurabilityPolicy.DURABLE_MIN_STATE;
                case 3 -> OrchestrationDurabilityPolicy.DURABLE_ENCRYPTED_STATE;
                default -> throw unknownEnum("OrchestrationDurabilityPolicy", code);
            });
    private static final ValueSchema<SignWorkflowStore.State> SIGN_STATE = valueSchema(TYPE_SIGN_STATE_ENUM,
            (writer, value) -> writer.writeUnsignedByte(value.persistentCode()),
            reader -> {
                int code = reader.readUnsignedByte();
                try {
                    return SignWorkflowStore.State.fromPersistentCode(code);
                } catch (IllegalArgumentException ex) {
                    throw new IOException("unknown SignWorkflowStore.State code " + code, ex);
                }
            });
    private static final ValueSchema<SubjectRdnType> SUBJECT_RDN_TYPE = enumSchema(TYPE_SUBJECT_RDN_TYPE_ENUM,
            value -> switch (value) {
                case COMMON_NAME -> 1;
                case ORGANIZATION_NAME -> 2;
                case ORGANIZATIONAL_UNIT_NAME -> 3;
                case COUNTRY_NAME -> 4;
                case STATE_OR_PROVINCE_NAME -> 5;
                case LOCALITY_NAME -> 6;
                case SERIAL_NUMBER -> 7;
                case EMAIL_ADDRESS -> 8;
                case PSEUDONYM -> 9;
            },
            code -> switch (code) {
                case 1 -> SubjectRdnType.COMMON_NAME;
                case 2 -> SubjectRdnType.ORGANIZATION_NAME;
                case 3 -> SubjectRdnType.ORGANIZATIONAL_UNIT_NAME;
                case 4 -> SubjectRdnType.COUNTRY_NAME;
                case 5 -> SubjectRdnType.STATE_OR_PROVINCE_NAME;
                case 6 -> SubjectRdnType.LOCALITY_NAME;
                case 7 -> SubjectRdnType.SERIAL_NUMBER;
                case 8 -> SubjectRdnType.EMAIL_ADDRESS;
                case 9 -> SubjectRdnType.PSEUDONYM;
                default -> throw unknownEnum("SubjectRdnType", code);
            });
    private static final ValueSchema<SubjectAlternativeNameType> SAN_TYPE = enumSchema(TYPE_SAN_TYPE_ENUM,
            value -> switch (value) {
                case DNS_NAME -> 1;
                case IP_ADDRESS -> 2;
                case URI -> 3;
                case RFC822_NAME -> 4;
            },
            code -> switch (code) {
                case 1 -> SubjectAlternativeNameType.DNS_NAME;
                case 2 -> SubjectAlternativeNameType.IP_ADDRESS;
                case 3 -> SubjectAlternativeNameType.URI;
                case 4 -> SubjectAlternativeNameType.RFC822_NAME;
                default -> throw unknownEnum("SubjectAlternativeNameType", code);
            });
    private static final ValueSchema<PkiId> PKI_ID = valueSchema(TYPE_PKI_ID,
            (writer, value) -> writer.writeValue(STRING, value.value()),
            reader -> new PkiId(reader.readValue(STRING)));
    private static final ValueSchema<KeyRef> KEY_REF = valueSchema(TYPE_KEY_REF,
            (writer, value) -> writer.writeValue(STRING, value.value()),
            reader -> new KeyRef(reader.readValue(STRING)));
    private static final ValueSchema<SubjectRef> SUBJECT_REF = valueSchema(TYPE_SUBJECT_REF,
            (writer, value) -> writer.writeValue(STRING, value.value()),
            reader -> new SubjectRef(reader.readValue(STRING)));
    private static final ValueSchema<IssuerRef> ISSUER_REF = valueSchema(TYPE_ISSUER_REF,
            (writer, value) -> writer.writeValue(PKI_ID, value.caId()),
            reader -> new IssuerRef(reader.readValue(PKI_ID)));
    private static final ValueSchema<FormatId> FORMAT_ID = valueSchema(TYPE_FORMAT_ID,
            (writer, value) -> writer.writeValue(STRING, value.value()),
            reader -> new FormatId(reader.readValue(STRING)));
    private static final ValueSchema<Validity> VALIDITY = valueSchema(TYPE_VALIDITY,
            (writer, value) -> {
                writer.writeValue(INSTANT, value.notBefore());
                writer.writeValue(INSTANT, value.notAfter());
            },
            reader -> new Validity(reader.readValue(INSTANT), reader.readValue(INSTANT)));
    private static final ValueSchema<EncodedObject> ENCODED_OBJECT = valueSchema(TYPE_ENCODED_OBJECT,
            FsCodec::writeEncodedObject, FsCodec::readEncodedObject);
    private static final ValueSchema<Principal> PRINCIPAL = valueSchema(TYPE_PRINCIPAL,
            (writer, value) -> {
                writer.writeValue(STRING, value.type());
                writer.writeValue(STRING, value.name());
            },
            reader -> new Principal(reader.readValue(STRING), reader.readValue(STRING)));
    private static final ValueSchema<AttributeId> ATTRIBUTE_ID = valueSchema(TYPE_ATTRIBUTE_ID,
            (writer, value) -> writer.writeValue(STRING, value.value()),
            reader -> new AttributeId(reader.readValue(STRING)));
    private static final ValueSchema<SubjectRdn> SUBJECT_RDN = valueSchema(TYPE_SUBJECT_RDN,
            (writer, value) -> {
                writer.writeValue(SUBJECT_RDN_TYPE, value.type());
                writer.writeValue(STRING, value.value());
            },
            reader -> new SubjectRdn(reader.readValue(SUBJECT_RDN_TYPE), reader.readValue(STRING)));
    private static final ValueSchema<List<SubjectRdn>> SUBJECT_RDNS = listOf(SUBJECT_RDN);
    private static final ValueSchema<SubjectAlternativeName> SUBJECT_ALT_NAME = valueSchema(TYPE_SAN,
            FsCodec::writeSubjectAlternativeName, FsCodec::readSubjectAlternativeName);
    private static final ValueSchema<List<SubjectAlternativeName>> SUBJECT_ALT_NAMES = listOf(SUBJECT_ALT_NAME);
    private static final ValueSchema<AttributeValue> ATTRIBUTE_VALUE = valueSchema(TYPE_ATTRIBUTE_VALUE,
            FsCodec::writeAttributeValue, FsCodec::readAttributeValue);
    private static final ValueSchema<List<AttributeValue>> ATTRIBUTE_VALUES = listOf(ATTRIBUTE_VALUE);
    private static final ValueSchema<AttributeSet> ATTRIBUTE_SET = valueSchema(TYPE_ATTRIBUTE_SET,
            FsCodec::writeAttributeSet, FsCodec::readAttributeSet);

    private static final ValueSchema<List<String>> STRINGS = listOf(STRING);
    private static final ValueSchema<PolicyTraceStep> POLICY_TRACE_STEP = valueSchema(TYPE_POLICY_TRACE_STEP,
            (writer, value) -> {
                writer.writeValue(STRING, value.ruleId());
                writer.writeValue(STRING, value.outcome());
                writer.writeValue(STRINGS, value.notes());
            },
            reader -> new PolicyTraceStep(reader.readValue(STRING), reader.readValue(STRING),
                    reader.readValue(STRINGS)));
    private static final ValueSchema<List<PolicyTraceStep>> POLICY_TRACE_STEPS = listOf(POLICY_TRACE_STEP);
    private static final ValueSchema<PublicationTarget> PUBLICATION_TARGET = valueSchema(TYPE_PUBLICATION_TARGET,
            (writer, value) -> {
                writer.writeValue(PUBLICATION_TARGET_TYPE, value.type());
                writer.writeValue(STRING, value.targetId());
                writer.writeValue(ATTRIBUTE_SET, value.attributes());
            },
            reader -> new PublicationTarget(reader.readValue(PUBLICATION_TARGET_TYPE), reader.readValue(STRING),
                    reader.readValue(ATTRIBUTE_SET)));

    private static final ValueSchema<Optional<Validity>> OPTIONAL_VALIDITY = optionalOf(VALIDITY);
    private static final ValueSchema<Optional<String>> OPTIONAL_STRING = optionalOf(STRING);
    private static final ValueSchema<Optional<Instant>> OPTIONAL_INSTANT = optionalOf(INSTANT);
    private static final ValueSchema<Optional<EncodedObject>> OPTIONAL_ENCODED_OBJECT = optionalOf(ENCODED_OBJECT);
    private static final ValueSchema<Optional<RevocationReason>> OPTIONAL_REVOCATION_REASON =
            optionalOf(REVOCATION_REASON);
    private static final ValueSchema<RevocationTransition> REVOCATION_TRANSITION =
            valueSchema(TYPE_REVOCATION_TRANSITION, FsCodec::writeRevocationTransition,
                    FsCodec::readRevocationTransition);
    private static final ValueSchema<List<RevocationTransition>> REVOCATION_TRANSITIONS =
            listOf(REVOCATION_TRANSITION);

    private static final ValueSchema<Credential> CREDENTIAL_VALUE = valueSchema(TYPE_CREDENTIAL_RECORD,
            FsCodec::writeCredential, FsCodec::readCredential);
    private static final ValueSchema<List<Credential>> CREDENTIALS = listOf(CREDENTIAL_VALUE);

    /* package */ static final Schema<CaRecord> CA_RECORD = topLevel(TOP_CA_RECORD, "CA_RECORD",
            valueSchema(100, FsCodec::writeCaRecord, FsCodec::readCaRecord));
    /* package */ static final Schema<Credential> CREDENTIAL = topLevel(TOP_CREDENTIAL, "CREDENTIAL",
            CREDENTIAL_VALUE);
    /* package */ static final Schema<ParsedCertificationRequest> PARSED_REQUEST = topLevel(TOP_PARSED_REQUEST,
            "PARSED_REQUEST", valueSchema(101, FsCodec::writeParsedRequest, FsCodec::readParsedRequest));
    /* package */ static final Schema<RevocationJournal> REVOCATION_JOURNAL =
            topLevel(TOP_REVOCATION, "REVOCATION_JOURNAL",
                    valueSchema(102, FsCodec::writeRevocationJournal, FsCodec::readRevocationJournal));
    /* package */ static final Schema<StatusObject> STATUS_OBJECT = topLevel(TOP_STATUS_OBJECT, "STATUS_OBJECT",
            valueSchema(103, FsCodec::writeStatusObject, FsCodec::readStatusObject));
    /* package */ static final Schema<PublicationRecord> PUBLICATION = topLevel(TOP_PUBLICATION, "PUBLICATION",
            valueSchema(104, FsCodec::writePublication, FsCodec::readPublication));
    /* package */ static final Schema<PolicyTrace> POLICY_TRACE = topLevel(TOP_POLICY_TRACE, "POLICY_TRACE",
            valueSchema(106, FsCodec::writePolicyTrace, FsCodec::readPolicyTrace));
    /* package */ static final Schema<WorkflowStateRecord> WORKFLOW_STATE = topLevel(TOP_WORKFLOW_STATE,
            "WORKFLOW_STATE", valueSchema(107, FsCodec::writeWorkflowState, FsCodec::readWorkflowState));
    /* package */ static final Schema<SignWorkflowStore.Record> SIGN_WORKFLOW_RECORD = topLevel(
            TOP_SIGN_WORKFLOW_RECORD, "SIGN_WORKFLOW_RECORD",
            valueSchema(108, FsCodec::writeSignWorkflowRecord, FsCodec::readSignWorkflowRecord));
    /* package */ static final Schema<ImportedCertificateProfileVersion> PROFILE_VERSION =
            topLevel(TOP_PROFILE_VERSION, "PROFILE_VERSION",
                    valueSchema(109, FsCodec::writeProfileVersion, FsCodec::readProfileVersion));
    /* package */ static final Schema<CertificateProfileRef> ACTIVE_PROFILE_REF =
            topLevel(TOP_ACTIVE_PROFILE_REF, "ACTIVE_PROFILE_REF", PROFILE_REF);

    private static final Map<Integer, Schema<?>> TOP_LEVEL_SCHEMAS = Map.ofEntries(
            Map.entry(TOP_CA_RECORD, CA_RECORD),
            Map.entry(TOP_CREDENTIAL, CREDENTIAL),
            Map.entry(TOP_PARSED_REQUEST, PARSED_REQUEST),
            Map.entry(TOP_REVOCATION, REVOCATION_JOURNAL),
            Map.entry(TOP_STATUS_OBJECT, STATUS_OBJECT),
            Map.entry(TOP_PUBLICATION, PUBLICATION),
            Map.entry(TOP_POLICY_TRACE, POLICY_TRACE),
            Map.entry(TOP_WORKFLOW_STATE, WORKFLOW_STATE),
            Map.entry(TOP_SIGN_WORKFLOW_RECORD, SIGN_WORKFLOW_RECORD),
            Map.entry(TOP_PROFILE_VERSION, PROFILE_VERSION),
            Map.entry(TOP_ACTIVE_PROFILE_REF, ACTIVE_PROFILE_REF));

    private FsCodec() {
        // utility
    }

    /* package */ static <T> byte[] encode(final Schema<T> schema, final T value) {
        Objects.requireNonNull(schema, "schema");
        Objects.requireNonNull(value, "value");
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            Writer writer = new Writer(output);
            writer.writeInt(CODEC_MAGIC);
            writer.writeUnsignedByte(CURRENT_CODEC_VERSION);
            writer.writeUnsignedByte(schema.typeId);
            schema.valueSchema.encoder.encode(writer, value);
            return output.toByteArray();
        } catch (IOException ex) {
            throw new IllegalStateException("Encoding failed: schema=" + schema.name + " code=ENCODE_FAILED", ex);
        }
    }

    /* package */ static <T> T decode(final Schema<T> schema, final byte[] encoded) {
        Objects.requireNonNull(schema, "schema");
        Objects.requireNonNull(encoded, "encoded");
        try {
            return decodeCurrentPayload(schema, encoded);
        } catch (IOException | IllegalArgumentException ex) {
            throw new IllegalStateException(
                    "Decoding failed: schema=" + schema.name + " code=INVALID_CURRENT_PAYLOAD", ex);
        }
    }

    private static <T> T decodeCurrentPayload(Schema<T> schema, byte[] encoded) throws IOException {
        ByteArrayInputStream input = new ByteArrayInputStream(encoded);
        Reader reader = new Reader(input);
        if (reader.readInt() != CODEC_MAGIC) {
            throw new IOException("codec magic mismatch");
        }
        int version = reader.readUnsignedByte();
        if (version != CURRENT_CODEC_VERSION) {
            throw new IOException("unsupported codec version");
        }
        int typeId = reader.readUnsignedByte();
        Schema<?> encodedSchema = TOP_LEVEL_SCHEMAS.get(typeId);
        if (encodedSchema == null) {
            throw new IOException("unknown top-level type");
        }
        if (encodedSchema.typeId != schema.typeId) {
            throw new IOException("top-level type mismatch");
        }
        T decoded = schema.valueSchema.decoder.decode(reader);
        if (input.available() != 0) {
            throw new IOException("trailing payload data");
        }
        return decoded;
    }

    private static void writeEncodedObject(Writer writer, EncodedObject value) throws IOException {
        writer.writeValue(ENCODING, value.encoding());
        byte[] bytes = value.bytes();
        try {
            writer.writeValue(BYTES, bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static EncodedObject readEncodedObject(Reader reader) throws IOException {
        Encoding encoding = reader.readValue(ENCODING);
        byte[] bytes = reader.readValue(BYTES);
        try {
            return new EncodedObject(encoding, bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static void writeAttributeValue(Writer writer, AttributeValue value) throws IOException {
        switch (value) {
            case AttributeValue.StringValue stringValue -> {
                writer.writeUnsignedByte(ATTRIBUTE_STRING);
                writer.writeValue(STRING, stringValue.value());
            }
            case AttributeValue.BooleanValue booleanValue -> {
                writer.writeUnsignedByte(ATTRIBUTE_BOOLEAN);
                writer.writeValue(BOOLEAN, booleanValue.value());
            }
            case AttributeValue.IntegerValue integerValue -> {
                writer.writeUnsignedByte(ATTRIBUTE_INTEGER);
                writer.writeValue(LONG, integerValue.value());
            }
            case AttributeValue.InstantValue instantValue -> {
                writer.writeUnsignedByte(ATTRIBUTE_INSTANT);
                writer.writeValue(INSTANT, instantValue.value());
            }
            case AttributeValue.BytesValue bytesValue -> {
                writer.writeUnsignedByte(ATTRIBUTE_BYTES);
                byte[] copy = bytesValue.value().clone();
                try {
                    writer.writeValue(BYTES, copy);
                } finally {
                    Arrays.fill(copy, (byte) 0);
                }
            }
        }
    }

    private static AttributeValue readAttributeValue(Reader reader) throws IOException {
        return switch (reader.readUnsignedByte()) {
            case ATTRIBUTE_STRING -> new AttributeValue.StringValue(reader.readValue(STRING));
            case ATTRIBUTE_BOOLEAN -> new AttributeValue.BooleanValue(reader.readValue(BOOLEAN));
            case ATTRIBUTE_INTEGER -> new AttributeValue.IntegerValue(reader.readValue(LONG));
            case ATTRIBUTE_INSTANT -> new AttributeValue.InstantValue(reader.readValue(INSTANT));
            case ATTRIBUTE_BYTES -> readAttributeBytes(reader);
            default -> throw new IOException("unknown attribute value type");
        };
    }

    private static AttributeValue readAttributeBytes(Reader reader) throws IOException {
        byte[] bytes = reader.readValue(BYTES);
        try {
            return new AttributeValue.BytesValue(bytes.clone());
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static void writeAttributeSet(Writer writer, AttributeSet value) throws IOException {
        List<AttributeId> ids = List.copyOf(value.ids());
        writer.writeCount(ids.size());
        for (AttributeId id : ids) {
            writer.writeValue(ATTRIBUTE_ID, id);
            writer.writeValue(ATTRIBUTE_VALUES, value.getAll(id));
        }
    }

    private static AttributeSet readAttributeSet(Reader reader) throws IOException {
        int count = reader.readCount();
        List<SimpleAttributeSet.Entry> entries = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            entries.add(new SimpleAttributeSet.Entry(reader.readValue(ATTRIBUTE_ID),
                    reader.readValue(ATTRIBUTE_VALUES)));
        }
        return new SimpleAttributeSet(entries);
    }

    private static void writeCredential(Writer writer, Credential value) throws IOException {
        writer.writeValue(PKI_ID, value.credentialId());
        writer.writeValue(FORMAT_ID, value.formatId());
        writer.writeValue(ISSUER_REF, value.issuerRef());
        writer.writeValue(SUBJECT_REF, value.subjectRef());
        writer.writeValue(VALIDITY, value.validity());
        writer.writeValue(STRING, value.serialOrUniqueId());
        writer.writeValue(PKI_ID, value.publicKeyId());
        writer.writeValue(PROFILE_BINDING, value.profileBinding());
        writer.writeValue(CREDENTIAL_STATUS, value.status());
        writer.writeValue(ENCODED_OBJECT, value.encoded());
        writer.writeValue(ATTRIBUTE_SET, value.attributes());
    }

    private static Credential readCredential(Reader reader) throws IOException {
        return new Credential(reader.readValue(PKI_ID), reader.readValue(FORMAT_ID), reader.readValue(ISSUER_REF),
                reader.readValue(SUBJECT_REF), reader.readValue(VALIDITY), reader.readValue(STRING),
                reader.readValue(PKI_ID), reader.readValue(PROFILE_BINDING), reader.readValue(CREDENTIAL_STATUS),
                reader.readValue(ENCODED_OBJECT), reader.readValue(ATTRIBUTE_SET));
    }

    private static void writeProfileBinding(Writer writer, CredentialProfileBinding value) throws IOException {
        switch (value) {
            case EndEntityProfileBinding endEntity -> {
                writer.writeUnsignedByte(1);
                writer.writeValue(PROFILE_REF, endEntity.reference());
            }
            case CaProfileBinding ca -> {
                writer.writeUnsignedByte(2);
                writer.writeValue(STRING, ca.profileId());
            }
        }
    }

    private static CredentialProfileBinding readProfileBinding(Reader reader) throws IOException {
        return switch (reader.readUnsignedByte()) {
            case 1 -> new EndEntityProfileBinding(reader.readValue(PROFILE_REF));
            case 2 -> new CaProfileBinding(reader.readValue(STRING));
            default -> throw new IOException("unknown credential profile binding");
        };
    }

    private static void writeCaRecord(Writer writer, CaRecord value) throws IOException {
        writer.writeValue(PKI_ID, value.caId());
        writer.writeValue(CA_KIND, value.kind());
        writer.writeValue(CA_STATE, value.state());
        writer.writeValue(KEY_REF, value.issuerKeyRef());
        writer.writeValue(SUBJECT_REF, value.subjectRef());
        writer.writeValue(CREDENTIALS, value.caCredentials());
    }

    private static CaRecord readCaRecord(Reader reader) throws IOException {
        return new CaRecord(reader.readValue(PKI_ID), reader.readValue(CA_KIND), reader.readValue(CA_STATE),
                reader.readValue(KEY_REF), reader.readValue(SUBJECT_REF), reader.readValue(CREDENTIALS));
    }

    private static void writeParsedRequest(Writer writer, ParsedCertificationRequest value) throws IOException {
        writer.writeValue(PKI_ID, value.requestId());
        writer.writeValue(FORMAT_ID, value.formatId());
        writer.writeValue(SUBJECT_REF, value.subjectRef());
        writer.writeValue(ENCODED_OBJECT, value.publicKeyInfo());
        writer.writeValue(OPTIONAL_VALIDITY, value.requestedValidity());
        writer.writeValue(OPTIONAL_STRING, value.requestedProfileId());
        writer.writeValue(SUBJECT_RDNS, value.subjectRdns());
        writer.writeValue(SUBJECT_ALT_NAMES, value.subjectAlternativeNames());
        writer.writeValue(BOOLEAN, value.subjectAlternativeNamePresent());
        writer.writeValue(ATTRIBUTE_SET, value.attributes());
    }

    private static ParsedCertificationRequest readParsedRequest(Reader reader) throws IOException {
        return new ParsedCertificationRequest(reader.readValue(PKI_ID), reader.readValue(FORMAT_ID),
                reader.readValue(SUBJECT_REF), reader.readValue(ENCODED_OBJECT), reader.readValue(OPTIONAL_VALIDITY),
                reader.readValue(OPTIONAL_STRING), reader.readValue(SUBJECT_RDNS), reader.readValue(SUBJECT_ALT_NAMES),
                reader.readValue(BOOLEAN), reader.readValue(ATTRIBUTE_SET));
    }

    private static void writeRevocationJournal(Writer writer, RevocationJournal value) throws IOException {
        writer.writeValue(PKI_ID, value.credentialId());
        writer.writeValue(LONG, (long) RevocationJournal.CURRENT_VERSION);
        writer.writeValue(REVOCATION_TRANSITIONS, value.transitions());
    }

    private static RevocationJournal readRevocationJournal(Reader reader) throws IOException {
        PkiId credentialId = reader.readValue(PKI_ID);
        long version = reader.readValue(LONG);
        if (version != RevocationJournal.CURRENT_VERSION) {
            throw new IOException("Unsupported revocation journal version");
        }
        return new RevocationJournal(credentialId, reader.readValue(REVOCATION_TRANSITIONS));
    }

    private static void writeRevocationTransition(Writer writer, RevocationTransition value) throws IOException {
        writer.writeValue(LONG, value.revision());
        writer.writeValue(REVOCATION_STATE, value.state());
        writer.writeValue(INSTANT, value.time());
        writer.writeValue(OPTIONAL_REVOCATION_REASON, value.permanentReason());
        writer.writeValue(ATTRIBUTE_SET, value.attributes());
    }

    private static RevocationTransition readRevocationTransition(Reader reader) throws IOException {
        return new RevocationTransition(reader.readValue(LONG), reader.readValue(REVOCATION_STATE),
                reader.readValue(INSTANT), reader.readValue(OPTIONAL_REVOCATION_REASON),
                reader.readValue(ATTRIBUTE_SET));
    }

    private static void writeStatusObject(Writer writer, StatusObject value) throws IOException {
        writer.writeValue(PKI_ID, value.statusObjectId());
        writer.writeValue(FORMAT_ID, value.formatId());
        writer.writeValue(PKI_ID, value.issuerCaId());
        writer.writeValue(STATUS_OBJECT_TYPE, value.type());
        writer.writeValue(INSTANT, value.thisUpdate());
        writer.writeValue(OPTIONAL_INSTANT, value.nextUpdate());
        writer.writeValue(ENCODED_OBJECT, value.encoded());
        writer.writeValue(ATTRIBUTE_SET, value.attributes());
    }

    private static StatusObject readStatusObject(Reader reader) throws IOException {
        return new StatusObject(reader.readValue(PKI_ID), reader.readValue(FORMAT_ID), reader.readValue(PKI_ID),
                reader.readValue(STATUS_OBJECT_TYPE), reader.readValue(INSTANT), reader.readValue(OPTIONAL_INSTANT),
                reader.readValue(ENCODED_OBJECT), reader.readValue(ATTRIBUTE_SET));
    }

    private static void writePublication(Writer writer, PublicationRecord value) throws IOException {
        writer.writeValue(PKI_ID, value.publicationId());
        writer.writeValue(INSTANT, value.time());
        writer.writeValue(PUBLICATION_TARGET, value.target());
        writer.writeValue(PKI_ID, value.objectId());
        writer.writeValue(STRING, value.objectKind());
        writer.writeValue(PUBLICATION_STATUS, value.status());
    }

    private static PublicationRecord readPublication(Reader reader) throws IOException {
        return new PublicationRecord(reader.readValue(PKI_ID), reader.readValue(INSTANT),
                reader.readValue(PUBLICATION_TARGET), reader.readValue(PKI_ID), reader.readValue(STRING),
                reader.readValue(PUBLICATION_STATUS));
    }

    private static void writeProfileVersion(Writer writer, ImportedCertificateProfileVersion value)
            throws IOException {
        writer.writeValue(PROFILE_REF, value.reference());
        writer.writeValue(LONG, (long) value.schemaVersion());
        writer.writeValue(BYTES, value.canonicalJson());
        writer.writeValue(INSTANT, value.importedAt());
    }

    private static ImportedCertificateProfileVersion readProfileVersion(Reader reader) throws IOException {
        CertificateProfileRef reference = reader.readValue(PROFILE_REF);
        int schemaVersion = toInt(reader.readValue(LONG));
        byte[] canonicalJson = reader.readValue(BYTES);
        Instant importedAt = reader.readValue(INSTANT);
        CertificateProfileDefinition definition;
        try {
            definition = CertificateProfileDocumentCodec.parse(canonicalJson);
            return new ImportedCertificateProfileVersion(reference, schemaVersion, definition, canonicalJson,
                    importedAt);
        } finally {
            Arrays.fill(canonicalJson, (byte) 0);
        }
    }

    private static void writeSubjectAlternativeName(Writer writer, SubjectAlternativeName value) throws IOException {
        writer.writeValue(SAN_TYPE, value.type());
        switch (value) {
            case SubjectAlternativeName.DnsName dns -> writer.writeValue(STRING, dns.value());
            case SubjectAlternativeName.IpAddress ip -> writer.writeValue(BYTES, ip.bytes());
            case SubjectAlternativeName.UriName uri -> writer.writeValue(STRING, uri.value());
            case SubjectAlternativeName.Rfc822Name email -> writer.writeValue(STRING, email.value());
        }
    }

    private static SubjectAlternativeName readSubjectAlternativeName(Reader reader) throws IOException {
        return switch (reader.readValue(SAN_TYPE)) {
            case DNS_NAME -> new SubjectAlternativeName.DnsName(reader.readValue(STRING));
            case IP_ADDRESS -> new SubjectAlternativeName.IpAddress(reader.readValue(BYTES));
            case URI -> new SubjectAlternativeName.UriName(reader.readValue(STRING));
            case RFC822_NAME -> new SubjectAlternativeName.Rfc822Name(reader.readValue(STRING));
        };
    }

    private static int toInt(long value) throws IOException {
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw new IOException("integer value out of range");
        }
        return (int) value;
    }

    private static void writePolicyTrace(Writer writer, PolicyTrace value) throws IOException {
        writer.writeValue(PKI_ID, value.decisionId());
        writer.writeValue(POLICY_TRACE_STEPS, value.steps());
    }

    private static PolicyTrace readPolicyTrace(Reader reader) throws IOException {
        return new PolicyTrace(reader.readValue(PKI_ID), reader.readValue(POLICY_TRACE_STEPS));
    }

    private static void writeWorkflowState(Writer writer, WorkflowStateRecord value) throws IOException {
        writer.writeValue(PKI_ID, value.opId());
        writer.writeValue(STRING, value.type());
        writer.writeValue(PRINCIPAL, value.owner());
        writer.writeValue(DURABILITY_POLICY, value.durabilityPolicy());
        writer.writeValue(INSTANT, value.createdAt());
        writer.writeValue(INSTANT, value.updatedAt());
        writer.writeValue(INSTANT, value.expiresAt());
        writer.writeValue(ENCODING, value.payloadEncoding());
        writer.writeValue(OPTIONAL_ENCODED_OBJECT, value.payload());
    }

    private static WorkflowStateRecord readWorkflowState(Reader reader) throws IOException {
        return new WorkflowStateRecord(reader.readValue(PKI_ID), reader.readValue(STRING),
                reader.readValue(PRINCIPAL), reader.readValue(DURABILITY_POLICY), reader.readValue(INSTANT),
                reader.readValue(INSTANT), reader.readValue(INSTANT), reader.readValue(ENCODING),
                reader.readValue(OPTIONAL_ENCODED_OBJECT));
    }

    private static void writeSignWorkflowRecord(Writer writer, SignWorkflowStore.Record value) throws IOException {
        writer.writeValue(PKI_ID, value.submissionId());
        writer.writeValue(STRING, value.namespace());
        writer.writeValue(STRING, value.fingerprint());
        writer.writeValue(PRINCIPAL, value.owner());
        writer.writeValue(INSTANT, value.createdAt());
        writer.writeValue(INSTANT, value.deadline());
        writer.writeValue(ENCODED_OBJECT, value.request());
        writer.writeValue(SIGN_STATE, value.state());
        writer.writeValue(LONG, value.revision());
        writer.writeValue(LONG, value.fence());
        writer.writeValue(OPTIONAL_INSTANT, value.leaseUntil());
        writer.writeValue(OPTIONAL_STRING, value.detailCode());
        writer.writeValue(OPTIONAL_ENCODED_OBJECT, value.result());
        writer.writeValue(OPTIONAL_INSTANT, value.providerUpdatedAt());
    }

    private static SignWorkflowStore.Record readSignWorkflowRecord(Reader reader) throws IOException {
        return new SignWorkflowStore.Record(reader.readValue(PKI_ID), reader.readValue(STRING),
                reader.readValue(STRING), reader.readValue(PRINCIPAL), reader.readValue(INSTANT),
                reader.readValue(INSTANT), reader.readValue(ENCODED_OBJECT), reader.readValue(SIGN_STATE),
                reader.readValue(LONG), reader.readValue(LONG), reader.readValue(OPTIONAL_INSTANT),
                reader.readValue(OPTIONAL_STRING), reader.readValue(OPTIONAL_ENCODED_OBJECT),
                reader.readValue(OPTIONAL_INSTANT));
    }

    private static <T> Schema<T> topLevel(int typeId, String name, ValueSchema<T> valueSchema) {
        return new Schema<>(typeId, name, valueSchema);
    }

    private static <T> ValueSchema<T> valueSchema(int typeCode, Encoder<T> encoder, Decoder<T> decoder) {
        return new ValueSchema<>(typeCode, encoder, decoder);
    }

    private static <E> ValueSchema<E> enumSchema(int typeCode, EnumEncoder<E> encoder, EnumDecoder<E> decoder) {
        return valueSchema(typeCode, (writer, value) -> writer.writeUnsignedByte(encoder.code(value)),
                reader -> decoder.value(reader.readUnsignedByte()));
    }

    private static <T> ValueSchema<List<T>> listOf(ValueSchema<T> elementSchema) {
        return valueSchema(TYPE_LIST, (writer, values) -> {
            writer.writeUnsignedByte(elementSchema.typeCode);
            writer.writeCount(values.size());
            for (T value : values) {
                writer.writeValue(elementSchema, Objects.requireNonNull(value, "list element"));
            }
        }, reader -> {
            reader.requireTypeCode(elementSchema.typeCode);
            int count = reader.readCount();
            List<T> values = new ArrayList<>(count);
            for (int index = 0; index < count; index++) {
                values.add(reader.readValue(elementSchema));
            }
            return List.copyOf(values);
        });
    }

    private static <T> ValueSchema<Optional<T>> optionalOf(ValueSchema<T> elementSchema) {
        return valueSchema(TYPE_OPTIONAL, (writer, value) -> {
            writer.writeUnsignedByte(elementSchema.typeCode);
            if (value.isEmpty()) {
                writer.writeUnsignedByte(MARKER_ABSENT);
                return;
            }
            writer.writeUnsignedByte(MARKER_PRESENT);
            writer.writeValue(elementSchema, value.orElseThrow());
        }, reader -> {
            reader.requireTypeCode(elementSchema.typeCode);
            int marker = reader.readUnsignedByte();
            if (marker == MARKER_ABSENT) {
                return Optional.empty();
            }
            if (marker != MARKER_PRESENT) {
                throw new IOException("invalid optional marker");
            }
            return Optional.of(reader.readValue(elementSchema));
        });
    }

    private static IOException unknownEnum(String type, int code) {
        return new IOException("unknown " + type + " code " + code);
    }

    /**
     * Trusted compile-time description of one approved top-level payload.
     *
     * @param <T> payload value type
     */
    /* package */ static final class Schema<T> {

        private final int typeId;
        private final String name;
        private final ValueSchema<T> valueSchema;

        private Schema(int typeId, String name, ValueSchema<T> valueSchema) {
            this.typeId = typeId;
            this.name = name;
            this.valueSchema = valueSchema;
        }
    }

    /**
     * Typed nested-value codec.
     *
     * @param <T> nested value type
     */
    private record ValueSchema<T>(int typeCode, Encoder<T> encoder, Decoder<T> decoder) {
    }

    /**
     * Writes one value through its declared schema.
     *
     * @param <T> value type
     */
    @FunctionalInterface
    private interface Encoder<T> {
        /**
         * Encodes a value.
         *
         * @param writer destination writer
         * @param value value to encode
         * @throws IOException if encoding fails
         */
        void encode(Writer writer, T value) throws IOException;
    }

    /**
     * Reads one value through its declared schema.
     *
     * @param <T> value type
     */
    @FunctionalInterface
    private interface Decoder<T> {
        /**
         * Decodes a value.
         *
         * @param reader source reader
         * @return decoded value
         * @throws IOException if decoding fails
         */
        T decode(Reader reader) throws IOException;
    }

    /**
     * Maps an approved enum constant to a stable code.
     *
     * @param <T> enum type
     */
    @FunctionalInterface
    private interface EnumEncoder<T> {
        /**
         * Returns the persistent code.
         *
         * @param value enum value
         * @return stable persistent code
         */
        int code(T value);
    }

    /**
     * Maps a stable code to one approved enum constant.
     *
     * @param <T> enum type
     */
    @FunctionalInterface
    private interface EnumDecoder<T> {
        /**
         * Returns the enum value for a code.
         *
         * @param code persistent code
         * @return decoded enum value
         * @throws IOException if the code is unknown
         */
        T value(int code) throws IOException;
    }

    /**
     * Minimal binary writer used only by declared schemas.
     */
    private static final class Writer {

        private final OutputStream output;

        private Writer(OutputStream output) {
            this.output = output;
        }

        private <T> void writeValue(ValueSchema<T> schema, T value) throws IOException {
            Objects.requireNonNull(value, "schema value");
            writeUnsignedByte(schema.typeCode);
            schema.encoder.encode(this, value);
        }

        private void writeString(String value) throws IOException {
            Util.writeUTF8(output, value);
        }

        private void writeBoolean(Boolean value) throws IOException {
            writeUnsignedByte(value ? 1 : 0);
        }

        private void writeLong(Long value) throws IOException {
            Util.writeLong(output, value);
        }

        private void writeBytes(byte[] value) throws IOException {
            Util.write(output, value);
        }

        private void writeInstant(Instant value) throws IOException {
            Util.writeLong(output, value.getEpochSecond());
            Util.writePack7I(output, value.getNano());
        }

        private void writeCount(int count) throws IOException {
            if (count < 0 || count > MAX_COLLECTION_ELEMENTS) {
                throw new IOException("collection size out of range");
            }
            Util.writePack7I(output, count);
        }

        private void writeUnsignedByte(int value) throws IOException {
            if (value < 0 || value > 0xFF) {
                throw new IOException("byte value out of range");
            }
            output.write(value);
        }

        private void writeInt(int value) throws IOException {
            output.write(value >>> 24);
            output.write(value >>> 16);
            output.write(value >>> 8);
            output.write(value);
        }
    }

    /**
     * Minimal binary reader used only by declared schemas.
     */
    private static final class Reader {

        private final InputStream input;

        private Reader(InputStream input) {
            this.input = input;
        }

        private <T> T readValue(ValueSchema<T> schema) throws IOException {
            requireTypeCode(schema.typeCode);
            return schema.decoder.decode(this);
        }

        private void requireTypeCode(int expected) throws IOException {
            int actual = readUnsignedByte();
            if (actual != expected) {
                throw new IOException("nested type mismatch");
            }
        }

        private String readString() throws IOException {
            return Util.readUTF8(input, MAX_COMPONENT_BYTES);
        }

        private Boolean readBoolean() throws IOException {
            int value = readUnsignedByte();
            if (value == MARKER_ABSENT) {
                return Boolean.FALSE;
            }
            if (value == MARKER_PRESENT) {
                return Boolean.TRUE;
            }
            throw new IOException("invalid boolean value");
        }

        private Long readLong() throws IOException {
            return Util.readLong(input);
        }

        private byte[] readBytes() throws IOException {
            return Util.read(input, MAX_COMPONENT_BYTES);
        }

        private Instant readInstant() throws IOException {
            long seconds = Util.readLong(input);
            int nanos = Util.readPack7I(input);
            if (nanos < 0 || nanos > 999_999_999) {
                throw new IOException("invalid instant nanoseconds");
            }
            try {
                return Instant.ofEpochSecond(seconds, nanos);
            } catch (DateTimeException ex) {
                throw new IOException("invalid instant", ex);
            }
        }

        private int readCount() throws IOException {
            int count = Util.readPack7I(input);
            if (count < 0 || count > MAX_COLLECTION_ELEMENTS) {
                throw new IOException("collection size out of range");
            }
            return count;
        }

        private int readUnsignedByte() throws IOException {
            int value = input.read();
            if (value < 0) {
                throw new EOFException("unexpected end of payload");
            }
            return value;
        }

        private int readInt() throws IOException {
            int first = readUnsignedByte();
            int second = readUnsignedByte();
            int third = readUnsignedByte();
            int fourth = readUnsignedByte();
            return first << 24 | second << 16 | third << 8 | fourth;
        }
    }
}
