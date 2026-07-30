/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

/**
 * Closed certificate-specific policy variant.
 */
public sealed interface CertificatePolicy permits LeafCertificatePolicy, CaCertificatePolicy {
}
