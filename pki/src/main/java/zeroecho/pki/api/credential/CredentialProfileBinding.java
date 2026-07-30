/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.credential;

/**
 * Closed immutable identity of the policy governing an issued credential.
 */
public sealed interface CredentialProfileBinding permits EndEntityProfileBinding, CaProfileBinding {
}
