/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api;

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationQuery;

/**
 * Authoritative revocation transition and journal administration.
 */
public interface RevocationService {

    /**
     * Places a credential on hold.
     *
     * @param command hold command
     * @return committed journal
     */
    RevocationJournal hold(RevocationCommand.Hold command);

    /**
     * Removes an existing hold.
     *
     * @param command unhold command
     * @return committed journal
     */
    RevocationJournal unhold(RevocationCommand.Unhold command);

    /**
     * Permanently revokes a credential.
     *
     * @param command permanent revocation command
     * @return committed journal
     */
    RevocationJournal revokePermanently(RevocationCommand.RevokePermanently command);

    /**
     * Retrieves the authoritative journal for one credential.
     *
     * @param credentialId credential identifier
     * @return journal when present
     */
    Optional<RevocationJournal> get(PkiId credentialId);

    /**
     * Searches authoritative journals by their latest transition.
     *
     * @param query administrative query
     * @return matching journals
     */
    List<RevocationJournal> search(RevocationQuery query);
}
