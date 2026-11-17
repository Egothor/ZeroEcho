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
package zeroecho.pki.server.acme;

/**
 * Holds stateless collaborators that borrow one ACME facade and its monitor.
 */
final class AcmeCollaborators {
    /**
     * Handles directory operations for the owning service.
     */
    /* default */ final AcmeDirectoryOperations directory;
    /**
     * Handles policy operations for the owning service.
     */
    /* default */ final AcmePolicyOperations policy;
    /**
     * Handles accounts operations for the owning service.
     */
    /* default */ final AcmeAccountsOperations accounts;
    /**
     * Handles orders operations for the owning service.
     */
    /* default */ final AcmeOrdersOperations orders;
    /**
     * Handles enrollment operations for the owning service.
     */
    /* default */ final AcmeEnrollmentOperations enrollment;
    /**
     * Handles challenges operations for the owning service.
     */
    /* default */ final AcmeChallengesOperations challenges;
    /**
     * Handles confirmation operations for the owning service.
     */
    /* default */ final AcmeConfirmationOperations confirmation;
    /**
     * Handles shared operations for the owning service.
     */
    /* default */ final AcmeSharedOperations shared;
    /**
     * Frozen enrollment binding validation.
     */
    /* default */ final AcmeEnrollmentBindings bindings;
    /**
     * Creates operation handlers for the supplied service without performing protocol or I/O work.
     */
    /* default */ AcmeCollaborators(AcmeService owner) {
        directory = new AcmeDirectoryOperations(owner);
        policy = new AcmePolicyOperations(owner);
        accounts = new AcmeAccountsOperations(owner);
        orders = new AcmeOrdersOperations(owner);
        enrollment = new AcmeEnrollmentOperations(owner);
        bindings = new AcmeEnrollmentBindings(owner);
        challenges = new AcmeChallengesOperations(owner);
        confirmation = new AcmeConfirmationOperations(owner);
        shared = new AcmeSharedOperations(owner);
    }
}
