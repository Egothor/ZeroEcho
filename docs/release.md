# GitHub and Maven Central releases

Push `release@x.y.z` (for example `release@1.2.3`) to run the GitHub release workflow.
Every Java publication uses this version and group `org.egothor`; artifact IDs remain
`ZeroEcho-app`, `ZeroEcho-ext`, `ZeroEcho-lib`, `ZeroEcho-pki`
and `ZeroEcho-pki-server`. The internal `api-spec` generator remains part of
the build and Javadoc checks but is excluded from Maven Central publication. Development builds retain `0.0.0-LOCAL`.
Conflux resolves exclusively from Maven Central at version `1.1.5`.

The repository owner configures these GitHub Actions secrets:

- `CENTRAL_BEARER_TOKEN`: the complete bearer value generated from a Central Portal user token.
  Its account must own the verified `org.egothor` namespace.
- `MAVEN_SIGNING_KEY`: ASCII-armored private PGP key; its public key must be available
  to Maven Central validators.
- `MAVEN_SIGNING_PASSWORD`: the private key passphrase.

The workflow uses Java 25, runs `clean check`, strict Javadoc and license validation,
then stages five signed publications locally. Each contains the JAR, sources JAR,
Javadoc JAR, POM and detached signatures. Binary artifacts use BSD 3-Clause terms;
sources use BSD 4-Clause terms. The Central bundle includes artifact MD5/SHA1
checksums and excludes Gradle/Maven metadata and signature checksums.
The ZIP is retained as a workflow artifact before uploading through the Central
Publisher API using `AUTOMATIC`. The deployment UUID is recorded in the workflow summary. Once Central accepts the
upload, the workflow creates the GitHub release with application TAR/ZIP
distributions. Central validation and publication continue asynchronously; the
GitHub release does not imply that the packages are already available on Central.
Automatic publication is irreversible. Inspect the deployment UUID in Central
Portal for its final result and before retrying if validation later fails;
do not blindly upload the same immutable version again.

## Change scope and acceptance

Baseline: Gitea publication depended on a Gitea token, used development versions,
and resolved Conflux through a private repository. This migration replaces that
release workflow and repository, keeping existing artifact IDs and license rules.
Acceptance: license/tooling tests, module checks and strict Javadoc pass; local
signed staging produces all five complete coordinates; independent review checks
the workflow before merge. Live Central account access and the first real upload
remain the repository owner's release-time checks. No upload is needed for local validation.

For local inspection, run `./gradlew check javadoc` and
`python3 -m unittest discover -s tools -p 'test_prepare_central_bundle.py'`.
With a disposable signing key supplied through the signing environment variables,
run `./gradlew publishMavenJavaPublicationToCentralBundleRepository -PreleaseVersion=1.2.3`
and `python3 tools/prepare_central_bundle.py --repository build/central-repository --output build/central-bundle.zip --version 1.2.3`.
The local stage command has no remote publishing repository.

Rollback before publication: revert the migration commit, remove no tags, and
confirm the previous workflow/conventions are restored with `git diff`. After a
Central version is published it cannot be overwritten or removed through this
workflow; publish a corrected new version and update the GitHub release notes.
The repository owner approves the actual release; this change prepares automation
and does not itself create a tag, GitHub release or Maven Central publication.
