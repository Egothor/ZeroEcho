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

## Prepare a local release bundle

Use local staging to inspect the artifacts before publishing. Set the signing
environment variables listed above to a disposable signing identity for a local
trial, and run from the repository root with JDK 25:

```sh
./gradlew check javadoc
python3 -m unittest discover -s tools -p 'test_prepare_central_bundle.py'
./gradlew publishMavenJavaPublicationToCentralBundleRepository -PreleaseVersion=1.2.3
python3 tools/prepare_central_bundle.py --repository build/central-repository --output build/central-bundle.zip --version 1.2.3
```

Replace `1.2.3` consistently with the intended release version. Inspect
`build/central-bundle.zip` for all five publications, sources, Javadoc, POMs and
signatures. Local staging does not upload to a remote publishing repository.

## Publish and recover from a failed release

After the release is approved, push the corresponding `release@x.y.z` tag.
Observe the GitHub workflow and the retained Central deployment UUID. Confirm
Central publication separately before directing consumers to the new version.

If Central rejects the upload, inspect the validation result for that deployment
before retrying. A published Central version cannot be overwritten or removed
through this workflow. Publish corrections under a new version and update the
GitHub release notes with the compatibility impact and required upgrade actions.
