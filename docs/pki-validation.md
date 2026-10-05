# PKI validation evidence

The web, remote CLI and standalone synchronous CLI validation checks completed
on 2026-09-28. This is an evidence record, not an implementation plan. Outstanding
proposals are kept only in [the work plan](project-work-plan.md).

## Functional and quality checks

| Check | Result |
| --- | --- |
| `:pki:test` | 1,538 tests; no failures, errors or skips |
| `:pki-server:test` | 254 tests; no failures, errors or skips |
| `:app:test` | 100 tests; no failures, errors or skips; repeated after final test-task wiring |
| `:pki-frontend:check` | Type checking and 74 tests in 13 files passed |
| PMD main checks for `pki`, `pki-server`, `app` | Passed with unchanged rule set |
| Javadoc for those three modules | Passed; no source-documentation warnings; four warnings remain about external documentation links using unnamed modules |
| Signing-performance source and test compilation | Passed |
| App/server installDist, ZIP and TAR; SPA bundle | Built and inspected |
| Demo Chromium tests | Six passed using installed Chromium |
| `:pki-server:frontendIntegrationTest` | Live backend/browser scenario passed |
| `:pki-server:packagedIntegrationTest` | Actual server/nginx images, SPA and remote CLI passed |
| `:app:packagedLocalRecoveryTest` | Both process-interruption scenarios passed |
| `:app:localPerformanceTest` | Three fresh JVM repetitions passed; no numerical performance gate |

All Gradle checks used `--offline`. Browser gates selected the installed browser
with `-PfrontendBrowser=/usr/bin/chromium-browser`; demo tests used a build-only
configuration selecting that executable. The packaged gate used rootless Podman
images rebuilt from the validated distributions. Gradle also reports deprecated
features relevant to a future Gradle 10 migration; the repository uses Gradle 9.4.0.

The [packaged deployment fixture](../pki-frontend/e2e/packaged/README.md) covers real
mutual TLS, forwarded identity, scoped authorization, independent approval,
known-value selectors, receipt retention, pending exit 7 and observation without
duplicate submission. It removes its containers and private network afterward.

The [local process fixture](../app/docs/local-validation.md) proves that inspection
does not advance durable work, explicit completion publishes a previously stored
signature, and a lost in-flight local result fails with
`LOCAL_RESTART_UNRECOVERABLE` (policy exit 4). Both paths preserve the keyring.
The separately instrumented local-session regression establishes that completion
does not call the signing provider again; deterministic signature equality alone
is not treated as proof of invocation count. Existing unit coverage also retains
local caller-thread/no-reactor behavior, store exclusivity, unknown durability,
internal key proofs, authority lifecycle, issuance, and full/delta CRLs.

[Performance results and raw samples](pki-signing-performance.md#recorded-serial-measurements-2026-09-28)
record the hardware, runtime, workload, latency distribution and separate startup
costs. They are informational and establish no capacity or scaling target.

## License verification

Full normalized source-license text was checked in 1,631 first-party commentable
source/configuration files, including the new test harness, two SVG assets and
fifteen ServiceLoader descriptors. The repair restored 226 incomplete or missing
headers. Existing copyright years and notices were preserved; canonical root
license texts, third-party notices and generated Gradle launcher licenses were
not changed. ServiceLoader provider entries match their pre-change contents, and
both SVG documents parse as XML. Formats without comment syntax are not rewritten
to add invalid comments.

Byte comparisons against `LICENSE-binary.txt` passed for the enabled first-party
`app`, `pki-server`, `pki`, `lib` and `ext` JARs, app/server installation trees and
ZIP/TAR archives, SPA output and ZIP, and both runtime container images.
`samples:jar` is disabled by the existing build. The shared build configuration
selects the source license for an existing `sources` classifier and the binary
license for other JARs; no new artifact variants or dependencies were added.
[Deployment documentation](../deploy/README.md#distribution-licenses) lists the
license locations. Third-party dependencies retain their own licenses.

## Independent review

General, security and performance reviews passed after corrections. Separate
license completeness review found and resolved the initially omitted SVG/service
descriptors and the missing `ext` JAR verification. The final performance review
independently reproduced every displayed statistic from the retained CSV files.
Private build outputs retain diagnostic logs and generated test keys; they are
not distribution artifacts or committed measurement data.
