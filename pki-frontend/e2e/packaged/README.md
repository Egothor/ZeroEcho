# Packaged deployment gate

Run from the repository root after building the current app/server distributions,
frontend bundle, and the deployment Dockerfiles' `prebuilt` targets:

```sh
./gradlew :pki-server:packagedIntegrationTest --offline \
  -PfrontendBrowser=/usr/bin/chromium-browser
```

The default image names are `localhost/zeroecho-pki-server:integration-test` and
`localhost/zeroecho-pki-nginx:integration-test`. Override them with `-PpackagedServerImage`
and `-PpackagedNginxImage`. The task never pulls or builds images. It requires
rootless Podman, curl, the existing Playwright installation, and Chromium.
Build each image with the repository root as its context, including the canonical
`LICENSE-binary.txt` copied into both runtime images. Prebuilt distribution trees
and the SPA bundle retain their own copies as well.
`-PfrontendNode` can select an existing Node executable.

The JVM fixture seeds a private store using existing realm APIs, closes the seed
session, and launches the actual server and nginx images on an invocation-owned
internal network. Only nginx publishes a randomly allocated loopback TLS port. Bind mounts use
Podman shared SELinux labels (`z`) because both containers access test TLS
material; relabeling is confined to the invocation-owned private fixture directory.
Both browser identities and the packaged CLI present real client certificates;
nginx forwards verified identity over its own authenticated upstream connection.
There is no test HTTP bridge, authentication override, or production fault hook.

Certificates are generated for each invocation with current-time validity. CLI,
curl and Playwright API requests validate the fixture CA and hostname. Chromium
uses `--ignore-certificate-errors-spki-list` limited to the exact ephemeral edge
public key; this avoids modifying OS/user trust stores and does not enable
universal certificate-error bypass. `ignoreHTTPSErrors` remains false.

The scenario covers missing-client-certificate rejection, authority-scoped denial,
independent approval, actual SPA selectors, client observation failure, and one
accepted submission per signing operation. CLI zero-wait exit 7 retains the ID;
subsequent commands only inspect that ID. Container access logs corroborate the
accepted POST count.

Each run retains fixture state, command logs and failure traces under
`build/pki-validation/packaged/run-*` in a private directory, including generated test keys.
Containers and the invocation-owned network are removed in `finally`, even when
the test fails. Ordinary JVM and browser tests exclude this gate.
