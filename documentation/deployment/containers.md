# Container images

The platform ships as two images. This page describes what each image contains,
how to build or obtain them, and how to run them together with Docker Compose. For
the volume and environment contract they consume, see [Configuration](configuration.md).

## The PKI server image

The server image (`zeroecho/pki-server`) bundles the long-lived administrative
HTTPS server and a local command-line utility used only at start-up. It is built
in stages:

- A build stage compiles the server and CLI distributions on a Java 25 toolchain.
  This stage needs no Node or frontend tooling.
- A slim runtime stage copies the two distributions onto a JRE base, installs
  `curl` for the health-check probe, and creates a non-root user (`zeroecho`,
  uid/gid `10001`).

The image pre-creates the four data directories owned by that user, declares them
as volumes, exposes the admin listener on port `8443`, and defines a `HEALTHCHECK`
that probes `/health/ready` over mutual-TLS. Its entrypoint performs a start-up
sequence before handing off to the server:

1. **Validate the configuration.** It runs `zeroecho-pki-server --validate-config
   --config <file>`, which parses and fully validates the strict versioned JSON
   without opening any provider, listener, or the store. An invalid configuration
   fails the container immediately.
2. **Reconcile certificate profiles.** For each profile document in the profiles
   directory, it registers and activates any profile whose identifier is not
   already present in the store. This runs against the same on-disk store the
   server will open, before the server takes its exclusive lock.
3. **Start the server as PID 1** so it receives `SIGTERM` directly and runs its
   own graceful-shutdown hook.

!!! note "Profile reconcile is identity-scoped"
    The start-up reconcile registers profiles whose identifier is new. It does not
    re-import a profile identifier that already exists, so editing an existing
    profile's content and restarting does not update it. To change an existing
    profile, register a new version through the console or CLI. Set
    `ZEROECHO_PROFILE_RECONCILE=off` to disable the start-up reconcile entirely.
    See [Configuration](configuration.md#changing-a-certificate-profile).

## The nginx edge image

The edge image (`zeroecho/pki-nginx`) serves the web console and reverse-proxies
the API to the PKI server. It is built in stages:

- A build stage compiles the single-page console bundle with a pinned Node
  toolchain. The build emits hashed, content-addressed assets and an
  `index.html`.
- A runtime stage layers the nginx configuration, the console bundle, and the
  **njs** module onto the stock nginx image.

nginx does three things at the edge:

- **Serves the console bundle** as static files, with immutable caching for hashed
  assets and revalidation of the app shell.
- **Terminates the browser's client certificate** (`ssl_verify_client on`),
  accepting the handshake only if the certificate chains to the administrators'
  trust bundle.
- **Forwards the verified identity** to the PKI server as an RFC 9440 `Client-Cert`
  header, while authenticating upstream with its own transport client certificate.

The njs module exists because RFC 9440 requires the header value to be a
Structured-Fields Byte Sequence — a colon, the base64 of the DER certificate, and
a closing colon. Stock nginx exposes the client certificate only as PEM, so the
bundled `client_cert.js` strips the PEM armour and whitespace and wraps the result
in colons to produce the canonical value the server's strict parser expects.

nginx also exposes a plaintext loopback endpoint, `/nginx-health`, used only by its
own container health check to prove the process is serving. It is not reachable off
the box.

## Building or obtaining the images

Build both images from the repository root on a POSIX host with a container engine:

```bash
docker compose -f deploy/compose/docker-compose.yml build
```

The server build stage runs the Gradle `installDist` tasks for the server and CLI;
the nginx build stage runs the pinned Node build of the console. If your build
pipeline has already produced the server and CLI distribution trees, or the console
bundle, use the images' `prebuilt` build targets to inject those artifacts and skip
the source build.

!!! tip "Pin base images by digest for production"
    The Dockerfiles reference their base images by tag as an interim. For
    supply-chain reproducibility, replace those tags with `image@sha256:<digest>`
    from your own registry mirror.

## Running with Docker Compose

The reference Compose stack runs both containers on a private bridge network,
publishes only the nginx edge to the host, and wires the health checks so nginx
starts after the server is healthy.

```bash
cp deploy/.env.example deploy/.env      # then edit deploy/.env and provision TLS material
docker compose -f deploy/compose/docker-compose.yml up -d --build
```

The stack reads all secrets and host paths from `deploy/.env`. Every secret and
mount path is a required variable — Compose refuses to start if one is unset. The
key service settings are:

```yaml
services:
  pki-server:
    image: zeroecho/pki-server:latest
    expose:
      - "8443"                 # reachable only from the private network, never published
    volumes:
      - store:/var/lib/zeroecho/store
      - keyring:/var/lib/zeroecho/keyring
      - artifacts:/var/lib/zeroecho/artifacts
      - audit:/var/lib/zeroecho/audit

  nginx:
    image: zeroecho/pki-nginx:latest
    depends_on:
      pki-server:
        condition: service_healthy
    ports:
      - "${NGINX_PUBLISH_HTTPS:-8443}:8443"   # the only host-published port
      - "${NGINX_PUBLISH_HTTP:-8080}:80"
```

Inside the container the edge listens on `8443` for HTTPS and on `80` for the
plain-HTTP redirect to HTTPS; the Compose file maps those to host ports `8443` and
`8080` by default.

!!! warning "First-mount ownership for the data volumes"
    On first mount of an **empty Docker named volume**, the runtime copies the
    image's directory ownership (uid `10001`, mode `0700` for the store and
    keyring), so the non-root server can write. A **bind mount** does not inherit
    that ownership — `chown -R 10001:10001` the host path and `chmod 700` the
    store and keyring paths before the first start. See
    [Configuration](configuration.md#volumes).

Once the stack is up, you can run the end-to-end smoke test, which drives one
issuance flow through the edge over mutual-TLS:

```bash
deploy/smoke-test.sh
```

The smoke test speaks the administrative HTTPS API directly with `curl` over
mutual-TLS, because that API is the platform's only network client contract. See
[Operations](operations.md) for what a healthy run looks like and
[Configuration](configuration.md) for the variables the test reads.
