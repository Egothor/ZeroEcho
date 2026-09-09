# Operations

This page covers running the platform day to day: checking health, backing up and
restoring the volumes, upgrading the images, recovering from disaster, and handling
logs and audit records.

## Health endpoints

The PKI server exposes two health routes on its admin listener. Both are served
before authentication, but the listener still requires a client certificate to
complete the TLS handshake, so a probe must present a certificate trusted by the
listener's client trust.

| Endpoint | Meaning | Response |
|---|---|---|
| `GET /health/live` | The process is up and responding. | `200` with `LIVE`. |
| `GET /health/ready` | The realm is ready to serve requests. | `200` with `READY`, or `503` with `NOT_READY`. |

Use liveness to decide whether to restart a stuck process, and readiness to decide
whether to route traffic. The container `HEALTHCHECK` and the Kubernetes probes
both target these endpoints with a dedicated **health-probe client identity** — a
client certificate whose issuer is trusted by the admin listener — mounted at
`/etc/zeroecho/health`.

```bash
curl -fsS --max-time 4 \
  --cert  /etc/zeroecho/health/health-client.pem \
  --key   /etc/zeroecho/health/health-client-key.pem \
  --cacert /etc/zeroecho/health/health-ca.pem \
  https://127.0.0.1:8443/health/ready
```

nginx has its own plaintext loopback endpoint, `/nginx-health`, used only by its
container health check to prove the edge process is serving. It is not reachable
off the box.

## Backup and restore

The store is the system of record and the keyring holds the CA private keys. Back
both up; the artifacts and audit volumes matter for republication and retention.

| Volume | Backup priority | Notes |
|---|---|---|
| `store` | Highest | Cannot be reconstructed. Back it up consistently. |
| `keyring` | Highest | Private-key material. Back it up separately, with stricter access. |
| `audit` | High | Retain per your audit-retention policy. Append-heavy. |
| `artifacts` | Lower | Reconstructible by republishing from the store. |

!!! warning "Take a consistent snapshot, not a live copy"
    The store commits with atomic rename and directory `fsync`, so a crash-consistent
    snapshot is safe to restore. A file-by-file copy of a **running** server can
    capture a torn intermediate state. Prefer one of these:

    - Stop the server, copy the volumes, then restart — the simplest consistent
      backup.
    - Use a filesystem or block-storage snapshot that is atomic across the volume.

Because the store enforces a single writer, never restore into a volume that a
running server already holds open. Restore into a stopped instance, then start it.

To restore, place the backed-up contents into fresh volumes with the correct
ownership (uid `10001`) and permissions (`0700` for store and keyring), mount them
at the same in-container paths, and start the server. Since the configuration uses
in-container paths, no configuration change is needed to point at restored storage.

## Upgrades

The images carry no persistent state, so an upgrade replaces the image while the
volumes carry the state forward.

1. Validate the configuration against the new image if the configuration schema may
   have changed: `zeroecho-pki-server --validate-config --config <file>`.
2. Back up the store and keyring volumes.
3. Roll the image.

=== "Compose"

    ```bash
    docker compose -f deploy/compose/docker-compose.yml pull
    docker compose -f deploy/compose/docker-compose.yml up -d
    ```

    The server receives `SIGTERM` and runs its graceful-shutdown hook before the
    new container starts.

=== "Kubernetes"

    ```bash
    kubectl -n zeroecho-pki set image statefulset/pki-server \
      pki-server=zeroecho/pki-server:<new-tag>
    ```

    Because the store is single-writer, the StatefulSet's single replica is
    replaced one pod at a time — the old pod terminates and releases the store lock
    before the new pod acquires it. The nginx Deployment can roll independently
    with its default rolling strategy.

!!! note "Certificate profiles on upgrade"
    On start-up the entrypoint reconciles profiles by identity — it registers new
    profile identifiers but does not overwrite existing ones. Plan profile changes
    as new versions registered through the console or
    [command line](../admin/command-line.md), not as edits picked up on restart.
    See [Configuration](configuration.md#changing-a-certificate-profile).

## Disaster recovery

To rebuild the platform from backups:

1. Provision fresh POSIX volumes for the store, keyring, artifacts, and audit with
   the correct ownership and permissions.
2. Restore the store and keyring backups into them. The artifacts volume can be
   left empty and repopulated by republishing from the store.
3. Restore the read-only configuration and TLS material, and set the password
   environment variables.
4. Start a single server instance. Confirm `/health/ready` returns `200`.
5. Republish artifacts if the artifacts volume was not restored.

Keep the keyring backup and its unlock password under separate control from the
store backup, so that a single compromised backup does not yield both the state and
the keys to sign against it.

## Logs and audit

Two distinct streams exist, and they serve different purposes.

- **Operational logs.** The server and the entrypoint write diagnostic logs to
  standard error; nginx writes access and error logs. Collect these through your
  container platform's normal log pipeline. The nginx access log records the
  verified client distinguished name, request line, status, and timings.
- **The durable audit sink.** The server writes audit records to the audit volume.
  This is the authoritative record of administrative activity and is append-heavy.
  Retain it per your audit-retention policy and treat it as evidence, not as
  rotating diagnostics. See [Audit and disclosure](../admin/audit-and-disclosure.md)
  for what the records contain and how to work with them.

!!! tip "Do not put secrets in logs"
    Passwords arrive only through environment variables and never appear in the
    configuration file or the logs. Keep it that way when adding your own log
    processing — avoid echoing environment values in wrapper scripts.

## Smoke-testing a deployment

After a deploy or upgrade, the bundled smoke test drives one end-to-end issuance
flow through the edge over mutual-TLS and asserts a terminal success:

```bash
deploy/smoke-test.sh
```

It waits for `/health/ready` through the edge, confirms an authenticated
administrative identity is accepted (proving the mutual-TLS to RFC 9440 to
forwarded-identity chain works), then imports a request and issues one credential —
following the signing operation to completion if issuance is asynchronous. It reads
its parameters (the base URL, an administrator client identity, a CA identifier, and
an active profile identifier) from `deploy/.env`. See
[Configuration](configuration.md) for those variables.
