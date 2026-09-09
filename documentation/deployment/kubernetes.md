# Kubernetes

On Kubernetes the PKI server runs as a single-replica StatefulSet with per-instance
PersistentVolumeClaims, and the nginx edge runs as a horizontally scalable
Deployment. Configuration comes from ConfigMaps, secrets from Secrets, and the
health probes exec `curl` over mutual-TLS. This page walks the reference manifests
under `deploy/k8s/`.

## Why a StatefulSet for the server

The store is a single-writer, durable backend that takes an exclusive advisory
lock on open. Two pods sharing one store volume would contend and risk corruption.
The server therefore runs as a StatefulSet with:

- **A single replica per realm store.** Do not scale the StatefulSet above one
  replica against the same volumes.
- **Per-instance PersistentVolumeClaims** for the store, keyring, artifacts, and
  audit, provisioned from `volumeClaimTemplates`.
- **A headless Service**, so the edge reaches the pod by its stable DNS name.

The nginx edge holds no state, so it is a Deployment (the reference uses two
replicas) fronted by a Service.

## Namespace, configuration, and secrets

The first manifest defines the namespace and the read-only configuration and secret
objects.

- A **ConfigMap** carries the server configuration as `server-config.json`.
- A **ConfigMap** carries the certificate-profile documents, one key per file;
  the keys become file names under `/etc/zeroecho/profiles`.
- A **Secret** carries the four passwords, projected into the server with `envFrom`.
- A **Secret** carries the PKCS#12 TLS material, projected at `/etc/zeroecho/tls`.
- A **Secret** carries the health-probe client identity, projected read-only at
  `/etc/zeroecho/health`.

Create the password and TLS Secrets from literals and files rather than committing
values:

```bash
kubectl -n zeroecho-pki create secret generic pki-server-secrets \
  --from-literal=ZEROECHO_KEYRING_PASSWORD=... \
  --from-literal=ZEROECHO_TLS_KEYSTORE_PASSWORD=... \
  --from-literal=ZEROECHO_PROXY_TRUSTSTORE_PASSWORD=... \
  --from-literal=ZEROECHO_ADMIN_TRUSTSTORE_PASSWORD=...

kubectl -n zeroecho-pki create secret generic pki-server-tls \
  --from-file=server-identity.p12 \
  --from-file=proxy-transport-trust.p12 \
  --from-file=administrators-trust.p12
```

The configuration ConfigMap uses absolute in-container paths throughout — the TLS
stores at `/etc/zeroecho/tls/...`, the store, keyring, artifacts, audit, and
control log under `/var/lib/zeroecho/...` — so no working-directory-relative
resolution is involved.

## The server StatefulSet

The StatefulSet pins the runtime identity, mounts configuration and state,
tightens the container security context, and defines exec probes.

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: pki-server
  namespace: zeroecho-pki
spec:
  serviceName: pki-server
  replicas: 1
  selector:
    matchLabels: {app: pki-server}
  template:
    metadata:
      labels: {app: pki-server}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001                 # makes the mounted PVCs writable by the runtime user
        fsGroupChangePolicy: OnRootMismatch
      containers:
        - name: pki-server
          image: zeroecho/pki-server:latest
          ports:
            - {name: admin-mtls, containerPort: 8443}
          envFrom:
            - secretRef: {name: pki-server-secrets}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          volumeMounts:
            - {name: server-config, mountPath: /etc/zeroecho/server-config.json, subPath: server-config.json, readOnly: true}
            - {name: profiles, mountPath: /etc/zeroecho/profiles, readOnly: true}
            - {name: tls, mountPath: /etc/zeroecho/tls, readOnly: true}
            - {name: health, mountPath: /etc/zeroecho/health, readOnly: true}
            - {name: store, mountPath: /var/lib/zeroecho/store}
            - {name: keyring, mountPath: /var/lib/zeroecho/keyring}
            - {name: artifacts, mountPath: /var/lib/zeroecho/artifacts}
            - {name: audit, mountPath: /var/lib/zeroecho/audit}
            - {name: tmp, mountPath: /tmp}
```

A few points worth noting:

- **`readOnlyRootFilesystem: true`** with an `emptyDir` mounted at `/tmp` keeps
  the container image immutable at run time; only the declared volumes are
  writable.
- **`fsGroup: 10001`** makes the claims group-writable by the non-root runtime
  user, which removes the manual `chown` step that bind mounts require.
- **The health Secret** is projected with a restrictive default mode, since it
  contains the probe's private key.

The persistent claims are provisioned per instance. Keep the keyring on a separate
claim from the store, and use POSIX filesystem StorageClasses:

```yaml
  volumeClaimTemplates:
    - metadata: {name: store}
      spec:
        accessModes: ["ReadWriteOnce"]
        resources: {requests: {storage: 20Gi}}
    - metadata: {name: keyring}
      spec:
        accessModes: ["ReadWriteOnce"]
        resources: {requests: {storage: 1Gi}}
    - metadata: {name: artifacts}
      spec:
        accessModes: ["ReadWriteOnce"]
        resources: {requests: {storage: 5Gi}}
    - metadata: {name: audit}
      spec:
        accessModes: ["ReadWriteOnce"]
        resources: {requests: {storage: 10Gi}}
```

## Readiness and liveness probes

The admin listener requires a client certificate even for the health routes, so an
HTTP-only probe cannot complete the handshake. Both probes therefore exec `curl`
with the health-probe client identity mounted at `/etc/zeroecho/health`:

```yaml
          readinessProbe:
            exec:
              command:
                - curl
                - -fsS
                - --max-time
                - "4"
                - --cert
                - /etc/zeroecho/health/health-client.pem
                - --key
                - /etc/zeroecho/health/health-client-key.pem
                - --cacert
                - /etc/zeroecho/health/health-ca.pem
                - https://127.0.0.1:8443/health/ready
            initialDelaySeconds: 15
            periodSeconds: 10
            failureThreshold: 6
          livenessProbe:
            exec:
              command: [ ... same identity ... , "https://127.0.0.1:8443/health/live"]
            initialDelaySeconds: 40
            periodSeconds: 20
            failureThreshold: 3
```

Readiness targets `/health/ready`, which returns `200` only when the realm is ready
to serve; liveness targets `/health/live`, which confirms the process is up. See
[Operations](operations.md#health-endpoints) for the semantics.

## Services and the edge

The server's Service is headless (`clusterIP: None`) and exposes the admin port to
the cluster's internal DNS only. The nginx Deployment reaches it by its fully
qualified service name, set through `PKI_UPSTREAM`:

```yaml
          env:
            - {name: NGINX_SERVER_NAME, value: "pki.example.com"}
            - {name: NGINX_HTTPS_PORT, value: "8443"}
            - {name: PKI_UPSTREAM, value: "pki-server.zeroecho-pki.svc.cluster.local:8443"}
            - {name: PKI_PROXY_SSL_NAME, value: "zeroecho-admin"}
```

The edge Deployment projects its three TLS material sets from Secrets and probes
its own plaintext `/nginx-health` loopback endpoint. Its Service is a
`LoadBalancer` in the reference manifest; if you place it behind an Ingress, that
Ingress must **pass browser mutual-TLS through** to nginx rather than terminating
it, because nginx is where the administrator certificate is verified.

!!! warning "The edge must terminate browser mutual-TLS"
    Do not offload client-certificate verification to an Ingress controller unless
    it forwards the verified certificate in the exact RFC 9440 form the server
    expects. The reference topology relies on nginx performing both the
    termination and the RFC 9440 forwarding. See
    [Security hardening](security-hardening.md).

## Applying the manifests

```bash
kubectl apply -f deploy/k8s/00-namespace-config.yaml
kubectl apply -f deploy/k8s/10-pki-server.yaml
kubectl apply -f deploy/k8s/20-nginx.yaml
```

Replace the placeholder Secrets and the example configuration and profile values
with your realm's own before applying. See [Configuration](configuration.md) for
the field-by-field contract and [Operations](operations.md) for backup, upgrade,
and recovery procedures.
