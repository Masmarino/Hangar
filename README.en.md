*[Lire en français](README.md)*

# Hangar

Self-hosted artifact repository manager — an npm registry and a Docker/OCI
registry behind one admin console, one auth system, and one set of
governance controls (quotas, retention, RBAC, audit).

Built as a hexagonal/DDD Rust backend (`hangar-domain` → `hangar-application`
→ `hangar-infrastructure`/`hangar-api`, plus protocol adapter crates
`hangar-npm` and `hangar-docker`) with an Angular 22 frontend served from
the same binary.

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Running locally](#running-locally)
- [Deploying](#deploying)
- [Configuration reference](#configuration-reference)
- [Security](#security)
- [Comparison with alternatives](#comparison-with-alternatives)
- [Roadmap](#roadmap)
- [License](#license)

## Features

**Registries**
- npm registry protocol (publish, install, unpublish, dist-tags)
- Docker/OCI registry protocol (push, pull, manifest delete)
- Three repository types per format: **hosted** (you own the content),
  **proxy** (transparent cache in front of an upstream registry, e.g.
  npmjs.org or Docker Hub), **group** (aggregates several repositories
  behind one endpoint)
- Per-repository storage quotas
- Per-repository retention policy (keep the last N versions/tags per
  package/image; tagged references such as `latest` are never purged) —
  swept automatically every 6 hours
- Package/image browser with per-package detail views

**Security scanning**
- npm dependency audit against the public advisory database, auto-triggered
  on publish
- Docker image vulnerability scanning via [Trivy](https://github.com/aquasecurity/trivy),
  auto-triggered on push, plus manual rescan

**Auth & access control**
- Local accounts with Argon2 password hashing
- Mandatory second factor: TOTP or WebAuthn/passkeys, with one-time backup
  codes
- Personal API tokens (scoped per user; admins can list/revoke any token)
- Per-repository RBAC (`read` / `write` / `admin`), granted per user
- Email-based account invitations and activation flow
- Per-process login throttling on failed attempts

**Admin console**
- Usage metrics, hourly metrics-history snapshots, and a health-status page
- Audit log and security-event log
- User management (create, delete, promote to super-admin)
- SMTP settings (host/port/credentials/security/from-name/from-address)
  with a test-email button
- Custom branding: replace the default logo/favicon everywhere (UI +
  emails) for white-label / isolated-cluster deployments
- Configuration export/import for backup and restore
- Transactional HTML emails (account created, password reset, MFA/passkey
  enrolled) with the deployment's branding embedded inline (CID, so it
  renders even with external images blocked)

## Architecture

Hexagonal/DDD, dependencies point inward:

| Crate | Role |
|---|---|
| `hangar-domain` | Entities, value objects, ports (traits) — no framework or I/O dependencies |
| `hangar-application` | Use cases, orchestrating domain logic against ports |
| `hangar-infrastructure` | Port implementations: Postgres, filesystem storage, SMTP, Trivy, Argon2, JWT |
| `hangar-api` | Axum HTTP server, route handlers/DTOs, wires everything together, serves the built frontend |
| `hangar-npm` | npm registry protocol adapter (its own route set, mounted into `hangar-api`) |
| `hangar-docker` | Docker/OCI registry protocol adapter (same pattern) |

Repositories (`PackageRepository`) and permissions are event-sourced;
most other state (users, settings, audit log, metrics) is plain CRUD over
Postgres.

## Tech stack

- **Backend:** Rust (edition 2024), [Axum](https://github.com/tokio-rs/axum), [SQLx](https://github.com/launchbadge/sqlx) + Postgres, [webauthn-rs](https://github.com/kanidm/webauthn-rs), [lettre](https://github.com/lettre/lettre)
- **Frontend:** Angular 22, standalone components, signals (no NgRx)
- **Storage:** local filesystem (`StorageBackendPort` is abstracted, but only a filesystem implementation exists today — see [Roadmap](#roadmap))

## Running locally

```bash
git clone <this-repo>
cd hangar
cp .env.example .env   # fill in POSTGRES_PASSWORD / JWT_SECRET
./scripts/dev.sh
```

This starts Postgres via `docker-compose`, runs the migrations, then runs
the backend (`cargo run -p hangar-api`, port 8081) and the frontend
(`ng serve`, port 4200 with hot reload) side by side. `scripts/dev.sh` sets
`HANGAR_BOOTSTRAP_ADMIN_USERNAME=admin` / `HANGAR_BOOTSTRAP_ADMIN_PASSWORD=admin123`
for you, so you can sign in immediately.

Run tests:

```bash
cargo test --workspace                  # backend
npm test --prefix frontend              # frontend
```

## Deploying

### Docker Compose

A single-node deployment (Hangar + Postgres) is one command away:

```bash
cp .env.example .env   # fill in POSTGRES_PASSWORD, JWT_SECRET, HANGAR_BOOTSTRAP_ADMIN_*
docker compose up -d --build
```

See [Configuration reference](#configuration-reference) below for every
variable `docker-compose.yml` wires through, and note the
`HANGAR_DOCKER_TOKEN_REALM` variable in particular — the Docker registry
protocol will not work for any client outside the container until it's set
to a URL your `docker` CLI can actually reach.

> Kubernetes/Helm deployment: to be documented later.

## Configuration reference

Every variable `hangar-api` reads from its environment.
`docker-compose.yml` already wires through the ones needed for a
single-node deployment; this table is the authoritative reference for a
bare-container deployment or for overriding those defaults.

| Env var | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | **Yes** | — | Postgres connection string, e.g. `postgres://user:pass@host:5432/hangar`. |
| `JWT_SECRET` | **Yes** | — | Signs session tokens and Docker registry access tokens. Long, random, secret. Rotating it invalidates every session and every `docker login`. |
| `HANGAR_BASE_DOMAIN` | **Yes** | — | Base domain organizations are resolved as subdomains of (e.g. `hangar.example`, so `acme.hangar.example` resolves the `acme` organization). No fallback: a misconfigured deployment must fail at startup rather than silently route every subdomain to the public organization. |
| `STORAGE_ROOT` | No | `./data` | Filesystem path where npm tarballs and Docker blobs are stored. Must be a persistent volume in any real deployment. |
| `BIND_ADDR` | No | `0.0.0.0:8080` | Address/port the HTTP server listens on. |
| `STATIC_DIR` | No | `./static` | Path to the built frontend assets served for non-API routes. Only relevant if you're not using the shipped Docker image. |
| `RUST_LOG` | No | — (no logging without it) | `tracing_subscriber` env-filter, e.g. `info` or `hangar_api=debug,info`. Without it, the container logs almost nothing. |
| `CORS_ALLOWED_ORIGIN` | No | permissive (any origin) | Locks CORS to one origin. Leave unset for local dev (`ng serve` on a different port than the backend) or when the frontend is served from the same origin as the API (the shipped image's default setup). |
| `HANGAR_DOCKER_TOKEN_REALM` | Effectively yes, for Docker | derived from `BIND_ADDR` (`http://0.0.0.0:8080/v2/token` — unreachable from outside the container) | Absolute URL of this deployment's own `/v2/token` endpoint, embedded in every `WWW-Authenticate` challenge. The Docker CLI resolves `login`/`push`/`pull` token requests against it — get this wrong and the entire Docker auth flow fails for real clients. Must be `https://` for any non-localhost host (`docker` refuses plain `http://` otherwise). |
| `PUBLIC_URL` | Effectively yes, once invitations are used | derived from `BIND_ADDR` (same unreachable-from-outside caveat) | Base URL account-invitation links are built against. Must be reachable from the recipient's mail client. |
| `HANGAR_BOOTSTRAP_ADMIN_USERNAME` | No | — | Username for the account auto-created **only when the `users` table is empty**. Safe to leave set across restarts/upgrades. |
| `HANGAR_BOOTSTRAP_ADMIN_PASSWORD` | No, but you need *some* way to get a first admin | — | Password for that same bootstrap account. Must be ≥ 8 characters — a shorter value fails silently (logged, not fatal) and leaves the deployment with no admin at all. |

Both `HANGAR_DOCKER_TOKEN_REALM` and `PUBLIC_URL` fall back to guessing a
URL from `BIND_ADDR`, which is only ever correct for a deployment reached
directly with no reverse proxy and no TLS termination — set them
explicitly in every other case.

**Not environment-configurable today** (hardcoded): the metrics-snapshot
sweep (hourly) and the retention-policy sweep (every 6 hours). The Docker
image scanner shells out to a `trivy` binary that must be on `PATH` (the
shipped Dockerfile installs it; a custom image build needs to install it
too).

## Security

- Argon2 password hashing
- Mandatory MFA (TOTP or WebAuthn/passkeys) with one-time backup codes
- A distinct, short-lived "password verified but not 2FA verified" token
  type, kept deliberately non-interchangeable with a full session token
- Per-repository RBAC, enforced on every route — not just hidden in the UI
- Audit log and security-event log for admin review
- Format-sniffed (magic-byte) validation on uploaded assets (branding
  logo/favicon), never trusting a client-supplied `Content-Type`

Found a security issue? Please report it privately rather than opening a
public issue.

## API Reference — Authentication

- **`POST /api/auth/login`** — authenticates a user with credentials (username + password); returns an MFA-enrollment response on success.
- **`POST /api/auth/register`** — self-registers a new account in the public organization (disabled on any other organization's subdomain); returns the same MFA-enrollment response as login.

## Comparison with alternatives

Hangar isn't the only option for self-hosting an npm and/or Docker
registry. Here's where it stands against three industry references — on
feature scope and license cost, not performance numbers: no comparative
benchmark has been run across these four tools, and it would be
dishonest to make one up.

| | **Hangar** | Nexus Repository (Community Edition) | Harbor | JFrog Artifactory |
|---|---|---|---|---|
| npm | ✅ | ✅ | ❌ | Paid (Pro) only |
| Docker / OCI | ✅ | ✅ | ✅ | Paid (Pro) only |
| Other formats (Maven, PyPI, NuGet, Cargo, Helm…) | ❌ *(roadmap)* | ✅ 20+ formats | OCI only (Helm, SBOM, OPA…) | ✅ 60+ formats *(Pro)* |
| MFA | **Mandatory**, built-in (TOTP/passkey) | Optional, SSO in Pro | Optional | Optional, SSO in Pro |
| LDAP/SAML/OIDC | ❌ *(roadmap)* | Pro | ❌ | Pro |
| Built-in vulnerability scanning | ✅ Trivy, built-in | Separate product (Sonatype Lifecycle) | ✅ Trivy, built-in | Paid (Xray) |
| Multi-tenant / isolated projects | ❌ *(roadmap)* | ✅ | ✅ | ✅ |
| Free self-hosting | ✅ | ✅ (Community Edition) | ✅ (Apache 2.0, CNCF project) | Java only — Docker/npm require the paid tier |

**Estimated annual cost, self-hosted, excluding infrastructure and
operations** (sourced figures — most of these vendors have no public
list price, see the notes):

- **Hangar** — free, no license.
- **Harbor** — free, Apache 2.0, CNCF project, no paid tier at all.
- **Nexus Repository Community Edition** — free for npm, Docker, Maven,
  PyPI, and about fifteen other formats. Pro (SSO, high availability,
  replication) has no public price; third-party estimates put it around
  $120/user/year, or $50,000–$150,000+/year bundled with the full
  Sonatype platform[^nexus-pricing].
- **JFrog Artifactory** — the open-source edition (Apache 2.0) only
  covers the Java ecosystem (Maven/Gradle/Ivy): no Docker, no npm. To
  get the two formats Hangar covers natively and for free, you need
  Pro X, whose published self-hosted starting price is $27,000/year for
  one server[^jfrog-pricing], climbing well beyond that at enterprise
  scale.

[^nexus-pricing]: [Sonatype Nexus Repository Pricing Guide — CloudRepo](https://www.cloudrepo.io/articles/sonatype-nexus-repository-pricing-guide)
[^jfrog-pricing]: [JFrog Artifactory Pricing Guide — CloudRepo](https://www.cloudrepo.io/articles/jfrog-artifactory-pricing-guide)

**Recommended hardware configuration** (figures taken from each
product's official documentation, not from a comparative benchmark):

| | **Hangar**[^hangar-bench] | Nexus Repository (Community Edition) | Harbor | JFrog Artifactory (Pro X, self-hosted) |
|---|---|---|---|---|
| Minimum CPU | 0.5 core | 2 cores ("Small" profile)[^nexus-sysreq] | 2 cores[^harbor-prereqs] | 4 cores, up to 20 active clients[^jfrog-sizing] |
| Recommended CPU | 1 core | 4 to 8 cores depending on profile[^nexus-sysreq] | 4 cores[^harbor-prereqs] | 6 to 8 cores, up to 200 active clients[^jfrog-sizing] |
| Minimum RAM | 128 MB | 8 GB[^nexus-sysreq] | 4 GB[^harbor-prereqs] | 6 GB, up to 20 active clients[^jfrog-sizing] |
| Recommended RAM | 256 MB | 8 to 32 GB depending on profile[^nexus-sysreq] | 8 GB[^harbor-prereqs] | 12 to 18 GB, up to 200 active clients[^jfrog-sizing] |
| Disk | not measured | ≥ 4 GB free at all times (falls back to read-only otherwise); 500 GB+ common with Docker/Maven[^nexus-sysreq] | 40 GB minimum, 160 GB recommended[^harbor-prereqs] | not quantified in the general docs; SSD recommended[^jfrog-sysreq] |
| Database | PostgreSQL, required | Embedded H2 for evaluation, PostgreSQL recommended in production[^nexus-sysreq] | PostgreSQL bundled with the installer | External PostgreSQL, required in production[^jfrog-sysreq] |
| Runtime | Native Rust binary, no JVM | JVM, Java 21 required[^nexus-sysreq] | Go, several containers, no JVM | JVM, bundled JDK 21[^jfrog-sysreq] |

[^hangar-bench]: Measured, not documented: the `hangar-api` container
    capped via `docker run --cpus`/`--memory` (cgroup v2), against 15-20
    simulated clients (npm install/publish + docker pull/push, mostly
    reads) for 2-3 minutes. RAM and CPU read directly from the
    container's `/sys/fs/cgroup/memory.current` and `cpu.stat`, not
    estimated. "Minimum" = 0.5 core / 128 MB: the load completes with no
    application-level failure, but with noticeable CPU throttling
    (~68% of run time throttled) and RAM right at the ceiling.
    "Recommended" = 1 core / 256 MB: 2185 requests, 2 failures, residual
    throttling (~3% of run time), RAM with headroom (peaked at 92 MB).
    Measured on a development machine, not dedicated server hardware —
    not directly comparable to the other three vendors' methodology,
    which document sizing profiles for production deployments on
    dedicated hardware.
[^nexus-sysreq]: [Sonatype Nexus Repository System Requirements](https://help.sonatype.com/en/sonatype-nexus-repository-system-requirements.html)
[^harbor-prereqs]: [Harbor Installation Prerequisites](https://goharbor.io/docs/2.13.0/install-config/installation-prereqs/)
[^jfrog-sizing]: [JFrog Hardware Sizing Matrix](https://docs.jfrog.com/installation/docs/hardware-sizing-matrix)
[^jfrog-sysreq]: [JFrog General System Requirements](https://docs.jfrog.com/installation/docs/general-system-requirements)

### Scaling up

Still measured, not documented: the table above comes from a modest load
(15-20 clients). To see how Hangar handles more concurrency, same
container (4 cores / 2 GB), but this time driven by an async HTTP load
generator (Python/aiohttp) instead of real npm/docker CLI processes per
client — that's what let this go up to 100 and 200 simultaneous clients
without multiplying heavy processes on the test machine[^hangar-scale]:

| Concurrent clients | Throughput | Failures | p95 (npm install) | Avg CPU | RAM (peak) |
|---|---|---|---|---|---|
| 20 | ~490 req/s | 0 | 90 ms | 108% (of 4 cores) | 549 MB |
| 100 | ~476 req/s | 0 | 360 ms | 108% | 568 MB |
| 200 | ~268 req/s | 0 | 1,781 ms | 81% | 527 MB |

Zero application-level failures at every tier, including at 200 clients:
Hangar slows down under heavy load but doesn't break. The less flattering
part, stated plainly: throughput **drops** between 100 and 200 clients
(476 → 268 req/s) while CPU usage drops too (108% → 81%) — a sign of a
bottleneck that isn't raw core count (likely the PostgreSQL connection
pool or contention on the async event loop, though not investigated
further). One run per tier, on a development machine: take it as an
order of magnitude, not a capacity guarantee.

**More CPU, more throughput** — still at 100 clients, doubling the CPU
allocation clearly moves sustained throughput:

| Config | Throughput at 100 clients | CPU throttling |
|---|---|---|
| 4 cores / 2 GB | ~476 req/s | noticeable |
| 8 cores / 2 GB | ~690 req/s | light |

No "recommended RAM for 100 clients" row here, deliberately: with a
client that fires with no rate limit at all, observed RAM grows with the
**test's duration** (an accumulating backlog of pending requests), not
with a stable per-client cost — over 15s it plateaued at 1.2 GB, over
60s it filled the 4 GB allocated. A trustworthy RAM figure would need a
load generator with a capped request rate (realistic requests/second
instead of full-throttle), which wasn't done here.

[^hangar-scale]: Load generator: Python `aiohttp`, direct HTTP calls
    against the same endpoints a real client hits (npm metadata + tarball,
    Docker token + manifest + blob), bypassing the `npm`/`docker` CLIs
    entirely. Same mix as the note above (mostly reads). CPU/RAM read
    from the same cgroup counters as the table above.

**What these two tables don't say**: no comparative benchmark has been
run against Nexus, Harbor, or Artifactory — the figures above are Hangar
only. Nexus and Harbor are also mature projects, deployed at scale for
years, with features Hangar doesn't have yet (see the
[roadmap](#roadmap)): enterprise identity, high availability,
multi-tenancy, more package formats.

## Roadmap

Hangar is an active project, not a finished product: quotas, retention,
built-in security scanning (Trivy + npm audit), customizable branding, and
mandatory MFA are already native. The list below is what we genuinely want
to build next — in rough priority order.

**Strengthening the foundations**
- [ ] Enterprise identity: LDAP/Active Directory, SAML, OIDC/SSO — today
      only local accounts + TOTP/passkeys exist
- [ ] More package formats: Maven/Gradle, PyPI, NuGet, Cargo, Go modules,
      Helm charts, generic/raw repositories — `hangar-npm`/`hangar-docker`
      already show the adapter pattern to follow
- [ ] Object-storage backend (S3-compatible) behind `StorageBackendPort`,
      to unblock multi-replica deployments (today: one filesystem volume,
      one replica)
- [ ] High availability / clustering, geo-replication
- [ ] Package signing / provenance (Sigstore, npm provenance)

**Thinking bigger: an open registry**
- [ ] Multi-tenant organizations and per-user namespaces, distinct from
      today's single global admin model
- [ ] Public, unauthenticated read access for public packages
- [ ] Rate limiting and abuse prevention for anonymous traffic
- [ ] Public search and package-discovery pages
- [ ] CDN-backed global artifact distribution

## License

No license file is currently included in this repository — treat the
source as all-rights-reserved until one is added.
