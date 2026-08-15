CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Exactly one organization may be the public one.
CREATE UNIQUE INDEX organizations_single_public_idx ON organizations ((is_public)) WHERE is_public;

-- Fixed id so every environment (dev, test, prod) agrees on it without a lookup.
INSERT INTO organizations (id, slug, display_name, is_public)
VALUES ('00000000-0000-0000-0000-000000000001', 'public', 'Public', true);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_super_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_organization_admin BOOLEAN NOT NULL DEFAULT FALSE,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    -- Nullable: an invited-but-not-activated account gets an unusable placeholder password_hash instead, so Argon2 verification needs no special case for "pending" accounts.
    email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Bumped to now() on password change, so a leaked/stolen session token stops working.
    tokens_valid_after TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_unique ON users (email) WHERE email IS NOT NULL;

-- Source of truth for the Permission and PackageRepository aggregates, and a plain append-only log for security events. aggregate_id is TEXT, not UUID, because Permission is
-- keyed by a composite "{user_id}:{repository_id}" identity, not a single UUID.
CREATE TABLE domain_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    version BIGINT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id UUID,
    UNIQUE (aggregate_type, aggregate_id, version)
);
CREATE INDEX domain_events_aggregate_idx ON domain_events (aggregate_type, aggregate_id, version);
CREATE INDEX domain_events_occurred_at_idx ON domain_events (occurred_at DESC);
-- Supports the audit log's "everything this actor did" filter.
CREATE INDEX domain_events_actor_id_idx ON domain_events (actor_id, occurred_at DESC);
-- The admin audit route also accepts aggregate_id without aggregate_type — domain_events_aggregate_idx needs aggregate_type as its leading column, so that shape gets no help from it.
CREATE INDEX domain_events_aggregate_id_idx ON domain_events (aggregate_id, occurred_at DESC);

-- Read-side projection for Permission, rebuilt synchronously (same transaction as the domain_events insert) on every append.
CREATE TABLE permission_projections (
    user_id UUID NOT NULL,
    repository_id UUID NOT NULL,
    role TEXT NOT NULL,
    version BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, repository_id)
);
-- The primary key only indexes repository_id as a non-leading column, so a lookup by repository_id alone (list_for_repository, ExportConfigurationUseCase) was a full table scan.
CREATE INDEX permission_projections_repository_id_idx ON permission_projections (repository_id);

-- Read-side projection for PackageRepository, rebuilt synchronously.
CREATE TABLE package_repository_projections (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    format TEXT NOT NULL,
    repo_type TEXT NOT NULL,
    remote_url TEXT,
    remote_username TEXT,
    remote_password TEXT,
    -- NULL means unlimited.
    quota_bytes BIGINT,
    -- NULL means automatic cleanup is disabled.
    retention_keep_last_n INT,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);
-- Deletion is soft (deleted_at is set, the row stays), so a plain UNIQUE on name would keep a deleted repository's name reserved forever — this partial index frees it up instead.
CREATE UNIQUE INDEX package_repository_org_name_active_idx
    ON package_repository_projections (organization_id, name)
    WHERE deleted_at IS NULL;

CREATE TABLE package_repository_group_members (
    group_repository_id UUID NOT NULL REFERENCES package_repository_projections(id) ON DELETE CASCADE,
    member_repository_id UUID NOT NULL,
    position INT NOT NULL,
    PRIMARY KEY (group_repository_id, member_repository_id),
    CONSTRAINT package_repository_group_members_member_fk FOREIGN KEY (member_repository_id) REFERENCES package_repository_projections(id)
);
CREATE INDEX package_repository_group_members_member_id_idx ON package_repository_group_members (member_repository_id);

-- Plain CRUD, not event-sourced like the projections above — there's no need to reconstruct past package metadata; publish/unpublish/deprecate already get their own domain_events entry.
CREATE TABLE npm_packages (
    id UUID PRIMARY KEY,
    package_repository_id UUID NOT NULL REFERENCES package_repository_projections(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Proxy repositories only: when this package's metadata was last fetched from the remote registry, driving the TTL revalidation check.
    metadata_fetched_at TIMESTAMPTZ,
    -- Proxy repositories only: the raw remote metadata document, cached verbatim and re-served until the TTL expires.
    cached_metadata JSONB,
    UNIQUE (package_repository_id, name)
);
-- search() matches with a leading wildcard (ILIKE '%...%'), which a plain B-tree can't serve.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX npm_packages_name_trgm_idx ON npm_packages USING gin (name gin_trgm_ops);

CREATE TABLE npm_package_versions (
    id UUID PRIMARY KEY,
    npm_package_id UUID NOT NULL REFERENCES npm_packages(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    manifest JSONB NOT NULL,
    shasum TEXT NOT NULL,
    integrity TEXT NOT NULL,
    tarball_storage_key TEXT NOT NULL,
    tarball_size_bytes BIGINT NOT NULL,
    deprecated BOOLEAN NOT NULL DEFAULT FALSE,
    deprecated_message TEXT,
    -- NULL for versions cached from a proxy's remote registry, never published by a Hangar user.
    published_by UUID REFERENCES users(id) ON DELETE SET NULL,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 'local' | 'proxy_cache' — matches hangar_domain::npm_package::NpmPackageOrigin.
    origin TEXT NOT NULL,
    UNIQUE (npm_package_id, version)
);
CREATE INDEX npm_package_versions_published_by_idx ON npm_package_versions (published_by);

CREATE TABLE npm_dist_tags (
    npm_package_id UUID NOT NULL REFERENCES npm_packages(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (npm_package_id, tag)
);

-- Deliberately not a domain_events row per download — a busy repository would flood the audit log, so pulls are a lightweight counter instead.
CREATE TABLE npm_download_counters (
    npm_package_version_id UUID PRIMARY KEY REFERENCES npm_package_versions(id) ON DELETE CASCADE,
    count BIGINT NOT NULL DEFAULT 0,
    last_downloaded_at TIMESTAMPTZ
);

-- Lets npm/CLI clients authenticate without a browser session. token_hash is a SHA-256 hash — the plaintext is shown once at creation and never stored.
CREATE TABLE api_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX api_tokens_user_id_idx ON api_tokens (user_id);

-- Backs hangar_domain::docker_registry's ports. Unlike npm_packages, blobs are globally content-addressed and deduped by digest across every repository, not scoped to one.
CREATE TABLE docker_blobs (
    digest TEXT PRIMARY KEY,
    size_bytes BIGINT NOT NULL,
    storage_key TEXT NOT NULL,
    -- Incremented on every manifest push referencing this digest, decremented on delete; the row is physically deleted once it reaches zero — reference counting, no GC sweep.
    reference_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Which repositories a blob was actually uploaded to, independent of whether any manifest references it yet. Blob storage itself is globally deduplicated by digest, so this
-- table plus docker_manifest_blobs are what a blob read checks to stay scoped to a repository the caller is authorized against.
CREATE TABLE docker_repository_blobs (
    package_repository_id UUID NOT NULL REFERENCES package_repository_projections(id) ON DELETE CASCADE,
    blob_digest TEXT NOT NULL REFERENCES docker_blobs(digest),
    PRIMARY KEY (package_repository_id, blob_digest)
);

-- One row per in-progress chunked/resumable blob upload session. The actual received bytes live in a staging file on disk, not in this table — only the bookkeeping does.
CREATE TABLE docker_blob_uploads (
    id UUID PRIMARY KEY,
    package_repository_id UUID NOT NULL REFERENCES package_repository_projections(id) ON DELETE CASCADE,
    staging_path TEXT NOT NULL,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- No periodic sweep — an abandoned session is instead cleaned up lazily, the next time any session lookup happens to land on it past this timestamp.
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX docker_blob_uploads_repository_idx ON docker_blob_uploads (package_repository_id);

-- A manifest's identity is (repository, image name, digest) — the same digest can legitimately recur under different image names or repositories, so digest alone isn't the
-- primary key here, unlike docker_blobs.
CREATE TABLE docker_manifests (
    id UUID PRIMARY KEY,
    package_repository_id UUID NOT NULL REFERENCES package_repository_projections(id) ON DELETE CASCADE,
    image_name TEXT NOT NULL,
    digest TEXT NOT NULL,
    media_type TEXT NOT NULL,
    -- Deliberately BYTEA, not JSONB: `digest` is the SHA-256 of these EXACT bytes, and clients re-verify it against the GET response body. JSONB doesn't round-trip byte-exact.
    body BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (package_repository_id, image_name, digest)
);

-- Which blobs a (non-list) manifest references. A manifest list's own entry here is always empty — its "blobs" are its member manifests, tracked in docker_manifest_list_members.
CREATE TABLE docker_manifest_blobs (
    manifest_id UUID NOT NULL REFERENCES docker_manifests(id) ON DELETE CASCADE,
    blob_digest TEXT NOT NULL REFERENCES docker_blobs(digest),
    PRIMARY KEY (manifest_id, blob_digest)
);
CREATE INDEX docker_manifest_blobs_blob_digest_idx ON docker_manifest_blobs (blob_digest);

-- Which member-manifest digests a manifest list points at. `member_digest` is deliberately plain TEXT, not a foreign key — digest alone isn't unique in docker_manifests, so a
-- member is always resolved within the list's own (package_repository_id, image_name) scope by application code.
CREATE TABLE docker_manifest_list_members (
    list_manifest_id UUID NOT NULL REFERENCES docker_manifests(id) ON DELETE CASCADE,
    member_digest TEXT NOT NULL,
    PRIMARY KEY (list_manifest_id, member_digest)
);

CREATE TABLE docker_tags (
    package_repository_id UUID NOT NULL REFERENCES package_repository_projections(id) ON DELETE CASCADE,
    image_name TEXT NOT NULL,
    tag TEXT NOT NULL,
    manifest_id UUID NOT NULL REFERENCES docker_manifests(id) ON DELETE CASCADE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (package_repository_id, image_name, tag)
);
CREATE INDEX docker_tags_lookup_idx ON docker_tags (package_repository_id, image_name);
CREATE INDEX docker_tags_manifest_id_idx ON docker_tags (manifest_id);

-- One row per completed deep dependency-tree scan of a published npm version — distinct from the lightweight check run live on every page view. History is insert-only, so
-- ScanDependencyTreeUseCase reads only the latest row per version via (npm_package_version_id, scanned_at DESC).
CREATE TABLE npm_dependency_audits (
    id UUID PRIMARY KEY,
    npm_package_version_id UUID NOT NULL REFERENCES npm_package_versions(id) ON DELETE CASCADE,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    packages_scanned INT NOT NULL,
    -- True when the walk hit its depth/count cap before exhausting the tree — the UI must surface this, never report partial coverage as complete.
    truncated BOOLEAN NOT NULL,
    -- Array of { dependency_name, dependency_version, advisory } — an immutable snapshot, never queried or updated per-finding, only read back whole.
    findings JSONB NOT NULL
);
CREATE INDEX npm_dependency_audits_version_scanned_at_idx ON npm_dependency_audits (npm_package_version_id, scanned_at DESC);

-- One row per completed Trivy scan of a Docker manifest, same insert-only history pattern as npm_dependency_audits. Keyed by the manifest's own immutable id, not by tag (which
-- can be repointed), so a new push under the same tag never gets confused with the old image's results.
CREATE TABLE docker_image_scans (
    id UUID PRIMARY KEY,
    docker_manifest_id UUID NOT NULL REFERENCES docker_manifests(id) ON DELETE CASCADE,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Array of DockerVulnerability — an immutable snapshot, never queried or updated per-vulnerability, only read back whole.
    vulnerabilities JSONB NOT NULL
);
CREATE INDEX docker_image_scans_manifest_scanned_at_idx ON docker_image_scans (docker_manifest_id, scanned_at DESC);

-- One row per periodic metrics snapshot (run on a timer from main.rs), insert-only, so the admin UI can chart the evolution of otherwise current-value-only totals over time.
CREATE TABLE metrics_snapshots (
    id UUID PRIMARY KEY,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    total_users BIGINT NOT NULL,
    total_repositories BIGINT NOT NULL,
    total_storage_bytes BIGINT NOT NULL
);
CREATE INDEX metrics_snapshots_recorded_at_idx ON metrics_snapshots (recorded_at);

-- Per-organization singleton — every organization gets its own login-throttle/session-TTL/registration policy.
CREATE TABLE system_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    max_login_attempts INT NOT NULL,
    login_attempt_window_seconds INT NOT NULL,
    session_ttl_hours INT NOT NULL,
    -- Lets a super-admin turn public self-registration off without disabling the whole "public" organization.
    registration_enabled BOOLEAN NOT NULL DEFAULT true
);
INSERT INTO system_settings (organization_id, max_login_attempts, login_attempt_window_seconds, session_ttl_hours)
VALUES ('00000000-0000-0000-0000-000000000001', 10, 300, 12);

-- Per-organization singleton like system_settings, but no seed row — SMTP is unconfigured by default. The password is encrypted (AES-256-GCM, key derived from
-- SECRETS_ENCRYPTION_KEY) rather than plaintext — the first real external-service credential this schema stores, unlike the one-way hashes elsewhere.
CREATE TABLE smtp_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    host TEXT NOT NULL,
    port INT NOT NULL,
    username TEXT NOT NULL,
    encrypted_password BYTEA NOT NULL,
    password_nonce BYTEA NOT NULL,
    from_address TEXT NOT NULL,
    from_name TEXT NOT NULL,
    security TEXT NOT NULL
);

-- One row per pending invitation, keyed by user_id so `ON CONFLICT (user_id) DO UPDATE` can both create the first invitation and reissue an expired one. Deleted on activation.
CREATE TABLE user_invitations (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL
);

-- The secret is encrypted (same secret_box helper as smtp_settings.encrypted_password) since, unlike a password hash, it must be recoverable to compute the next code.
-- `confirmed = false` until the user proves possession with a valid code — an unconfirmed row is never consulted at login. `last_used_step` guards against replay.
CREATE TABLE totp_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret BYTEA NOT NULL,
    secret_nonce BYTEA NOT NULL,
    confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_step BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per backup code, hashed like API tokens and invitation tokens. `used_at` marks single-use consumption instead of deleting the row, so a full history stays available.
CREATE TABLE mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX mfa_backup_codes_user_id_idx ON mfa_backup_codes (user_id);

-- Holds only the credential's public key and metadata — the private key never leaves the authenticator, so unlike totp_credentials this needs no encryption at rest.
CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    passkey_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials (user_id);

-- Singleton, same pattern as smtp_settings/system_settings, no seed row: branding is unconfigured by default. The built-in fallback logo/favicon are compiled into the binary
-- (see branding_defaults), not stored here.
CREATE TABLE branding_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    logo_bytes BYTEA,
    logo_content_type TEXT,
    favicon_bytes BYTEA,
    favicon_content_type TEXT,
    CONSTRAINT logo_bytes_and_content_type_together CHECK ((logo_bytes IS NULL) = (logo_content_type IS NULL)),
    CONSTRAINT favicon_bytes_and_content_type_together CHECK ((favicon_bytes IS NULL) = (favicon_content_type IS NULL))
);

-- Per-org singleton, same pattern as branding_settings — absence of a row means "local accounts only". `config` holds a serialized IdentityProviderConfig; its one secret field
-- is encrypted before this column is written, never stored in plaintext.
CREATE TABLE organization_identity_providers (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    config JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
