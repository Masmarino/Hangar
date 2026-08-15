use hangar_domain::error::{DomainError, EventStoreError};
use hangar_domain::storage::StorageError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error(transparent)]
    EventStore(#[from] EventStoreError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("username already taken")]
    UsernameTaken,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("repository name already taken")]
    RepositoryNameTaken,
    #[error("cannot delete the last super-administrator")]
    LastSuperAdmin,
    #[error("this package version already exists and cannot be republished")]
    PackageVersionExists,
    #[error("package not found")]
    NpmPackageNotFound,
    #[error("version not found")]
    NpmVersionNotFound,
    #[error("invalid tarball or manifest: {0}")]
    InvalidNpmPayload(String),
    #[error("blob with this digest already exists")]
    DockerBlobAlreadyExists,
    #[error("blob not found")]
    DockerBlobNotFound,
    #[error("manifest not found")]
    DockerManifestNotFound,
    #[error("digest mismatch: expected {expected}, computed {computed}")]
    DockerDigestMismatch { expected: String, computed: String },
    #[error("invalid manifest or upload: {0}")]
    InvalidDockerPayload(String),
    #[error("upload session not found or expired")]
    DockerUploadSessionNotFound,
    #[error("chunk offset mismatch: expected to start at {expected}, got {got}")]
    DockerChunkOffsetMismatch { expected: i64, got: i64 },
    #[error("invalid system settings: {0}")]
    InvalidSystemSettings(String),
    #[error("this write would exceed the repository's storage quota")]
    StorageQuotaExceeded,
    #[error("invalid SMTP settings: {0}")]
    InvalidSmtpSettings(String),
    #[error("invalid email address: {0}")]
    InvalidEmail(String),
    #[error("invitation not found or already used")]
    InvitationNotFound,
    #[error("this invitation has expired")]
    InvitationExpired,
    #[error("two-factor authentication is already enabled")]
    MfaAlreadyEnabled,
    #[error("two-factor authentication is not enabled")]
    MfaNotEnrolled,
    #[error("invalid or already-used authentication code")]
    InvalidMfaCode,
    #[error("passkeys are not available: the server's PUBLIC_URL is not configured with a valid domain")]
    PasskeysUnavailable,
    #[error("this instance is not empty — import only works on a freshly-provisioned instance with no repositories and no users other than the one running the import")]
    InstanceNotEmpty,
    #[error("invalid branding asset: {0}")]
    InvalidBrandingAsset(String),
    #[error("organization slug already taken")]
    OrganizationSlugTaken,
    #[error("the acting admin's own user record could not be found — its token was valid enough to identify a user, but that user no longer exists")]
    ActingAdminNotFound,
    /// Either the id doesn't exist at all, or it belongs to a different user —
    /// deliberately indistinguishable to the caller, same as a cross-organization
    /// lookup elsewhere in this codebase.
    #[error("api token not found")]
    ApiTokenNotFound,
}
