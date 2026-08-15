use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid username: {0}")]
    InvalidUsername(String),
    #[error("email already in use")]
    EmailTaken,
    #[error("password must be at least 8 characters")]
    PasswordTooShort,
    #[error("invalid repository name: {0}")]
    InvalidRepositoryName(String),
    #[error("invalid organization slug: {0}")]
    InvalidOrganizationSlug(String),
    #[error("invalid remote url: {0}")]
    InvalidRemoteUrl(String),
    #[error("operation not valid for repository type {0:?}")]
    InvalidForRepositoryType(String),
    #[error("a group repository cannot contain itself")]
    SelfGroupMembership,
    #[error("member repository does not exist: {0}")]
    UnknownGroupMember(Uuid),
    #[error("member repository {0} has a different format than the group")]
    GroupMemberFormatMismatch(Uuid),
    #[error("member repository {0} belongs to a different organization than the group")]
    GroupMemberOrganizationMismatch(Uuid),
    #[error("user {0} belongs to a different organization than the repository")]
    GranteeOrganizationMismatch(Uuid),
    #[error("permission already absent, nothing to revoke")]
    NothingToRevoke,
    #[error("package repository has already been deleted")]
    AlreadyDeleted,
    #[error("infrastructure failure: {0}")]
    Infrastructure(String),
    #[error("chunk offset mismatch: expected {expected}, got {got}")]
    ChunkOffsetMismatch { expected: i64, got: i64 },
    #[error("validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EventStoreError {
    #[error("concurrency conflict: expected version {expected}, found {actual}")]
    ConcurrencyConflict { expected: u64, actual: u64 },
    #[error("storage failure: {0}")]
    Storage(String),
}
