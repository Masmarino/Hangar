use std::fmt::Display;

use hangar_domain::error::{DomainError, EventStoreError};

/// `.infra_err()` instead of `.map_err(|e| DomainError::Infrastructure(e.to_string()))` everywhere.
pub trait InfraErr<T> {
    fn infra_err(self) -> Result<T, DomainError>;
}

impl<T, E: Display> InfraErr<T> for Result<T, E> {
    fn infra_err(self) -> Result<T, DomainError> {
        self.map_err(|e| DomainError::Infrastructure(e.to_string()))
    }
}

/// Same idea for the event-store repositories, which report failures as `EventStoreError` instead.
pub trait StorageErr<T> {
    fn storage_err(self) -> Result<T, EventStoreError>;
}

impl<T, E: Display> StorageErr<T> for Result<T, E> {
    fn storage_err(self) -> Result<T, EventStoreError> {
        self.map_err(|e| EventStoreError::Storage(e.to_string()))
    }
}
