use async_trait::async_trait;
use uuid::Uuid;

use crate::error::DomainError;

/// `content_type` is sniffed from the bytes, never the client's declared header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandingAsset {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// `None` on either field means "not customized" — the baked-in default lives in `hangar-infrastructure`, not here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrandingSettings {
    pub logo: Option<BrandingAsset>,
    pub favicon: Option<BrandingAsset>,
}

#[async_trait]
pub trait BrandingPort: Send + Sync {
    async fn get(&self, organization_id: Uuid) -> Result<BrandingSettings, DomainError>;
    async fn set_logo(&self, organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError>;
    async fn clear_logo(&self, organization_id: Uuid) -> Result<(), DomainError>;
    async fn set_favicon(&self, organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError>;
    async fn clear_favicon(&self, organization_id: Uuid) -> Result<(), DomainError>;
}
