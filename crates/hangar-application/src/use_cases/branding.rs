use std::sync::Arc;

use hangar_domain::branding::{BrandingAsset, BrandingPort};
use uuid::Uuid;

use crate::error::ApplicationError;

const MAX_ASSET_BYTES: usize = 2 * 1024 * 1024;

/// Sniffs the real format from the bytes rather than trusting the client's declared Content-Type, which would otherwise get served back to every visitor unchecked.
fn sniff_content_type(bytes: &[u8], allow_ico: bool) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if allow_ico && bytes.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Some("image/x-icon");
    }
    None
}

fn validate_asset(bytes: Vec<u8>, allow_ico: bool, format_hint: &str) -> Result<BrandingAsset, ApplicationError> {
    if bytes.is_empty() {
        return Err(ApplicationError::InvalidBrandingAsset("file is empty".to_string()));
    }
    if bytes.len() > MAX_ASSET_BYTES {
        return Err(ApplicationError::InvalidBrandingAsset("file exceeds 2 MB".to_string()));
    }
    let content_type = sniff_content_type(&bytes, allow_ico).ok_or_else(|| ApplicationError::InvalidBrandingAsset(format!("unsupported format ({format_hint})")))?;
    Ok(BrandingAsset { bytes, content_type: content_type.to_string() })
}

/// Compiled-in logo/favicon served when an operator hasn't uploaded their own — supplied by the composition root, not looked up here.
pub struct BrandingDefaults {
    pub logo: BrandingAsset,
    pub favicon: BrandingAsset,
}

/// Unlike `BrandingSettings`, never `None` — a fallback has already been applied, so a caller can't forget to handle the unconfigured case.
pub struct ResolvedBranding {
    pub logo: BrandingAsset,
    pub favicon: BrandingAsset,
}

pub struct GetBrandingUseCase {
    branding: Arc<dyn BrandingPort>,
    defaults: BrandingDefaults,
}

impl GetBrandingUseCase {
    pub fn new(branding: Arc<dyn BrandingPort>, defaults: BrandingDefaults) -> Self {
        Self { branding, defaults }
    }

    /// Always resolves to something — the operator's own upload, or the compiled-in default.
    pub async fn execute(&self, organization_id: Uuid) -> Result<ResolvedBranding, ApplicationError> {
        let settings = self.branding.get(organization_id).await?;
        Ok(ResolvedBranding {
            logo: settings.logo.unwrap_or_else(|| self.defaults.logo.clone()),
            favicon: settings.favicon.unwrap_or_else(|| self.defaults.favicon.clone()),
        })
    }
}

pub struct SetBrandingLogoUseCase {
    branding: Arc<dyn BrandingPort>,
}

impl SetBrandingLogoUseCase {
    pub fn new(branding: Arc<dyn BrandingPort>) -> Self {
        Self { branding }
    }

    pub async fn execute(&self, organization_id: Uuid, bytes: Vec<u8>) -> Result<(), ApplicationError> {
        let asset = validate_asset(bytes, false, "PNG ou JPEG uniquement")?;
        self.branding.set_logo(organization_id, &asset).await?;
        Ok(())
    }
}

pub struct ClearBrandingLogoUseCase {
    branding: Arc<dyn BrandingPort>,
}

impl ClearBrandingLogoUseCase {
    pub fn new(branding: Arc<dyn BrandingPort>) -> Self {
        Self { branding }
    }

    pub async fn execute(&self, organization_id: Uuid) -> Result<(), ApplicationError> {
        Ok(self.branding.clear_logo(organization_id).await?)
    }
}

pub struct SetBrandingFaviconUseCase {
    branding: Arc<dyn BrandingPort>,
}

impl SetBrandingFaviconUseCase {
    pub fn new(branding: Arc<dyn BrandingPort>) -> Self {
        Self { branding }
    }

    pub async fn execute(&self, organization_id: Uuid, bytes: Vec<u8>) -> Result<(), ApplicationError> {
        let asset = validate_asset(bytes, true, "PNG, JPEG ou ICO uniquement")?;
        self.branding.set_favicon(organization_id, &asset).await?;
        Ok(())
    }
}

pub struct ClearBrandingFaviconUseCase {
    branding: Arc<dyn BrandingPort>,
}

impl ClearBrandingFaviconUseCase {
    pub fn new(branding: Arc<dyn BrandingPort>) -> Self {
        Self { branding }
    }

    pub async fn execute(&self, organization_id: Uuid) -> Result<(), ApplicationError> {
        Ok(self.branding.clear_favicon(organization_id).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hangar_domain::branding::BrandingSettings;
    use hangar_domain::error::DomainError;
    use std::sync::Mutex;

    struct FakeBranding {
        settings: Mutex<BrandingSettings>,
    }

    impl FakeBranding {
        fn new() -> Self {
            Self { settings: Mutex::new(BrandingSettings::default()) }
        }
    }

    #[async_trait]
    impl BrandingPort for FakeBranding {
        async fn get(&self, _organization_id: Uuid) -> Result<BrandingSettings, DomainError> {
            Ok(self.settings.lock().unwrap().clone())
        }
        async fn set_logo(&self, _organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError> {
            self.settings.lock().unwrap().logo = Some(asset.clone());
            Ok(())
        }
        async fn clear_logo(&self, _organization_id: Uuid) -> Result<(), DomainError> {
            self.settings.lock().unwrap().logo = None;
            Ok(())
        }
        async fn set_favicon(&self, _organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError> {
            self.settings.lock().unwrap().favicon = Some(asset.clone());
            Ok(())
        }
        async fn clear_favicon(&self, _organization_id: Uuid) -> Result<(), DomainError> {
            self.settings.lock().unwrap().favicon = None;
            Ok(())
        }
    }

    const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const JPEG_MAGIC: [u8; 3] = [0xFF, 0xD8, 0xFF];
    const ICO_MAGIC: [u8; 4] = [0x00, 0x00, 0x01, 0x00];

    fn png_bytes() -> Vec<u8> {
        let mut bytes = PNG_MAGIC.to_vec();
        bytes.extend_from_slice(b"fake-png-data");
        bytes
    }

    fn jpeg_bytes() -> Vec<u8> {
        let mut bytes = JPEG_MAGIC.to_vec();
        bytes.extend_from_slice(b"fake-jpeg-data");
        bytes
    }

    fn ico_bytes() -> Vec<u8> {
        let mut bytes = ICO_MAGIC.to_vec();
        bytes.extend_from_slice(b"fake-ico-data");
        bytes
    }

    fn test_org_id() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    /// Deliberately distinct from any real sniffed content-type, so a test can tell whether
    /// GetBrandingUseCase fell back to these or served the operator's own upload.
    fn test_defaults() -> BrandingDefaults {
        BrandingDefaults {
            logo: BrandingAsset { bytes: b"default-logo".to_vec(), content_type: "image/default-logo".to_string() },
            favicon: BrandingAsset { bytes: b"default-favicon".to_vec(), content_type: "image/default-favicon".to_string() },
        }
    }

    #[tokio::test]
    async fn setting_a_logo_then_getting_it_round_trips() {
        let branding = Arc::new(FakeBranding::new());
        let set = SetBrandingLogoUseCase::new(branding.clone());
        set.execute(test_org_id(), png_bytes()).await.unwrap();

        let settings = GetBrandingUseCase::new(branding, test_defaults()).execute(test_org_id()).await.unwrap();
        assert_eq!(settings.logo.content_type, "image/png");
    }

    #[tokio::test]
    async fn a_jpeg_logo_is_accepted_and_sniffed_correctly() {
        let branding = Arc::new(FakeBranding::new());
        SetBrandingLogoUseCase::new(branding.clone()).execute(test_org_id(), jpeg_bytes()).await.unwrap();

        let settings = GetBrandingUseCase::new(branding, test_defaults()).execute(test_org_id()).await.unwrap();
        assert_eq!(settings.logo.content_type, "image/jpeg");
    }

    #[tokio::test]
    async fn an_unconfigured_instance_serves_the_compiled_in_defaults() {
        let branding = Arc::new(FakeBranding::new());
        let settings = GetBrandingUseCase::new(branding, test_defaults()).execute(test_org_id()).await.unwrap();
        assert_eq!(settings.logo.content_type, "image/default-logo");
        assert_eq!(settings.favicon.content_type, "image/default-favicon");
    }

    #[tokio::test]
    async fn an_ico_logo_is_rejected() {
        let branding = Arc::new(FakeBranding::new());
        let err = SetBrandingLogoUseCase::new(branding).execute(test_org_id(), ico_bytes()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidBrandingAsset(_)));
    }

    #[tokio::test]
    async fn an_ico_favicon_is_accepted() {
        let branding = Arc::new(FakeBranding::new());
        SetBrandingFaviconUseCase::new(branding.clone()).execute(test_org_id(), ico_bytes()).await.unwrap();

        let settings = GetBrandingUseCase::new(branding, test_defaults()).execute(test_org_id()).await.unwrap();
        assert_eq!(settings.favicon.content_type, "image/x-icon");
    }

    #[tokio::test]
    async fn an_unrecognized_format_is_rejected() {
        let branding = Arc::new(FakeBranding::new());
        let err = SetBrandingLogoUseCase::new(branding).execute(test_org_id(), b"not an image".to_vec()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidBrandingAsset(_)));
    }

    #[tokio::test]
    async fn an_oversized_logo_is_rejected() {
        let mut bytes = PNG_MAGIC.to_vec();
        bytes.resize(MAX_ASSET_BYTES + 1, 0);
        let branding = Arc::new(FakeBranding::new());
        let err = SetBrandingLogoUseCase::new(branding).execute(test_org_id(), bytes).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidBrandingAsset(_)));
    }

    #[tokio::test]
    async fn an_empty_upload_is_rejected() {
        let branding = Arc::new(FakeBranding::new());
        let err = SetBrandingLogoUseCase::new(branding).execute(test_org_id(), Vec::new()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidBrandingAsset(_)));
    }

    #[tokio::test]
    async fn clearing_the_logo_leaves_the_favicon_alone() {
        let branding = Arc::new(FakeBranding::new());
        SetBrandingLogoUseCase::new(branding.clone()).execute(test_org_id(), png_bytes()).await.unwrap();
        SetBrandingFaviconUseCase::new(branding.clone()).execute(test_org_id(), ico_bytes()).await.unwrap();

        ClearBrandingLogoUseCase::new(branding.clone()).execute(test_org_id()).await.unwrap();

        let settings = GetBrandingUseCase::new(branding, test_defaults()).execute(test_org_id()).await.unwrap();
        assert_eq!(settings.logo.content_type, "image/default-logo", "cleared logo must fall back to the compiled-in default");
        assert_eq!(settings.favicon.content_type, "image/x-icon");
    }

    #[tokio::test]
    async fn clearing_the_favicon_leaves_the_logo_alone() {
        let branding = Arc::new(FakeBranding::new());
        SetBrandingLogoUseCase::new(branding.clone()).execute(test_org_id(), png_bytes()).await.unwrap();
        SetBrandingFaviconUseCase::new(branding.clone()).execute(test_org_id(), ico_bytes()).await.unwrap();

        ClearBrandingFaviconUseCase::new(branding.clone()).execute(test_org_id()).await.unwrap();

        let settings = GetBrandingUseCase::new(branding, test_defaults()).execute(test_org_id()).await.unwrap();
        assert_eq!(settings.logo.content_type, "image/png");
        assert_eq!(settings.favicon.content_type, "image/default-favicon", "cleared favicon must fall back to the compiled-in default");
    }
}
