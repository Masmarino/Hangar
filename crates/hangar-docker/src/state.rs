use std::sync::Arc;

use hangar_application::use_cases::docker_access_token::IssueDockerAccessTokenUseCase;
use hangar_application::use_cases::docker_blob_get::GetBlobUseCase;
use hangar_application::use_cases::docker_list::{ListCatalogUseCase, ListDockerRegistryCatalogUseCase, ListTagsUseCase};
use hangar_application::use_cases::docker_manifest_cache::CacheProxiedManifestUseCase;
use hangar_application::use_cases::docker_manifest_delete::DeleteManifestUseCase;
use hangar_application::use_cases::docker_scan::ScanDockerImageUseCase;
use hangar_application::use_cases::docker_manifest_get::GetManifestUseCase;
use hangar_application::use_cases::docker_manifest_put::PutManifestUseCase;
use hangar_application::use_cases::docker_upload::{CompleteBlobUploadUseCase, MonolithicBlobUploadUseCase, PatchBlobUploadUseCase, StartBlobUploadUseCase};
use hangar_domain::docker_registry::DockerTokenIssuerPort;
use hangar_domain::organization::OrganizationRepositoryPort;
use hangar_domain::package_repository::PackageRepositoryQueryPort;
use hangar_domain::permission::PermissionQueryPort;

#[derive(Clone)]
pub struct DockerState {
    pub repositories: Arc<dyn PackageRepositoryQueryPort>,
    pub permissions: Arc<dyn PermissionQueryPort>,
    pub organizations: Arc<dyn OrganizationRepositoryPort>,
    /// Base domain `ResolvedOrganization` strips off the `Host` header to find the subdomain label.
    pub hangar_base_domain: String,
    pub token_issuer: Arc<dyn DockerTokenIssuerPort>,
    pub token_realm: String,
    pub token_service: String,
    pub issue_access_token: Arc<IssueDockerAccessTokenUseCase>,
    pub start_upload: Arc<StartBlobUploadUseCase>,
    pub patch_upload: Arc<PatchBlobUploadUseCase>,
    pub complete_upload: Arc<CompleteBlobUploadUseCase>,
    pub monolithic_upload: Arc<MonolithicBlobUploadUseCase>,
    pub put_manifest: Arc<PutManifestUseCase>,
    pub cache_proxied_manifest: Arc<CacheProxiedManifestUseCase>,
    pub get_manifest: Arc<GetManifestUseCase>,
    pub get_blob: Arc<GetBlobUseCase>,
    pub delete_manifest: Arc<DeleteManifestUseCase>,
    pub list_tags: Arc<ListTagsUseCase>,
    pub list_catalog: Arc<ListCatalogUseCase>,
    pub list_registry_catalog: Arc<ListDockerRegistryCatalogUseCase>,
    pub scan_docker_image: Arc<ScanDockerImageUseCase>,
}
