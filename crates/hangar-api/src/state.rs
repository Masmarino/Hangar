use std::sync::Arc;

use hangar_application::use_cases::admin::{
    AdminListApiTokensUseCase, AdminRevokeApiTokenUseCase, ExportConfigurationUseCase, GetAdminStatsUseCase, GetHealthStatusUseCase, GetMetricsHistoryUseCase, GetSystemSettingsUseCase,
    GetUsageMetricsUseCase, ImportConfigurationUseCase, QueryAuditLogUseCase, RecordMetricsSnapshotUseCase, RecordSecurityEventUseCase, UpdateSystemSettingsUseCase,
};
use hangar_application::use_cases::api_token::{CreateApiTokenUseCase, ListApiTokensUseCase, RevokeApiTokenUseCase};
use hangar_application::use_cases::branding::{BrandingDefaults, ClearBrandingFaviconUseCase, ClearBrandingLogoUseCase, GetBrandingUseCase, SetBrandingFaviconUseCase, SetBrandingLogoUseCase};
use hangar_application::use_cases::docker_manifest_delete::{DeleteDockerImageUseCase, DeleteManifestUseCase};
use hangar_application::use_cases::docker_scan::{GetDockerImageScanResultUseCase, ScanDockerImageUseCase};
use hangar_application::use_cases::list_repository_packages::ListRepositoryPackagesUseCase;
use hangar_application::use_cases::npm_audit::AuditNpmPackageUseCase;
use hangar_application::use_cases::npm_dependency_scan::{GetDependencyAuditResultUseCase, ScanDependencyTreeUseCase};
use hangar_application::use_cases::npm_unpublish::UnpublishNpmPackageUseCase;
use hangar_application::use_cases::organization::CreateOrganizationUseCase;
use hangar_application::use_cases::package_details::{GetDockerImageDetailsUseCase, GetNpmPackageDetailsUseCase};
use hangar_application::use_cases::package_repository::{
    AddGroupMemberUseCase, CreatePackageRepositoryUseCase, DeletePackageRepositoryUseCase, RemoveGroupMemberUseCase,
    RenamePackageRepositoryUseCase, SetRepositoryQuotaUseCase, SetRetentionPolicyUseCase,
};
use hangar_application::use_cases::permission::{GrantPermissionUseCase, RevokePermissionUseCase};
use hangar_application::use_cases::invitation::{ActivateAccountUseCase, InviteUserUseCase, ResendInvitationUseCase};
use hangar_application::use_cases::mfa::{
    ConfirmTotpUseCase, DisableTotpUseCase, EnrollTotpUseCase, GetMfaStatusUseCase, RegenerateBackupCodesUseCase, VerifyBackupCodeUseCase, VerifyTotpUseCase,
};
use hangar_application::use_cases::smtp::{GetSmtpSettingsUseCase, SendTestEmailUseCase, UpdateSmtpSettingsUseCase};
use hangar_application::use_cases::webauthn::{
    build_webauthn_client, DeletePasskeyUseCase, FinishPasskeyAuthenticationUseCase, FinishPasskeyRegistrationUseCase, ListPasskeysUseCase, PasskeyCeremonyStore,
    StartPasskeyAuthenticationUseCase, StartPasskeyRegistrationUseCase,
};
use hangar_application::use_cases::user::{AuthenticateUserUseCase, ChangePasswordUseCase, CreateUserUseCase, DeleteUserUseCase, SetOrganizationAdminUseCase, SetSuperAdminUseCase};
use hangar_application::use_cases::registration::RegisterPublicUserUseCase;
use hangar_application::use_cases::sso::ProvisionSsoUserUseCase;
use hangar_domain::api_token::ApiTokenRepositoryPort;
use hangar_domain::audit::EventPublisherPort;
use hangar_domain::npm_audit::NpmAuditPort;
use hangar_domain::npm_package::NpmPackageRepositoryPort;
use hangar_domain::organization::OrganizationRepositoryPort;
use hangar_domain::package_repository::PackageRepositoryQueryPort;
use hangar_domain::permission::PermissionQueryPort;
use hangar_domain::storage::StorageBackendPort;
use hangar_domain::user::{TokenIssuerPort, UserRepositoryPort};
use hangar_domain::sso::{IdentityProviderRepositoryPort, LdapAuthPort, OidcAuthPort};
use hangar_domain::branding::BrandingAsset;
use hangar_infrastructure::argon2_hasher::Argon2PasswordHasher;
use hangar_infrastructure::branding_defaults;
use hangar_infrastructure::filesystem_storage::FilesystemStorageBackend;
use hangar_infrastructure::jwt_mfa_pending_token_issuer::JwtMfaPendingTokenIssuer;
use hangar_infrastructure::jwt_token_issuer::JwtTokenIssuer;
use hangar_infrastructure::postgres::api_token_repository::PostgresApiTokenRepository;
use hangar_infrastructure::postgres::backup_code_repository::PostgresBackupCodeRepository;
use hangar_infrastructure::postgres::event_publisher::PostgresEventPublisher;
use hangar_infrastructure::postgres::health::PostgresHealthCheck;
use hangar_infrastructure::postgres::docker_image_scan_repository::PostgresDockerImageScanRepository;
use hangar_infrastructure::postgres::metrics_snapshot_repository::PostgresMetricsSnapshotRepository;
use hangar_infrastructure::postgres::npm_dependency_audit_repository::PostgresDependencyAuditRepository;
use hangar_infrastructure::postgres::npm_package_repository::PostgresNpmPackageRepository;
use hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository;
use hangar_infrastructure::postgres::package_repository_store::PostgresPackageRepositoryStore;
use hangar_infrastructure::postgres::permission_store::PostgresPermissionStore;
use hangar_infrastructure::postgres::smtp_settings_repository::PostgresSmtpSettingsRepository;
use hangar_infrastructure::postgres::system_settings_repository::PostgresSystemSettingsRepository;
use hangar_infrastructure::postgres::totp_credential_repository::PostgresTotpCredentialRepository;
use hangar_infrastructure::postgres::user_invitation_repository::PostgresUserInvitationRepository;
use hangar_infrastructure::postgres::user_repository::PostgresUserRepository;
use hangar_infrastructure::postgres::webauthn_credential_repository::PostgresWebauthnCredentialRepository;
use hangar_infrastructure::ldap3_auth_adapter::Ldap3AuthAdapter;
use hangar_infrastructure::openidconnect_auth_adapter::OpenidConnectAuthAdapter;
use hangar_infrastructure::postgres::identity_provider_repository::PostgresIdentityProviderRepository;
use hangar_infrastructure::smtp_email_sender::SmtpEmailSender;
use sqlx::PgPool;
use std::time::Instant;

use crate::config::Config;
use crate::login_throttle::LoginThrottle;

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<dyn UserRepositoryPort>,
    pub permissions: Arc<dyn PermissionQueryPort>,
    pub repositories: Arc<dyn PackageRepositoryQueryPort>,
    pub organizations: Arc<dyn OrganizationRepositoryPort>,
    pub identity_providers: Arc<dyn IdentityProviderRepositoryPort>,
    pub ldap_auth: Arc<dyn LdapAuthPort>,
    pub oidc_auth: Arc<dyn OidcAuthPort>,
    pub provision_sso_user: Arc<ProvisionSsoUserUseCase>,
    /// Base domain `ResolvedOrganization` strips off the `Host` header to find the subdomain label.
    pub hangar_base_domain: String,
    /// The SPA's public URL — used to build the final browser redirect after an OIDC callback.
    pub public_url: String,
    pub api_tokens: Arc<dyn ApiTokenRepositoryPort>,
    /// Exposed so `main.rs` can reuse the same adapters for `hangar_npm`/`hangar_docker` state.
    pub storage: Arc<dyn StorageBackendPort>,
    pub events: Arc<dyn EventPublisherPort>,
    pub npm_packages: Arc<dyn NpmPackageRepositoryPort>,
    pub npm_audit: Arc<dyn NpmAuditPort>,
    pub docker_blobs: Arc<dyn hangar_domain::docker_registry::DockerBlobStorePort>,
    pub docker_manifests: Arc<dyn hangar_domain::docker_registry::DockerManifestRepositoryPort>,
    pub docker_uploads: Arc<dyn hangar_application::use_cases::docker_upload::DockerUploadSessionPort>,
    pub create_user: Arc<CreateUserUseCase>,
    pub register_public_user: Arc<RegisterPublicUserUseCase>,
    pub authenticate_user: Arc<AuthenticateUserUseCase>,
    pub delete_user: Arc<DeleteUserUseCase>,
    pub set_super_admin: Arc<SetSuperAdminUseCase>,
    pub set_organization_admin: Arc<SetOrganizationAdminUseCase>,
    pub change_password: Arc<ChangePasswordUseCase>,
    pub create_organization: Arc<CreateOrganizationUseCase>,
    pub create_repository: Arc<CreatePackageRepositoryUseCase>,
    pub rename_repository: Arc<RenamePackageRepositoryUseCase>,
    pub delete_repository: Arc<DeletePackageRepositoryUseCase>,
    pub add_group_member: Arc<AddGroupMemberUseCase>,
    pub remove_group_member: Arc<RemoveGroupMemberUseCase>,
    pub set_repository_quota: Arc<SetRepositoryQuotaUseCase>,
    pub set_retention_policy: Arc<SetRetentionPolicyUseCase>,
    pub sweep_retention: Arc<hangar_application::use_cases::retention::SweepRetentionUseCase>,
    pub grant_permission: Arc<GrantPermissionUseCase>,
    pub revoke_permission: Arc<RevokePermissionUseCase>,
    pub query_audit_log: Arc<QueryAuditLogUseCase>,
    pub record_security_event: Arc<RecordSecurityEventUseCase>,
    pub get_usage_metrics: Arc<GetUsageMetricsUseCase>,
    pub get_metrics_history: Arc<GetMetricsHistoryUseCase>,
    pub record_metrics_snapshot: Arc<RecordMetricsSnapshotUseCase>,
    pub get_health_status: Arc<GetHealthStatusUseCase>,
    pub get_admin_stats: Arc<GetAdminStatsUseCase>,
    pub export_configuration: Arc<ExportConfigurationUseCase>,
    pub import_configuration: Arc<ImportConfigurationUseCase>,
    pub create_api_token: Arc<CreateApiTokenUseCase>,
    pub list_api_tokens: Arc<ListApiTokensUseCase>,
    pub revoke_api_token: Arc<RevokeApiTokenUseCase>,
    pub admin_list_api_tokens: Arc<AdminListApiTokensUseCase>,
    pub admin_revoke_api_token: Arc<AdminRevokeApiTokenUseCase>,
    pub list_repository_packages: Arc<ListRepositoryPackagesUseCase>,
    pub get_npm_package_details: Arc<GetNpmPackageDetailsUseCase>,
    pub get_docker_image_details: Arc<GetDockerImageDetailsUseCase>,
    pub unpublish_npm_package: Arc<UnpublishNpmPackageUseCase>,
    pub audit_npm_package: Arc<AuditNpmPackageUseCase>,
    pub scan_dependency_tree: Arc<ScanDependencyTreeUseCase>,
    pub get_dependency_audit: Arc<GetDependencyAuditResultUseCase>,
    pub delete_docker_manifest: Arc<DeleteManifestUseCase>,
    pub delete_docker_image: Arc<DeleteDockerImageUseCase>,
    pub scan_docker_image: Arc<ScanDockerImageUseCase>,
    pub get_docker_image_scan: Arc<GetDockerImageScanResultUseCase>,
    pub token_issuer: Arc<JwtTokenIssuer>,
    pub login_throttle: LoginThrottle,
    pub get_system_settings: Arc<GetSystemSettingsUseCase>,
    pub update_system_settings: Arc<UpdateSystemSettingsUseCase>,
    pub get_smtp_settings: Arc<GetSmtpSettingsUseCase>,
    pub update_smtp_settings: Arc<UpdateSmtpSettingsUseCase>,
    pub send_test_email: Arc<SendTestEmailUseCase>,
    pub get_branding: Arc<GetBrandingUseCase>,
    pub set_branding_logo: Arc<SetBrandingLogoUseCase>,
    pub clear_branding_logo: Arc<ClearBrandingLogoUseCase>,
    pub set_branding_favicon: Arc<SetBrandingFaviconUseCase>,
    pub clear_branding_favicon: Arc<ClearBrandingFaviconUseCase>,
    pub invite_user: Arc<InviteUserUseCase>,
    pub resend_invitation: Arc<ResendInvitationUseCase>,
    pub activate_account: Arc<ActivateAccountUseCase>,
    pub user_invitations: Arc<dyn hangar_domain::invitation::UserInvitationPort>,
    pub totp_credentials: Arc<dyn hangar_domain::mfa::TotpCredentialPort>,
    /// Signs a "password verified" proof — never interchangeable with `token_issuer`.
    pub mfa_pending_token_issuer: Arc<dyn TokenIssuerPort>,
    pub get_mfa_status: Arc<GetMfaStatusUseCase>,
    pub enroll_totp: Arc<EnrollTotpUseCase>,
    pub confirm_totp: Arc<ConfirmTotpUseCase>,
    pub verify_totp: Arc<VerifyTotpUseCase>,
    pub verify_backup_code: Arc<VerifyBackupCodeUseCase>,
    pub disable_totp: Arc<DisableTotpUseCase>,
    pub regenerate_backup_codes: Arc<RegenerateBackupCodesUseCase>,
    pub webauthn_credentials: Arc<dyn hangar_domain::webauthn::WebauthnCredentialPort>,
    pub start_passkey_registration: Arc<StartPasskeyRegistrationUseCase>,
    pub finish_passkey_registration: Arc<FinishPasskeyRegistrationUseCase>,
    pub start_passkey_authentication: Arc<StartPasskeyAuthenticationUseCase>,
    pub finish_passkey_authentication: Arc<FinishPasskeyAuthenticationUseCase>,
    pub list_passkeys: Arc<ListPasskeysUseCase>,
    pub delete_passkey: Arc<DeletePasskeyUseCase>,
}

impl AppState {
    pub fn build(pool: PgPool, config: &Config) -> Self {
        let started_at = Instant::now();
        let users_repo = Arc::new(PostgresUserRepository::new(pool.clone()));
        let organizations: Arc<dyn OrganizationRepositoryPort> = Arc::new(PostgresOrganizationRepository::new(pool.clone()));
        let identity_providers: Arc<dyn IdentityProviderRepositoryPort> = Arc::new(PostgresIdentityProviderRepository::new(pool.clone(), config.secrets_encryption_key.clone()));
        let ldap_auth: Arc<dyn LdapAuthPort> = Arc::new(Ldap3AuthAdapter);
        let oidc_auth: Arc<dyn OidcAuthPort> = Arc::new(OpenidConnectAuthAdapter::new(config.jwt_secret.clone()));
        let create_organization = Arc::new(CreateOrganizationUseCase::new(organizations.clone()));
        let permission_store = Arc::new(PostgresPermissionStore::new(pool.clone()));
        let repository_store = Arc::new(PostgresPackageRepositoryStore::new(pool.clone(), config.secrets_encryption_key.clone()));
        let event_publisher = Arc::new(PostgresEventPublisher::new(pool.clone()));
        let health_check = Arc::new(PostgresHealthCheck::new(pool.clone(), config.db_max_connections));
        let hasher = Arc::new(Argon2PasswordHasher);
        let token_issuer = Arc::new(JwtTokenIssuer::new(config.jwt_secret.clone()));
        let storage = Arc::new(FilesystemStorageBackend::new(config.storage_root.clone()));
        let api_tokens: Arc<dyn ApiTokenRepositoryPort> = Arc::new(PostgresApiTokenRepository::new(pool.clone()));
        let npm_packages: Arc<dyn NpmPackageRepositoryPort> = Arc::new(PostgresNpmPackageRepository::new(pool.clone()));
        let npm_audit: Arc<dyn NpmAuditPort> = Arc::new(hangar_infrastructure::http_npm_audit_client::HttpNpmAuditClient::new());
        let dependency_audits: Arc<dyn hangar_domain::npm_audit::DependencyAuditRepositoryPort> =
            Arc::new(PostgresDependencyAuditRepository::new(pool.clone()));
        let public_registry: Arc<dyn hangar_domain::npm_remote::RemoteNpmRegistryPort> =
            Arc::new(hangar_infrastructure::http_remote_npm_registry::HttpRemoteNpmRegistry::new());
        let docker_blobs: Arc<dyn hangar_domain::docker_registry::DockerBlobStorePort> = Arc::new(
            hangar_infrastructure::filesystem_docker_blob_store::FilesystemDockerBlobStore::new(
                pool.clone(),
                std::path::Path::new(&config.storage_root).join("docker-blobs"),
            ),
        );
        let docker_manifests: Arc<dyn hangar_domain::docker_registry::DockerManifestRepositoryPort> =
            Arc::new(hangar_infrastructure::postgres::docker_manifest_repository::PostgresDockerManifestRepository::new(pool.clone()));
        let docker_uploads: Arc<dyn hangar_application::use_cases::docker_upload::DockerUploadSessionPort> = Arc::new(
            hangar_infrastructure::postgres::docker_upload_session_repository::PostgresDockerUploadSessionRepository::new(
                pool.clone(),
                std::path::Path::new(&config.storage_root).join("docker-uploads"),
            ),
        );
        let docker_image_scans: Arc<dyn hangar_domain::docker_scan::DockerImageScanRepositoryPort> =
            Arc::new(PostgresDockerImageScanRepository::new(pool.clone()));
        // Trivy runs as a subprocess on this same host, reached over loopback.
        let registry_port = config.bind_addr.rsplit(':').next().unwrap_or("8080");
        let docker_scanner: Arc<dyn hangar_domain::docker_scan::DockerImageScannerPort> =
            Arc::new(hangar_infrastructure::trivy_docker_image_scanner::TrivyDockerImageScanner::new(format!("127.0.0.1:{registry_port}")));
        let docker_token_issuer: Arc<dyn hangar_domain::docker_registry::DockerTokenIssuerPort> =
            Arc::new(hangar_infrastructure::jwt_docker_token_issuer::JwtDockerTokenIssuer::new(config.jwt_secret.clone()));
        let metrics_snapshots: Arc<dyn hangar_domain::metrics_snapshot::MetricsSnapshotRepositoryPort> =
            Arc::new(PostgresMetricsSnapshotRepository::new(pool.clone()));
        let get_usage_metrics = Arc::new(GetUsageMetricsUseCase::new(repository_store.clone(), storage.clone(), docker_blobs.clone()));
        let system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort> = Arc::new(PostgresSystemSettingsRepository::new(pool.clone()));
        let smtp_settings: Arc<dyn hangar_domain::email::SmtpSettingsPort> = Arc::new(PostgresSmtpSettingsRepository::new(pool.clone(), config.secrets_encryption_key.clone()));
        let branding: Arc<dyn hangar_domain::branding::BrandingPort> = Arc::new(hangar_infrastructure::postgres::branding_repository::PostgresBrandingRepository::new(pool.clone()));
        let email_sender: Arc<dyn hangar_domain::email::EmailPort> = Arc::new(SmtpEmailSender::new(smtp_settings.clone(), branding.clone()));
        let user_invitations: Arc<dyn hangar_domain::invitation::UserInvitationPort> = Arc::new(PostgresUserInvitationRepository::new(pool.clone()));
        let totp_credentials: Arc<dyn hangar_domain::mfa::TotpCredentialPort> = Arc::new(PostgresTotpCredentialRepository::new(pool.clone(), config.secrets_encryption_key.clone()));
        let backup_codes: Arc<dyn hangar_domain::mfa::BackupCodePort> = Arc::new(PostgresBackupCodeRepository::new(pool.clone()));
        let mfa_pending_token_issuer: Arc<dyn TokenIssuerPort> = Arc::new(JwtMfaPendingTokenIssuer::new(config.jwt_secret.clone()));
        let webauthn_credentials: Arc<dyn hangar_domain::webauthn::WebauthnCredentialPort> = Arc::new(PostgresWebauthnCredentialRepository::new(pool.clone()));
        // Degrades to "passkeys disabled" rather than refusing to start the server.
        let webauthn_client = Arc::new(match build_webauthn_client(&config.hangar_base_domain, "Hangar", &config.public_url) {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!("passkeys disabled: {e}. Set HANGAR_BASE_DOMAIN to this deployment's real base domain to enable them.");
                None
            }
        });
        let passkey_ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let login_throttle = LoginThrottle::new();
        // Bound here so `sweep_retention` can reuse the same instances.
        let unpublish_npm_package = Arc::new(UnpublishNpmPackageUseCase::new(npm_packages.clone(), storage.clone(), event_publisher.clone()));
        let delete_docker_manifest = Arc::new(DeleteManifestUseCase::new(docker_manifests.clone(), docker_blobs.clone(), event_publisher.clone()));
        let delete_docker_image = Arc::new(DeleteDockerImageUseCase::new(docker_manifests.clone(), delete_docker_manifest.clone()));
        let sweep_retention = Arc::new(hangar_application::use_cases::retention::SweepRetentionUseCase::new(
            repository_store.clone(),
            npm_packages.clone(),
            unpublish_npm_package.clone(),
            docker_manifests.clone(),
            delete_docker_manifest.clone(),
        ));

        // Bound here so `import_configuration` can reuse the same instances.
        let create_repository = Arc::new(CreatePackageRepositoryUseCase::new(repository_store.clone(), repository_store.clone()));
        let set_repository_quota = Arc::new(SetRepositoryQuotaUseCase::new(repository_store.clone()));
        let set_retention_policy = Arc::new(SetRetentionPolicyUseCase::new(repository_store.clone()));
        let add_group_member = Arc::new(AddGroupMemberUseCase::new(repository_store.clone(), repository_store.clone()));
        let grant_permission = Arc::new(GrantPermissionUseCase::new(permission_store.clone(), repository_store.clone(), users_repo.clone()));
        let update_system_settings = Arc::new(UpdateSystemSettingsUseCase::new(system_settings.clone()));
        let import_configuration = Arc::new(ImportConfigurationUseCase::new(
            users_repo.clone(),
            hasher.clone(),
            create_repository.clone(),
            set_repository_quota.clone(),
            set_retention_policy.clone(),
            add_group_member.clone(),
            grant_permission.clone(),
            update_system_settings.clone(),
            repository_store.clone(),
            user_invitations.clone(),
            email_sender.clone(),
            organizations.clone(),
            config.hangar_base_domain.clone(),
        ));

        Self {
            users: users_repo.clone(),
            permissions: permission_store.clone(),
            repositories: repository_store.clone(),
            organizations: organizations.clone(),
            identity_providers: identity_providers.clone(),
            ldap_auth: ldap_auth.clone(),
            oidc_auth: oidc_auth.clone(),
            provision_sso_user: Arc::new(ProvisionSsoUserUseCase::new(users_repo.clone(), hasher.clone(), token_issuer.clone(), system_settings.clone())),
            hangar_base_domain: config.hangar_base_domain.clone(),
            public_url: config.public_url.clone(),
            api_tokens: api_tokens.clone(),
            storage: storage.clone(),
            events: event_publisher.clone(),
            npm_packages: npm_packages.clone(),
            npm_audit: npm_audit.clone(),
            docker_blobs: docker_blobs.clone(),
            docker_manifests: docker_manifests.clone(),
            docker_uploads: docker_uploads.clone(),
            create_user: Arc::new(CreateUserUseCase::new(users_repo.clone(), hasher.clone())),
            register_public_user: Arc::new(RegisterPublicUserUseCase::new(users_repo.clone(), hasher.clone())),
            authenticate_user: Arc::new(AuthenticateUserUseCase::new(users_repo.clone(), hasher.clone(), token_issuer.clone(), system_settings.clone())),
            delete_user: Arc::new(DeleteUserUseCase::new(users_repo.clone())),
            set_super_admin: Arc::new(SetSuperAdminUseCase::new(users_repo.clone())),
            set_organization_admin: Arc::new(SetOrganizationAdminUseCase::new(users_repo.clone())),
            change_password: Arc::new(ChangePasswordUseCase::new(users_repo.clone(), hasher.clone(), email_sender.clone())),
            create_organization,
            create_repository,
            rename_repository: Arc::new(RenamePackageRepositoryUseCase::new(repository_store.clone(), repository_store.clone())),
            delete_repository: Arc::new(DeletePackageRepositoryUseCase::new(repository_store.clone())),
            add_group_member,
            remove_group_member: Arc::new(RemoveGroupMemberUseCase::new(repository_store.clone())),
            set_repository_quota,
            set_retention_policy,
            sweep_retention,
            grant_permission,
            revoke_permission: Arc::new(RevokePermissionUseCase::new(permission_store.clone())),
            query_audit_log: Arc::new(QueryAuditLogUseCase::new(event_publisher.clone())),
            record_security_event: Arc::new(RecordSecurityEventUseCase::new(event_publisher.clone())),
            get_usage_metrics: get_usage_metrics.clone(),
            get_metrics_history: Arc::new(GetMetricsHistoryUseCase::new(metrics_snapshots.clone())),
            record_metrics_snapshot: Arc::new(RecordMetricsSnapshotUseCase::new(users_repo.clone(), get_usage_metrics, metrics_snapshots)),
            get_health_status: Arc::new(GetHealthStatusUseCase::new(health_check.clone(), storage.clone(), started_at)),
            get_admin_stats: Arc::new(GetAdminStatsUseCase::new(users_repo.clone(), repository_store.clone(), permission_store.clone())),
            export_configuration: Arc::new(ExportConfigurationUseCase::new(users_repo.clone(), repository_store.clone(), permission_store.clone(), system_settings.clone())),
            import_configuration,
            create_api_token: Arc::new(CreateApiTokenUseCase::new(api_tokens.clone())),
            list_api_tokens: Arc::new(ListApiTokensUseCase::new(api_tokens.clone())),
            revoke_api_token: Arc::new(RevokeApiTokenUseCase::new(api_tokens.clone())),
            admin_list_api_tokens: Arc::new(AdminListApiTokensUseCase::new(api_tokens.clone(), users_repo.clone())),
            admin_revoke_api_token: Arc::new(AdminRevokeApiTokenUseCase::new(api_tokens.clone())),
            list_repository_packages: Arc::new(ListRepositoryPackagesUseCase::new(
                npm_packages.clone(),
                dependency_audits.clone(),
                docker_manifests.clone(),
                docker_image_scans.clone(),
            )),
            get_npm_package_details: Arc::new(GetNpmPackageDetailsUseCase::new(npm_packages.clone())),
            get_docker_image_details: Arc::new(GetDockerImageDetailsUseCase::new(docker_manifests.clone())),
            unpublish_npm_package: unpublish_npm_package.clone(),
            audit_npm_package: Arc::new(AuditNpmPackageUseCase::new(npm_packages.clone(), npm_audit.clone())),
            scan_dependency_tree: Arc::new(ScanDependencyTreeUseCase::new(
                npm_packages.clone(),
                public_registry,
                npm_audit.clone(),
                dependency_audits.clone(),
            )),
            get_dependency_audit: Arc::new(GetDependencyAuditResultUseCase::new(npm_packages.clone(), dependency_audits)),
            scan_docker_image: Arc::new(ScanDockerImageUseCase::new(
                docker_manifests.clone(),
                repository_store.clone(),
                docker_token_issuer,
                docker_scanner,
                docker_image_scans.clone(),
            )),
            get_docker_image_scan: Arc::new(GetDockerImageScanResultUseCase::new(docker_manifests.clone(), docker_image_scans)),
            delete_docker_manifest: delete_docker_manifest.clone(),
            delete_docker_image,
            token_issuer,
            login_throttle,
            get_system_settings: Arc::new(GetSystemSettingsUseCase::new(system_settings.clone())),
            update_system_settings,
            get_smtp_settings: Arc::new(GetSmtpSettingsUseCase::new(smtp_settings.clone())),
            update_smtp_settings: Arc::new(UpdateSmtpSettingsUseCase::new(smtp_settings)),
            send_test_email: Arc::new(SendTestEmailUseCase::new(email_sender.clone())),
            get_branding: Arc::new(GetBrandingUseCase::new(
                branding.clone(),
                BrandingDefaults {
                    logo: BrandingAsset { bytes: branding_defaults::DEFAULT_LOGO_BYTES.to_vec(), content_type: branding_defaults::DEFAULT_LOGO_CONTENT_TYPE.to_string() },
                    favicon: BrandingAsset { bytes: branding_defaults::DEFAULT_FAVICON_BYTES.to_vec(), content_type: branding_defaults::DEFAULT_FAVICON_CONTENT_TYPE.to_string() },
                },
            )),
            set_branding_logo: Arc::new(SetBrandingLogoUseCase::new(branding.clone())),
            clear_branding_logo: Arc::new(ClearBrandingLogoUseCase::new(branding.clone())),
            set_branding_favicon: Arc::new(SetBrandingFaviconUseCase::new(branding.clone())),
            clear_branding_favicon: Arc::new(ClearBrandingFaviconUseCase::new(branding)),
            // Scoped to hangar_base_domain, not public_url — the invitation must link to
            // the invitee's own organization's subdomain.
            invite_user: Arc::new(InviteUserUseCase::new(
                users_repo.clone(),
                user_invitations.clone(),
                hasher.clone(),
                email_sender.clone(),
                organizations.clone(),
                config.hangar_base_domain.clone(),
            )),
            resend_invitation: Arc::new(ResendInvitationUseCase::new(users_repo.clone(), user_invitations.clone(), email_sender.clone(), organizations.clone(), config.hangar_base_domain.clone())),
            activate_account: Arc::new(ActivateAccountUseCase::new(users_repo.clone(), user_invitations.clone(), hasher.clone())),
            user_invitations,
            totp_credentials: totp_credentials.clone(),
            mfa_pending_token_issuer,
            get_mfa_status: Arc::new(GetMfaStatusUseCase::new(totp_credentials.clone(), backup_codes.clone(), webauthn_credentials.clone())),
            enroll_totp: Arc::new(EnrollTotpUseCase::new(totp_credentials.clone())),
            confirm_totp: Arc::new(ConfirmTotpUseCase::new(totp_credentials.clone(), backup_codes.clone(), users_repo.clone(), email_sender.clone())),
            verify_totp: Arc::new(VerifyTotpUseCase::new(totp_credentials.clone())),
            verify_backup_code: Arc::new(VerifyBackupCodeUseCase::new(backup_codes.clone())),
            disable_totp: Arc::new(DisableTotpUseCase::new(users_repo.clone(), hasher.clone(), totp_credentials.clone(), backup_codes.clone())),
            regenerate_backup_codes: Arc::new(RegenerateBackupCodesUseCase::new(users_repo.clone(), hasher.clone(), totp_credentials, backup_codes)),
            webauthn_credentials: webauthn_credentials.clone(),
            start_passkey_registration: Arc::new(StartPasskeyRegistrationUseCase::new(webauthn_client.clone(), webauthn_credentials.clone(), passkey_ceremonies.clone())),
            finish_passkey_registration: Arc::new(FinishPasskeyRegistrationUseCase::new(webauthn_client.clone(), webauthn_credentials.clone(), passkey_ceremonies.clone(), users_repo.clone(), email_sender.clone())),
            start_passkey_authentication: Arc::new(StartPasskeyAuthenticationUseCase::new(webauthn_client.clone(), webauthn_credentials.clone(), passkey_ceremonies.clone())),
            finish_passkey_authentication: Arc::new(FinishPasskeyAuthenticationUseCase::new(webauthn_client, webauthn_credentials.clone(), passkey_ceremonies)),
            list_passkeys: Arc::new(ListPasskeysUseCase::new(webauthn_credentials.clone())),
            delete_passkey: Arc::new(DeletePasskeyUseCase::new(users_repo, hasher, webauthn_credentials)),
        }
    }
}
