pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    /// Encrypts secrets at rest (SMTP/LDAP/OIDC/TOTP). Separate from `jwt_secret` so a leaked JWT_SECRET doesn't also expose these; falls back to it when unset.
    pub secrets_encryption_key: String,
    pub storage_root: String,
    pub bind_addr: String,
    /// `None` restricts CORS to localhost/127.0.0.1/[::1] on any port (see `main::cors_layer`).
    pub cors_allowed_origin: Option<String>,
    /// Defaults from `bind_addr` — wrong behind a reverse proxy or TLS termination, override with `HANGAR_DOCKER_TOKEN_REALM`.
    pub docker_token_realm: String,
    /// Base URL invitation links are built against. Defaults from `bind_addr`, override with `PUBLIC_URL` behind a proxy.
    pub public_url: String,
    /// Postgres pool size, override with `DB_MAX_CONNECTIONS`.
    pub db_max_connections: u32,
    /// The base domain subdomains are resolved against. Mandatory (`HANGAR_BASE_DOMAIN`), no fallback — a misconfigured deployment must fail loudly at startup.
    pub hangar_base_domain: String,
}

impl Config {
    pub fn from_env() -> Self {
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        Self {
            database_url: std::env::var("DATABASE_URL").expect("DATABASE_URL must be set"),
            secrets_encryption_key: std::env::var("SECRETS_ENCRYPTION_KEY").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| jwt_secret.clone()),
            jwt_secret,
            storage_root: std::env::var("STORAGE_ROOT").unwrap_or_else(|_| "./data".to_string()),
            bind_addr: std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            // docker-compose ${VAR:-} passthroughs set an empty string, not unset.
            cors_allowed_origin: std::env::var("CORS_ALLOWED_ORIGIN").ok().filter(|s| !s.is_empty()),
            docker_token_realm: std::env::var("HANGAR_DOCKER_TOKEN_REALM")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("http://{}/v2/token", std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()))),
            public_url: std::env::var("PUBLIC_URL")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("http://{}", std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()))),
            db_max_connections: std::env::var("DB_MAX_CONNECTIONS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(hangar_infrastructure::postgres::DEFAULT_DB_MAX_CONNECTIONS),
            // Lowercased to match ResolvedOrganization's own lowercasing of the Host header.
            hangar_base_domain: std::env::var("HANGAR_BASE_DOMAIN").expect("HANGAR_BASE_DOMAIN must be set").to_ascii_lowercase(),
        }
    }
}
