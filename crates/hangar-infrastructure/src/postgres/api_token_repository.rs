use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hangar_domain::api_token::{ApiToken, ApiTokenRepositoryPort};
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresApiTokenRepository {
    pool: PgPool,
}

impl PostgresApiTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct TokenRow {
    id: Uuid,
    user_id: Uuid,
    token_hash: String,
    label: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<TokenRow> for ApiToken {
    fn from(row: TokenRow) -> Self {
        ApiToken {
            id: row.id,
            user_id: row.user_id,
            token_hash: row.token_hash,
            label: row.label,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[async_trait]
impl ApiTokenRepositoryPort for PostgresApiTokenRepository {
    async fn insert(&self, token: &ApiToken) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO api_tokens (id, user_id, token_hash, label, created_at, last_used_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            token.id,
            token.user_id,
            token.token_hash,
            token.label,
            token.created_at,
            token.last_used_at,
            token.revoked_at,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ApiToken>, DomainError> {
        // Revoked tokens are filtered out entirely, not returned with revoked_at set.
        let rows = sqlx::query_as!(
            TokenRow,
            "SELECT id, user_id, token_hash, label, created_at, last_used_at, revoked_at FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC",
            user_id
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        Ok(rows.into_iter().map(ApiToken::from).collect())
    }

    async fn list_all(&self) -> Result<Vec<ApiToken>, DomainError> {
        let rows = sqlx::query_as!(
            TokenRow,
            "SELECT id, user_id, token_hash, label, created_at, last_used_at, revoked_at FROM api_tokens ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        Ok(rows.into_iter().map(ApiToken::from).collect())
    }

    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<ApiToken>, DomainError> {
        let row = sqlx::query_as!(
            TokenRow,
            "SELECT id, user_id, token_hash, label, created_at, last_used_at, revoked_at FROM api_tokens WHERE token_hash = $1",
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        Ok(row.map(ApiToken::from))
    }

    async fn touch_last_used_at(&self, id: Uuid, used_at: DateTime<Utc>) -> Result<(), DomainError> {
        sqlx::query!("UPDATE api_tokens SET last_used_at = $2 WHERE id = $1", id, used_at)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn revoke(&self, id: Uuid, user_id: Uuid) -> Result<bool, DomainError> {
        let result = sqlx::query!("UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2", id, user_id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(result.rows_affected() > 0)
    }

    async fn revoke_any(&self, id: Uuid) -> Result<(), DomainError> {
        sqlx::query!("UPDATE api_tokens SET revoked_at = now() WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_domain::api_token::ApiToken;

    fn sample(user_id: Uuid) -> ApiToken {
        ApiToken { id: Uuid::new_v4(), user_id, token_hash: "hash-1".into(), label: "laptop".into(), created_at: chrono::Utc::now(), last_used_at: None, revoked_at: None }
    }

    async fn seed_user(pool: &sqlx::PgPool, id: Uuid) {
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash, is_super_admin, organization_id, created_at) VALUES ($1, $2, 'h', FALSE, $3, now())",
            id,
            format!("user-{id}"),
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn inserts_and_finds_by_hash(pool: sqlx::PgPool) {
        let user_id = Uuid::new_v4();
        seed_user(&pool, user_id).await;
        let repo = PostgresApiTokenRepository::new(pool);
        let token = sample(user_id);
        repo.insert(&token).await.unwrap();

        let found = repo.find_by_hash("hash-1").await.unwrap().unwrap();
        assert_eq!(found.id, token.id);
    }

    #[sqlx::test]
    async fn revoke_only_affects_the_owning_user(pool: sqlx::PgPool) {
        let owner = Uuid::new_v4();
        let other = Uuid::new_v4();
        seed_user(&pool, owner).await;
        seed_user(&pool, other).await;
        let repo = PostgresApiTokenRepository::new(pool);
        let token = sample(owner);
        repo.insert(&token).await.unwrap();

        assert!(!repo.revoke(token.id, other).await.unwrap(), "revoke must report no row affected for a non-owner");
        let unaffected = repo.find_by_hash("hash-1").await.unwrap().unwrap();
        assert!(unaffected.revoked_at.is_none());

        assert!(repo.revoke(token.id, owner).await.unwrap(), "revoke must report a row affected for the owner");
        let revoked = repo.find_by_hash("hash-1").await.unwrap().unwrap();
        assert!(revoked.revoked_at.is_some());
    }

    #[sqlx::test]
    async fn list_for_user_excludes_revoked_tokens(pool: sqlx::PgPool) {
        let owner = Uuid::new_v4();
        seed_user(&pool, owner).await;
        let repo = PostgresApiTokenRepository::new(pool);

        let active = sample(owner);
        let mut to_revoke = sample(owner);
        to_revoke.id = Uuid::new_v4();
        to_revoke.token_hash = "hash-2".into();
        repo.insert(&active).await.unwrap();
        repo.insert(&to_revoke).await.unwrap();

        let before = repo.list_for_user(owner).await.unwrap();
        assert_eq!(before.len(), 2, "both tokens should be listed before either is revoked");

        repo.revoke(to_revoke.id, owner).await.unwrap();

        let after = repo.list_for_user(owner).await.unwrap();
        assert_eq!(after.len(), 1, "a revoked token must disappear from the list");
        assert_eq!(after[0].id, active.id);
    }

    #[sqlx::test]
    async fn list_all_includes_tokens_across_every_user_and_keeps_revoked_ones(pool: sqlx::PgPool) {
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        seed_user(&pool, alice).await;
        seed_user(&pool, bob).await;
        let repo = PostgresApiTokenRepository::new(pool);

        let alices_token = sample(alice);
        let mut bobs_token = sample(bob);
        bobs_token.id = Uuid::new_v4();
        bobs_token.token_hash = "hash-2".into();
        repo.insert(&alices_token).await.unwrap();
        repo.insert(&bobs_token).await.unwrap();
        repo.revoke(bobs_token.id, bob).await.unwrap();

        let all = repo.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
        let revoked = all.iter().find(|t| t.id == bobs_token.id).unwrap();
        assert!(revoked.revoked_at.is_some(), "list_all must keep revoked tokens, not drop them");
    }

    #[sqlx::test]
    async fn revoke_any_revokes_regardless_of_owner(pool: sqlx::PgPool) {
        let owner = Uuid::new_v4();
        seed_user(&pool, owner).await;
        let repo = PostgresApiTokenRepository::new(pool);
        let token = sample(owner);
        repo.insert(&token).await.unwrap();

        repo.revoke_any(token.id).await.unwrap();

        let revoked = repo.find_by_hash("hash-1").await.unwrap().unwrap();
        assert!(revoked.revoked_at.is_some());
    }
}
