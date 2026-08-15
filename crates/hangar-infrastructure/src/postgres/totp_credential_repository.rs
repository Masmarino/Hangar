use async_trait::async_trait;
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::mfa::{TotpCredential, TotpCredentialPort};
use sqlx::PgPool;
use uuid::Uuid;

use crate::secret_box;

pub struct PostgresTotpCredentialRepository {
    pool: PgPool,
    secrets_encryption_key: String,
}

impl PostgresTotpCredentialRepository {
    pub fn new(pool: PgPool, secrets_encryption_key: String) -> Self {
        Self { pool, secrets_encryption_key }
    }
}

#[async_trait]
impl TotpCredentialPort for PostgresTotpCredentialRepository {
    async fn get(&self, user_id: Uuid) -> Result<Option<TotpCredential>, DomainError> {
        let row = sqlx::query!(
            "SELECT user_id, encrypted_secret, secret_nonce, confirmed, last_used_step, created_at FROM totp_credentials WHERE user_id = $1",
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        let Some(row) = row else {
            return Ok(None);
        };
        let secret = secret_box::decrypt(&row.encrypted_secret, &row.secret_nonce, &self.secrets_encryption_key)?;
        Ok(Some(TotpCredential { user_id: row.user_id, secret, confirmed: row.confirmed, last_used_step: row.last_used_step, created_at: row.created_at }))
    }

    async fn upsert(&self, credential: &TotpCredential) -> Result<(), DomainError> {
        let (encrypted_secret, secret_nonce) = secret_box::encrypt(&credential.secret, &self.secrets_encryption_key);
        sqlx::query!(
            "INSERT INTO totp_credentials (user_id, encrypted_secret, secret_nonce, confirmed, last_used_step, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (user_id) DO UPDATE SET \
             encrypted_secret = EXCLUDED.encrypted_secret, secret_nonce = EXCLUDED.secret_nonce, \
             confirmed = EXCLUDED.confirmed, last_used_step = EXCLUDED.last_used_step",
            credential.user_id,
            encrypted_secret,
            secret_nonce,
            credential.confirmed,
            credential.last_used_step,
            credential.created_at,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn set_last_used_step(&self, user_id: Uuid, step: i64) -> Result<bool, DomainError> {
        // The AND guard makes this a compare-and-swap — only the first concurrent caller wins.
        let result = sqlx::query!(
            "UPDATE totp_credentials SET last_used_step = $1 WHERE user_id = $2 AND (last_used_step IS NULL OR last_used_step < $1)",
            step,
            user_id
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete(&self, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!("DELETE FROM totp_credentials WHERE user_id = $1", user_id).execute(&self.pool).await.infra_err()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_domain::user::{User, UserRepositoryPort, Username};

    use crate::postgres::user_repository::PostgresUserRepository;

    async fn seed_user(pool: &PgPool) -> Uuid {
        let users = PostgresUserRepository::new(pool.clone());
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("mfauser").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        users.insert(&user).await.unwrap();
        user.id
    }

    fn sample(user_id: Uuid) -> TotpCredential {
        TotpCredential { user_id, secret: "JBSWY3DPEHPK3PXP".to_string(), confirmed: false, last_used_step: None, created_at: chrono::Utc::now() }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn get_returns_none_when_never_enrolled(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresTotpCredentialRepository::new(pool, "jwt-secret".to_string());
        assert_eq!(repo.get(user_id).await.unwrap(), None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn upsert_then_get_round_trips_including_the_secret(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresTotpCredentialRepository::new(pool, "jwt-secret".to_string());
        let credential = sample(user_id);
        repo.upsert(&credential).await.unwrap();

        let found = repo.get(user_id).await.unwrap().unwrap();
        // Postgres timestamptz only keeps microsecond precision — compare at that granularity, not against Utc::now()'s full nanosecond value.
        assert_eq!(
            TotpCredential { created_at: found.created_at, ..credential.clone() },
            found
        );
        assert_eq!(found.created_at.timestamp_micros(), credential.created_at.timestamp_micros());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_upsert_confirms_rather_than_duplicating(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresTotpCredentialRepository::new(pool, "jwt-secret".to_string());
        repo.upsert(&sample(user_id)).await.unwrap();
        repo.upsert(&TotpCredential { confirmed: true, ..sample(user_id) }).await.unwrap();

        assert!(repo.get(user_id).await.unwrap().unwrap().confirmed);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn set_last_used_step_persists(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresTotpCredentialRepository::new(pool, "jwt-secret".to_string());
        repo.upsert(&sample(user_id)).await.unwrap();

        let advanced = repo.set_last_used_step(user_id, 42).await.unwrap();

        assert!(advanced);
        assert_eq!(repo.get(user_id).await.unwrap().unwrap().last_used_step, Some(42));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn set_last_used_step_is_a_compare_and_swap_not_an_unconditional_write(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresTotpCredentialRepository::new(pool, "jwt-secret".to_string());
        repo.upsert(&sample(user_id)).await.unwrap();

        let first = repo.set_last_used_step(user_id, 100).await.unwrap();
        let second = repo.set_last_used_step(user_id, 100).await.unwrap();
        let backward = repo.set_last_used_step(user_id, 99).await.unwrap();

        assert!(first, "the first caller to advance the step must succeed");
        assert!(!second, "a second caller presenting the same step must not also succeed");
        assert!(!backward, "advancing to an older step than what's already stored must fail");
        assert_eq!(repo.get(user_id).await.unwrap().unwrap().last_used_step, Some(100));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn delete_removes_the_credential(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresTotpCredentialRepository::new(pool, "jwt-secret".to_string());
        repo.upsert(&sample(user_id)).await.unwrap();

        repo.delete(user_id).await.unwrap();

        assert_eq!(repo.get(user_id).await.unwrap(), None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_secret_is_never_stored_in_plaintext(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresTotpCredentialRepository::new(pool, "jwt-secret".to_string());
        repo.upsert(&sample(user_id)).await.unwrap();

        let row: (Vec<u8>,) = sqlx::query_as("SELECT encrypted_secret FROM totp_credentials WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        let stored = String::from_utf8_lossy(&row.0);
        assert!(!stored.contains("JBSWY3DPEHPK3PXP"));
    }
}
