use async_trait::async_trait;
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::webauthn::{WebauthnCredential, WebauthnCredentialPort};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresWebauthnCredentialRepository {
    pool: PgPool,
}

impl PostgresWebauthnCredentialRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WebauthnCredentialPort for PostgresWebauthnCredentialRepository {
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<WebauthnCredential>, DomainError> {
        let rows = sqlx::query!("SELECT id, user_id, name, passkey_data, created_at FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at", user_id)
            .fetch_all(&self.pool)
            .await
            .infra_err()?;
        Ok(rows.into_iter().map(|r| WebauthnCredential { id: r.id, user_id: r.user_id, name: r.name, passkey_data: r.passkey_data, created_at: r.created_at }).collect())
    }

    async fn insert(&self, credential: &WebauthnCredential) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO webauthn_credentials (id, user_id, name, passkey_data, created_at) VALUES ($1, $2, $3, $4, $5)",
            credential.id,
            credential.user_id,
            credential.name,
            credential.passkey_data,
            credential.created_at,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn update_passkey_data(&self, id: Uuid, passkey_data: Vec<u8>) -> Result<(), DomainError> {
        sqlx::query!("UPDATE webauthn_credentials SET passkey_data = $1 WHERE id = $2", passkey_data, id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!("DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2", id, user_id).execute(&self.pool).await.infra_err()?;
        Ok(())
    }

    async fn count_for_user(&self, user_id: Uuid) -> Result<i64, DomainError> {
        let count: i64 = sqlx::query_scalar!("SELECT count(*) FROM webauthn_credentials WHERE user_id = $1", user_id)
            .fetch_one(&self.pool)
            .await
            .infra_err()?
            .unwrap_or(0);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_domain::user::{User, UserRepositoryPort, Username};

    use crate::postgres::user_repository::PostgresUserRepository;

    async fn seed_user(pool: &PgPool, username: &str) -> Uuid {
        let users = PostgresUserRepository::new(pool.clone());
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse(username).unwrap(),
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

    fn sample(user_id: Uuid) -> WebauthnCredential {
        WebauthnCredential { id: Uuid::new_v4(), user_id, name: "MacBook".to_string(), passkey_data: b"opaque-passkey-bytes".to_vec(), created_at: chrono::Utc::now() }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn insert_then_list_for_user_round_trips(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool, "florian").await;
        let repo = PostgresWebauthnCredentialRepository::new(pool);
        let credential = sample(user_id);
        repo.insert(&credential).await.unwrap();

        let listed = repo.list_for_user(user_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        let found = listed.into_iter().next().unwrap();
        // Postgres timestamptz only keeps microsecond precision, so compare created_at
        // at that granularity rather than against Utc::now()'s full nanosecond value.
        assert_eq!(
            WebauthnCredential { created_at: found.created_at, ..credential.clone() },
            found
        );
        assert_eq!(found.created_at.timestamp_micros(), credential.created_at.timestamp_micros());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn list_for_user_returns_empty_when_none_registered(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool, "florian").await;
        let repo = PostgresWebauthnCredentialRepository::new(pool);
        assert_eq!(repo.list_for_user(user_id).await.unwrap(), vec![]);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn update_passkey_data_persists(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool, "florian").await;
        let repo = PostgresWebauthnCredentialRepository::new(pool);
        let credential = sample(user_id);
        repo.insert(&credential).await.unwrap();

        repo.update_passkey_data(credential.id, b"updated-bytes".to_vec()).await.unwrap();

        let listed = repo.list_for_user(user_id).await.unwrap();
        assert_eq!(listed[0].passkey_data, b"updated-bytes".to_vec());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn delete_only_removes_the_owners_credential(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool, "florian").await;
        let other_user_id = seed_user(&pool, "other-user").await;
        let repo = PostgresWebauthnCredentialRepository::new(pool);
        let credential = sample(user_id);
        repo.insert(&credential).await.unwrap();

        repo.delete(credential.id, other_user_id).await.unwrap();
        assert_eq!(repo.count_for_user(user_id).await.unwrap(), 1, "deleting with the wrong user_id must not remove the credential");

        repo.delete(credential.id, user_id).await.unwrap();
        assert_eq!(repo.count_for_user(user_id).await.unwrap(), 0);
    }
}
