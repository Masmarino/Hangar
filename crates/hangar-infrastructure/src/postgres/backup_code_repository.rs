use async_trait::async_trait;
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::mfa::BackupCodePort;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresBackupCodeRepository {
    pool: PgPool,
}

impl PostgresBackupCodeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BackupCodePort for PostgresBackupCodeRepository {
    async fn replace_all(&self, user_id: Uuid, code_hashes: &[String]) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.infra_err()?;
        sqlx::query!("DELETE FROM mfa_backup_codes WHERE user_id = $1", user_id).execute(&mut *tx).await.infra_err()?;
        if !code_hashes.is_empty() {
            sqlx::query!(
                "INSERT INTO mfa_backup_codes (user_id, code_hash) SELECT $1, * FROM UNNEST($2::text[])",
                user_id,
                code_hashes
            )
            .execute(&mut *tx)
            .await
            .infra_err()?;
        }
        tx.commit().await.infra_err()?;
        Ok(())
    }

    async fn try_consume(&self, user_id: Uuid, code_hash: &str) -> Result<bool, DomainError> {
        let result = sqlx::query!("UPDATE mfa_backup_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL", user_id, code_hash)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(result.rows_affected() > 0)
    }

    async fn count_unused(&self, user_id: Uuid) -> Result<i64, DomainError> {
        let count: i64 = sqlx::query_scalar!("SELECT count(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL", user_id)
            .fetch_one(&self.pool)
            .await
            .infra_err()?
            .unwrap_or(0);
        Ok(count)
    }

    async fn delete_all(&self, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!("DELETE FROM mfa_backup_codes WHERE user_id = $1", user_id).execute(&self.pool).await.infra_err()?;
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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn replace_all_then_try_consume_finds_the_new_codes(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresBackupCodeRepository::new(pool);
        repo.replace_all(user_id, &["hash-a".to_string(), "hash-b".to_string()]).await.unwrap();

        assert!(!repo.try_consume(user_id, "hash-c").await.unwrap(), "an unknown code must not consume");
        assert_eq!(repo.count_unused(user_id).await.unwrap(), 2);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_replace_all_wipes_the_first_set(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresBackupCodeRepository::new(pool);
        repo.replace_all(user_id, &["hash-a".to_string()]).await.unwrap();
        repo.replace_all(user_id, &["hash-b".to_string()]).await.unwrap();

        assert!(!repo.try_consume(user_id, "hash-a").await.unwrap(), "the old code must no longer be valid");
        assert_eq!(repo.count_unused(user_id).await.unwrap(), 1);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn try_consume_makes_the_code_single_use(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresBackupCodeRepository::new(pool);
        repo.replace_all(user_id, &["hash-a".to_string()]).await.unwrap();

        assert!(repo.try_consume(user_id, "hash-a").await.unwrap());
        assert!(!repo.try_consume(user_id, "hash-a").await.unwrap(), "the same code must not be usable twice");
        assert_eq!(repo.count_unused(user_id).await.unwrap(), 0);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn delete_all_removes_every_code(pool: sqlx::PgPool) {
        let user_id = seed_user(&pool).await;
        let repo = PostgresBackupCodeRepository::new(pool);
        repo.replace_all(user_id, &["hash-a".to_string(), "hash-b".to_string()]).await.unwrap();

        repo.delete_all(user_id).await.unwrap();

        assert_eq!(repo.count_unused(user_id).await.unwrap(), 0);
    }
}
