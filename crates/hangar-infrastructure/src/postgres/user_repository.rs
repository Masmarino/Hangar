use async_trait::async_trait;
use hangar_domain::error::DomainError;
use crate::error_ext::InfraErr;
use hangar_domain::user::{User, UserRepositoryPort, Username};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct UserRow {
    id: Uuid,
    username: String,
    password_hash: String,
    is_super_admin: bool,
    is_organization_admin: bool,
    organization_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    tokens_valid_after: chrono::DateTime<chrono::Utc>,
    email: Option<String>,
}

impl UserRow {
    fn into_domain(self) -> Result<User, DomainError> {
        Ok(User {
            id: self.id,
            username: Username::parse(&self.username)?,
            password_hash: self.password_hash,
            is_super_admin: self.is_super_admin,
            is_organization_admin: self.is_organization_admin,
            organization_id: self.organization_id,
            created_at: self.created_at,
            tokens_valid_after: self.tokens_valid_after,
            email: self.email,
        })
    }
}

#[async_trait]
impl UserRepositoryPort for PostgresUserRepository {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            UserRow,
            "SELECT id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at, tokens_valid_after, email FROM users WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(UserRow::into_domain).transpose()
    }

    async fn find_by_username(&self, username: &Username) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            UserRow,
            "SELECT id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at, tokens_valid_after, email FROM users WHERE username = $1",
            username.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(UserRow::into_domain).transpose()
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            UserRow,
            "SELECT id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at, tokens_valid_after, email FROM users WHERE email = $1",
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(UserRow::into_domain).transpose()
    }

    async fn list_all(&self) -> Result<Vec<User>, DomainError> {
        let rows = sqlx::query_as!(
            UserRow,
            "SELECT id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at, tokens_valid_after, email FROM users ORDER BY created_at"
        )
        .fetch_all(&self.pool)
        .await
        .infra_err()?;
        rows.into_iter().map(UserRow::into_domain).collect()
    }

    async fn insert(&self, user: &User) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO users (id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at, tokens_valid_after, email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            user.id,
            user.username.as_str(),
            user.password_hash,
            user.is_super_admin,
            user.is_organization_admin,
            user.organization_id,
            user.created_at,
            user.tokens_valid_after,
            user.email,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.constraint() == Some("users_email_unique") => DomainError::EmailTaken,
            _ => DomainError::Infrastructure(e.to_string()),
        })?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<(), DomainError> {
        sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), DomainError> {
        sqlx::query!(
            "UPDATE users SET password_hash = $1, tokens_valid_after = now() WHERE id = $2",
            new_password_hash,
            id
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn set_super_admin(&self, id: Uuid, is_super_admin: bool) -> Result<(), DomainError> {
        sqlx::query!("UPDATE users SET is_super_admin = $1 WHERE id = $2", is_super_admin, id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError> {
        sqlx::query!("UPDATE users SET is_organization_admin = $1 WHERE id = $2", is_organization_admin, id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }

    async fn delete_unless_last_super_admin(&self, id: Uuid) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.infra_err()?;

        // Serializes any operation that could change the super-admin count —
        // a per-row lock isn't enough since two concurrent ops can each
        // target a different admin.
        sqlx::query!("SELECT pg_advisory_xact_lock(hashtext('user_super_admin_guard'))")
            .execute(&mut *tx)
            .await
            .infra_err()?;

        let target_is_admin: Option<bool> = sqlx::query_scalar!("SELECT is_super_admin FROM users WHERE id = $1", id)
            .fetch_optional(&mut *tx)
            .await
            .infra_err()?;

        if target_is_admin == Some(true) {
            let remaining: i64 = sqlx::query_scalar!("SELECT count(*) FROM users WHERE is_super_admin AND id <> $1", id)
                .fetch_one(&mut *tx)
                .await
                .infra_err()?
                .unwrap_or(0);
            if remaining == 0 {
                return Ok(false); // tx drops here without commit -> rolls back
            }
        }

        sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(&mut *tx)
            .await
            .infra_err()?;
        tx.commit().await.infra_err()?;
        Ok(true)
    }

    async fn set_super_admin_unless_last(&self, id: Uuid, is_super_admin: bool) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.infra_err()?;

        sqlx::query!("SELECT pg_advisory_xact_lock(hashtext('user_super_admin_guard'))")
            .execute(&mut *tx)
            .await
            .infra_err()?;

        if !is_super_admin {
            let target_is_admin: Option<bool> = sqlx::query_scalar!("SELECT is_super_admin FROM users WHERE id = $1", id)
                .fetch_optional(&mut *tx)
                .await
                .infra_err()?;
            if target_is_admin == Some(true) {
                let remaining: i64 = sqlx::query_scalar!("SELECT count(*) FROM users WHERE is_super_admin AND id <> $1", id)
                    .fetch_one(&mut *tx)
                    .await
                    .infra_err()?
                    .unwrap_or(0);
                if remaining == 0 {
                    return Ok(false);
                }
            }
        }

        sqlx::query!("UPDATE users SET is_super_admin = $1 WHERE id = $2", is_super_admin, id)
            .execute(&mut *tx)
            .await
            .infra_err()?;
        tx.commit().await.infra_err()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[sqlx::test]
    async fn inserts_and_finds_a_user_by_username(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: true,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        repo.insert(&user).await.unwrap();

        let found = repo.find_by_username(&Username::parse("florian").unwrap()).await.unwrap().unwrap();
        assert_eq!(found.id, user.id);
        assert!(found.is_super_admin);
    }

    #[sqlx::test]
    async fn returns_none_for_an_unknown_username(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let found = repo.find_by_username(&Username::parse("ghost").unwrap()).await.unwrap();
        assert!(found.is_none());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn finds_a_user_by_email(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: Some("florian@example.com".to_string()),
        };
        repo.insert(&user).await.unwrap();

        let found = repo.find_by_email("florian@example.com").await.unwrap().unwrap();
        assert_eq!(found.id, user.id);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn finding_by_an_unknown_email_returns_none(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        assert!(repo.find_by_email("nobody@example.com").await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn deletes_a_user(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("todelete").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        repo.insert(&user).await.unwrap();
        repo.delete(user.id).await.unwrap();
        assert!(repo.find_by_id(user.id).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn only_one_of_two_concurrent_demotions_of_different_admins_succeeds(pool: sqlx::PgPool) {
        let repo = Arc::new(PostgresUserRepository::new(pool));
        let admin_a = User {
            id: Uuid::new_v4(),
            username: Username::parse("admin-a").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: true,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        let admin_b = User {
            id: Uuid::new_v4(),
            username: Username::parse("admin-b").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: true,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        repo.insert(&admin_a).await.unwrap();
        repo.insert(&admin_b).await.unwrap();

        let repo_a = repo.clone();
        let repo_b = repo.clone();
        let id_a = admin_a.id;
        let id_b = admin_b.id;

        let (result_a, result_b) = tokio::join!(
            tokio::spawn(async move { repo_a.set_super_admin_unless_last(id_a, false).await.unwrap() }),
            tokio::spawn(async move { repo_b.set_super_admin_unless_last(id_b, false).await.unwrap() }),
        );
        let result_a = result_a.unwrap();
        let result_b = result_b.unwrap();

        assert_ne!(result_a, result_b, "exactly one of the two concurrent demotions must succeed, got a={result_a} b={result_b}");

        let remaining_admins = repo.list_all().await.unwrap().into_iter().filter(|u| u.is_super_admin).count();
        assert_eq!(remaining_admins, 1, "the system must never end up with zero super-admins");
    }

    #[sqlx::test]
    async fn updates_the_password_hash(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "old-hash".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        repo.insert(&user).await.unwrap();

        repo.update_password(user.id, "new-hash".to_string()).await.unwrap();

        let found = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(found.password_hash, "new-hash");
    }

    #[sqlx::test]
    async fn sets_organization_admin_status(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        repo.insert(&user).await.unwrap();

        repo.set_organization_admin(user.id, true).await.unwrap();

        let found = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert!(found.is_organization_admin);
    }
}
