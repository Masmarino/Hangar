use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::sso::{ExternalIdentity, LdapAuthPort, LdapConfig};
use ldap3::{LdapConnAsync, Scope, SearchEntry};

pub struct Ldap3AuthAdapter;

/// Escapes LDAP filter metacharacters per RFC 4515 before substituting into the template, so a crafted username can't alter the filter's structure.
fn build_filter(template: &str, username: &str) -> String {
    let escaped: String = username
        .chars()
        .map(|c| match c {
            '(' => "\\28".to_string(),
            ')' => "\\29".to_string(),
            '\\' => "\\5c".to_string(),
            '*' => "\\2a".to_string(),
            '\0' => "\\00".to_string(),
            other => other.to_string(),
        })
        .collect();
    template.replace("{username}", &escaped)
}

/// Exactly one match required — zero or more than one both fail closed rather than guess.
fn extract_single_match(entries: Vec<SearchEntry>, email_attribute: &str) -> Result<(String, String), DomainError> {
    if entries.len() != 1 {
        return Err(DomainError::Infrastructure(format!("ldap search returned {} entries, expected exactly 1", entries.len())));
    }
    let entry = entries.into_iter().next().expect("length checked above");
    let email = entry
        .attrs
        .get(email_attribute)
        .and_then(|values| values.first())
        .ok_or_else(|| DomainError::Infrastructure(format!("ldap entry missing {email_attribute} attribute")))?
        .clone();
    Ok((entry.dn, email))
}

#[async_trait]
impl LdapAuthPort for Ldap3AuthAdapter {
    async fn authenticate(&self, config: &LdapConfig, username: &str, password: &str) -> Result<ExternalIdentity, DomainError> {
        // A non-empty DN with a zero-length password is an "unauthenticated bind" per RFC 4513 5.1.2 — some directories accept it regardless.
        if password.is_empty() {
            return Err(DomainError::Infrastructure("empty password rejected".to_string()));
        }

        // Same SSRF guard as the other admin-configured remote hosts (npm/docker/OIDC).
        crate::ssrf_guard::ensure_public_host(&config.server_url).await?;

        let (conn, mut ldap) = LdapConnAsync::new(&config.server_url).await.map_err(|e| DomainError::Infrastructure(format!("ldap connect failed: {e}")))?;
        ldap3::drive!(conn);

        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await
            .map_err(|e| DomainError::Infrastructure(format!("ldap service bind failed: {e}")))?
            .success()
            .map_err(|e| DomainError::Infrastructure(format!("ldap service bind rejected: {e}")))?;

        let filter = build_filter(&config.user_search_filter, username);
        let (results, _) = ldap
            .search(&config.user_search_base, Scope::Subtree, &filter, vec![config.email_attribute.as_str()])
            .await
            .map_err(|e| DomainError::Infrastructure(format!("ldap search failed: {e}")))?
            .success()
            .map_err(|e| DomainError::Infrastructure(format!("ldap search rejected: {e}")))?;

        let entries: Vec<SearchEntry> = results.into_iter().map(SearchEntry::construct).collect();
        let (dn, email) = extract_single_match(entries, &config.email_attribute)?;

        // The actual credential check — the earlier service-account bind proves nothing about the submitted password.
        ldap.simple_bind(&dn, password)
            .await
            .map_err(|e| DomainError::Infrastructure(format!("ldap user bind failed: {e}")))?
            .success()
            .map_err(|_| DomainError::Infrastructure("ldap user bind rejected: invalid credentials".to_string()))?;

        let _ = ldap.unbind().await;
        Ok(ExternalIdentity { email, display_name: None })
    }
}

#[cfg(test)]
mod tests {
    use hangar_domain::sso::LdapConfig;

    use super::*;

    #[tokio::test]
    async fn an_empty_password_is_rejected_without_contacting_the_directory() {
        let adapter = Ldap3AuthAdapter;
        let config = LdapConfig {
            server_url: "ldap://127.0.0.1:1".to_string(), // deliberately unroutable — if this test ever tries to connect, it will hang/fail slowly, proving the empty-password check didn't short-circuit
            bind_dn: "cn=service,dc=corp,dc=example".to_string(),
            bind_password: "s3cret!".to_string(),
            user_search_base: "ou=people,dc=corp,dc=example".to_string(),
            user_search_filter: "(uid={username})".to_string(),
            email_attribute: "mail".to_string(),
        };

        let result = adapter.authenticate(&config, "florian", "").await;

        // Asserting on the message, not just is_err() — a connection failure here would also produce an Err, masking a removed check.
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("empty password"), "got {err:?}");
    }

    #[tokio::test]
    async fn a_server_url_pointing_at_a_private_address_is_rejected_before_connecting() {
        let adapter = Ldap3AuthAdapter;
        let config = LdapConfig {
            server_url: "ldap://127.0.0.1:1".to_string(),
            bind_dn: "cn=service,dc=corp,dc=example".to_string(),
            bind_password: "s3cret!".to_string(),
            user_search_base: "ou=people,dc=corp,dc=example".to_string(),
            user_search_filter: "(uid={username})".to_string(),
            email_attribute: "mail".to_string(),
        };

        let err = adapter.authenticate(&config, "florian", "not-empty").await.unwrap_err();

        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }

    #[tokio::test]
    async fn a_server_url_pointing_at_the_cloud_metadata_endpoint_is_rejected() {
        let adapter = Ldap3AuthAdapter;
        let config = LdapConfig {
            server_url: "ldap://169.254.169.254".to_string(),
            bind_dn: "cn=service,dc=corp,dc=example".to_string(),
            bind_password: "s3cret!".to_string(),
            user_search_base: "ou=people,dc=corp,dc=example".to_string(),
            user_search_filter: "(uid={username})".to_string(),
            email_attribute: "mail".to_string(),
        };

        let err = adapter.authenticate(&config, "florian", "not-empty").await.unwrap_err();

        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }

    #[test]
    fn substitutes_the_username_placeholder() {
        assert_eq!(build_filter("(uid={username})", "florian"), "(uid=florian)");
    }

    #[test]
    fn escapes_ldap_filter_metacharacters_in_the_submitted_username() {
        assert_eq!(build_filter("(uid={username})", "a)(uid=*"), "(uid=a\\29\\28uid=\\2a)");
    }

    #[test]
    fn leaves_a_filter_with_no_placeholder_unchanged() {
        assert_eq!(build_filter("(objectClass=person)", "florian"), "(objectClass=person)");
    }

    fn entry(dn: &str, attrs: Vec<(&str, Vec<&str>)>) -> SearchEntry {
        SearchEntry {
            dn: dn.to_string(),
            attrs: attrs.into_iter().map(|(k, vs)| (k.to_string(), vs.into_iter().map(str::to_string).collect())).collect(),
            bin_attrs: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn a_single_match_with_the_email_attribute_present_succeeds() {
        let entries = vec![entry("uid=florian,ou=people,dc=corp,dc=example", vec![("mail", vec!["florian@corp.example"])])];

        let result = extract_single_match(entries, "mail");

        assert_eq!(result.unwrap(), ("uid=florian,ou=people,dc=corp,dc=example".to_string(), "florian@corp.example".to_string()));
    }

    #[test]
    fn zero_matches_is_rejected() {
        let result = extract_single_match(vec![], "mail");

        let err = result.unwrap_err();
        assert!(format!("{err}").contains("ldap search returned 0 entries, expected exactly 1"), "got {err:?}");
    }

    #[test]
    fn more_than_one_match_is_rejected() {
        let entries = vec![
            entry("uid=a,ou=people,dc=corp,dc=example", vec![("mail", vec!["a@corp.example"])]),
            entry("uid=b,ou=people,dc=corp,dc=example", vec![("mail", vec!["b@corp.example"])]),
        ];

        let result = extract_single_match(entries, "mail");

        let err = result.unwrap_err();
        assert!(format!("{err}").contains("ldap search returned 2 entries, expected exactly 1"), "got {err:?}");
    }

    #[test]
    fn a_single_match_missing_the_email_attribute_is_rejected() {
        let entries = vec![entry("uid=florian,ou=people,dc=corp,dc=example", vec![("cn", vec!["Florian"])])];

        let result = extract_single_match(entries, "mail");

        let err = result.unwrap_err();
        assert!(format!("{err}").contains("ldap entry missing mail attribute"), "got {err:?}");
    }

    #[test]
    fn a_single_match_with_an_empty_value_list_for_the_email_attribute_is_treated_as_missing() {
        // An empty Vec for the key takes the same "missing" path as the key being absent.
        let entries = vec![entry("uid=florian,ou=people,dc=corp,dc=example", vec![("mail", vec![])])];

        let result = extract_single_match(entries, "mail");

        let err = result.unwrap_err();
        assert!(format!("{err}").contains("ldap entry missing mail attribute"), "got {err:?}");
    }
}
