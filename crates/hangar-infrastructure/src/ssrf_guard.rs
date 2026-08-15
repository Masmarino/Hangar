//! Blocks outbound requests to private/internal targets — every remote URL we fetch, including
//! follow-ups the remote hands back. Checks DNS at call time, so it won't catch rebinding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hangar_domain::error::DomainError;

pub async fn ensure_public_host(url: &str) -> Result<(), DomainError> {
    let parsed = reqwest::Url::parse(url).map_err(|e| DomainError::Infrastructure(format!("invalid remote URL {url}: {e}")))?;
    let host = parsed.host_str().ok_or_else(|| DomainError::Infrastructure(format!("remote URL {url} has no host")))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    ensure_public_host_and_port(host, port).await
}

/// Same check as [`ensure_public_host`], for callers (LDAP, SMTP) whose target is a bare host/port pair rather than a URL.
pub async fn ensure_public_host_and_port(host: &str, port: u16) -> Result<(), DomainError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return reject_if_private(ip, host);
    }

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| DomainError::Infrastructure(format!("resolving host {host}: {e}")))?;
    let mut resolved_any = false;
    for addr in addrs {
        resolved_any = true;
        reject_if_private(addr.ip(), host)?;
    }
    if !resolved_any {
        return Err(DomainError::Infrastructure(format!("host {host} did not resolve to any address")));
    }
    Ok(())
}

fn reject_if_private(ip: IpAddr, host: &str) -> Result<(), DomainError> {
    if is_private_or_reserved(ip) {
        return Err(DomainError::Infrastructure(format!("host {host} resolves to a private or reserved address ({ip}), which is not allowed")));
    }
    Ok(())
}

fn is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_reserved_v4(v4),
        IpAddr::V6(v6) => is_private_or_reserved_v6(v6),
    }
}

fn is_private_or_reserved_v4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
}

fn is_private_or_reserved_v6(ip: Ipv6Addr) -> bool {
    // An IPv4-mapped address (::ffff:a.b.c.d) is checked against the same IPv4 ranges.
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.to_ipv4_mapped().is_some_and(is_private_or_reserved_v4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback() {
        assert!(is_private_or_reserved("127.0.0.1".parse().unwrap()));
        assert!(is_private_or_reserved("::1".parse().unwrap()));
    }

    #[test]
    fn rejects_rfc1918_private_ranges() {
        assert!(is_private_or_reserved("10.0.0.5".parse().unwrap()));
        assert!(is_private_or_reserved("172.16.5.1".parse().unwrap()));
        assert!(is_private_or_reserved("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn rejects_link_local_including_the_cloud_metadata_address() {
        assert!(is_private_or_reserved("169.254.169.254".parse().unwrap()));
        assert!(is_private_or_reserved("fe80::1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_unique_local() {
        assert!(is_private_or_reserved("fc00::1".parse().unwrap()));
    }

    #[test]
    fn rejects_an_ipv4_mapped_private_address() {
        assert!(is_private_or_reserved("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_a_real_public_address() {
        assert!(!is_private_or_reserved("1.1.1.1".parse().unwrap()));
        assert!(!is_private_or_reserved("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn rejects_a_url_whose_literal_host_is_a_private_ip() {
        let err = ensure_public_host("http://127.0.0.1:8080/").await.unwrap_err();
        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_a_url_pointing_at_localhost_by_name() {
        let err = ensure_public_host("http://localhost:8080/").await.unwrap_err();
        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_a_bare_host_that_is_a_private_ip() {
        let err = ensure_public_host_and_port("127.0.0.1", 389).await.unwrap_err();
        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_a_bare_hostname_resolving_to_localhost() {
        let err = ensure_public_host_and_port("localhost", 389).await.unwrap_err();
        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }

    #[tokio::test]
    #[ignore = "requires network access to resolve one.one.one.one"]
    async fn allows_a_bare_public_hostname() {
        ensure_public_host_and_port("one.one.one.one", 443).await.unwrap();
    }
}
