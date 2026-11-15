use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

pub trait ToSocketAddrsWithHostname {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>>;
    fn hostname(&self) -> String;
}

// SSH known-host lookup receives the port separately. Preserve the original DNS
// name/IP spelling while removing the endpoint's port and IPv6 brackets.
fn hostname_from_endpoint(address: &str) -> &str {
    let Some((host, port)) = address.rsplit_once(':') else {
        return address;
    };
    if port.parse::<u16>().is_err() || host.is_empty() {
        return address;
    }
    if let Some(ipv6) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return if ipv6.is_empty() { address } else { ipv6 };
    }
    // An unbracketed IPv6 address is a host, not an unambiguous host:port pair.
    if host.contains(':') { address } else { host }
}

impl ToSocketAddrsWithHostname for String {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.as_str().to_socket_addrs().map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        hostname_from_endpoint(self).to_string()
    }
}

impl ToSocketAddrsWithHostname for &str {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        hostname_from_endpoint(self).to_string()
    }
}

impl ToSocketAddrsWithHostname for (&str, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.0.to_string()
    }
}

impl ToSocketAddrsWithHostname for (String, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        self.0.clone()
    }
}

impl ToSocketAddrsWithHostname for (IpAddr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
}

impl ToSocketAddrsWithHostname for (Ipv4Addr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
}

impl ToSocketAddrsWithHostname for (Ipv6Addr, u16) {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        ToSocketAddrs::to_socket_addrs(self).map(|iter| iter.collect())
    }
    fn hostname(&self) -> String {
        format!("{}", self.0)
    }
}

impl ToSocketAddrsWithHostname for SocketAddr {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![*self])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
}

impl ToSocketAddrsWithHostname for SocketAddrV4 {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::V4(*self)])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
}

impl ToSocketAddrsWithHostname for SocketAddrV6 {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::V6(*self)])
    }
    fn hostname(&self) -> String {
        format!("{}", self.ip())
    }
}

impl ToSocketAddrsWithHostname for &[SocketAddr] {
    fn to_socket_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(self.to_vec())
    }

    fn hostname(&self) -> String {
        self.iter()
            .map(|addr| addr.ip().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_endpoints_provide_hosts_without_ports_or_ipv6_brackets() {
        for (endpoint, expected) in [
            ("router.example:22", "router.example"),
            ("router.example:2222", "router.example"),
            ("127.0.0.1:2222", "127.0.0.1"),
            ("[::1]:22", "::1"),
            ("[2001:db8::1]:2222", "2001:db8::1"),
            ("[fe80::1%2]:2222", "fe80::1%2"),
            ("2001:db8::22", "2001:db8::22"),
            ("router.example", "router.example"),
            ("router.example:invalid", "router.example:invalid"),
        ] {
            assert_eq!(endpoint.hostname(), expected, "borrowed {endpoint}");
            assert_eq!(
                endpoint.to_string().hostname(),
                expected,
                "owned {endpoint}"
            );
        }
    }

    #[test]
    fn tuple_and_socket_hosts_keep_their_existing_identity() {
        assert_eq!(("router.example", 2222).hostname(), "router.example");
        assert_eq!(
            ("router.example".to_string(), 2222).hostname(),
            "router.example"
        );
        let ipv4 = Ipv4Addr::LOCALHOST;
        let ipv6 = Ipv6Addr::LOCALHOST;
        assert_eq!((ipv4, 2222).hostname(), "127.0.0.1");
        assert_eq!((ipv6, 2222).hostname(), "::1");
        assert_eq!((IpAddr::V6(ipv6), 2222).hostname(), "::1");
        assert_eq!(SocketAddr::from((ipv4, 2222)).hostname(), "127.0.0.1");
        assert_eq!(SocketAddr::from((ipv6, 2222)).hostname(), "::1");
    }

    #[test]
    fn numeric_string_endpoints_still_resolve_their_original_ports() {
        for endpoint in ["127.0.0.1:2222", "[::1]:2222"] {
            let addresses = ToSocketAddrsWithHostname::to_socket_addrs(&endpoint).unwrap();
            assert_eq!(addresses.len(), 1);
            assert_eq!(addresses[0].port(), 2222);
        }
    }
}
