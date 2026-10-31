//! Address resolution and dial ordering, modelled on Go's `net` package.
//!
//! frp-rs has to reproduce two different Go behaviours on the same dial path,
//! because they answer different questions:
//!
//! * **`net.Dial`** resolves *every* address and tries them in sequence
//!   (`net/dial.go`: `Dialer.dial` partitions by family at `:552-560`, and
//!   `dialParallel`/`dialSerial` at `:659-745` walk each group in order, with
//!   `dialSerial` returning "the error from the first address" as most
//!   relevant). So a name whose first address has no listener still connects
//!   on a later one — [`dial_order`].
//! * **`net.ResolveTCPAddr` / `net.ResolveUDPAddr`** return exactly *one*
//!   address, chosen by `addrList.forResolve` (`net/ipsock.go:79-95`): "IPv4 is
//!   preferred, unless addr contains an IPv6 literal", and `first` falls back
//!   to the list's first entry when no address has the preferred family
//!   (`net/ipsock.go:100-107`) — [`pick_for_resolve`].
//!
//! The split matters because UDP transports cannot report a dead address: a
//! datagram sent to an unreachable peer is silently dropped, so a KCP or QUIC
//! dial has no error to fall back on and must pick Go's address up front. The
//! stream transports (TCP, TLS, WS/WSS) can fail immediately and therefore try
//! the whole list.

use std::net::SocketAddr;

/// Resolve `addr` (`host:port`, or a literal socket address) to every address,
/// in resolver order, without duplicates.
///
/// `ErrorKind::NotFound` means the resolver returned no records; any other kind
/// is the resolver's own failure.
pub(crate) async fn resolve_peers(addr: &str) -> std::io::Result<Vec<SocketAddr>> {
    if let Ok(peer) = addr.parse::<SocketAddr>() {
        return Ok(vec![peer]);
    }
    let mut peers: Vec<SocketAddr> = Vec::new();
    for peer in tokio::net::lookup_host(addr).await? {
        if !peers.contains(&peer) {
            peers.push(peer);
        }
    }
    if peers.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no records found",
        ));
    }
    Ok(peers)
}

/// Go's `net.Dial` order: the group matching the family of the list's *first*
/// entry first (`addrList.partition`, `net/ipsock.go:115-127`), then the other
/// group, each in resolver order.
///
/// frp-rs walks the two groups sequentially instead of racing them, so a
/// blackholed first group costs its whole dial timeout before the fallback
/// starts, where Go starts the fallback after `fallbackDelay` (300 ms) or on
/// the primary group's first error (`net/dial.go:698`, `:725-732`). The set of
/// addresses tried, and the order within each group, are identical.
///
/// # Panics
///
/// Panics in debug builds if `peers` is empty; every caller resolves first, and
/// [`resolve_peers`] never returns an empty list.
pub(crate) fn dial_order(peers: &[SocketAddr]) -> Vec<SocketAddr> {
    debug_assert!(!peers.is_empty(), "dial_order needs a resolved address");
    let primary_is_v4 = peers[0].is_ipv4();
    let mut ordered = Vec::with_capacity(peers.len());
    ordered.extend(
        peers
            .iter()
            .filter(|p| p.is_ipv4() == primary_is_v4)
            .copied(),
    );
    ordered.extend(
        peers
            .iter()
            .filter(|p| p.is_ipv4() != primary_is_v4)
            .copied(),
    );
    ordered
}

/// Go's `addrList.forResolve` (`net/ipsock.go:79-107`): the single address a
/// `ResolveTCPAddr`/`ResolveUDPAddr` call returns.
///
/// IPv4 is preferred; if the dialled string carries a bracketed IPv6 literal
/// (`bracketed_literal` — Go tests `strings.Count(addr, "[") > 0`) the first
/// non-IPv4 address is preferred instead; and when no address has the
/// preferred family the list's first entry is returned.
///
/// # Panics
///
/// Panics in debug builds if `peers` is empty; see [`dial_order`].
pub(crate) fn pick_for_resolve(peers: &[SocketAddr], bracketed_literal: bool) -> SocketAddr {
    debug_assert!(
        !peers.is_empty(),
        "pick_for_resolve needs a resolved address"
    );
    let wants = |peer: &SocketAddr| {
        if bracketed_literal {
            !peer.is_ipv4()
        } else {
            peer.is_ipv4()
        }
    };
    peers
        .iter()
        .find(|peer| wants(peer))
        .copied()
        .unwrap_or(peers[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))
    }

    /// `localhost` on macOS resolves to `[::1]` first — the shape that made the
    /// old `.next()` reach a dead address. `net.Dial` still tries the IPv4
    /// entry afterwards (`net/dial.go:552-560`), and that is what `dial_order`
    /// must reproduce: the first entry's family leads, the other follows.
    #[test]
    fn dial_order_tries_the_second_family_after_the_first() {
        assert_eq!(dial_order(&[v6(1), v4(1)]), vec![v6(1), v4(1)]);
        assert_eq!(dial_order(&[v4(1), v6(1)]), vec![v4(1), v6(1)]);
    }

    #[test]
    fn dial_order_keeps_resolver_order_inside_a_family_group() {
        assert_eq!(
            dial_order(&[v4(1), v6(1), v4(2), v6(2)]),
            vec![v4(1), v4(2), v6(1), v6(2)]
        );
        assert_eq!(
            dial_order(&[v6(1), v4(1), v6(2), v4(2)]),
            vec![v6(1), v6(2), v4(1), v4(2)]
        );
    }

    #[test]
    fn dial_order_is_a_permutation_of_its_input() {
        let peers = [v4(1), v6(1), v4(2)];
        let ordered = dial_order(&peers);
        assert_eq!(ordered.len(), peers.len());
        for peer in &peers {
            assert!(ordered.contains(peer));
        }
    }

    /// Go's measured behaviour for `localhost`: `LookupIP` answers `[::1]
    /// 127.0.0.1` but `ResolveUDPAddr`/`ResolveTCPAddr` answer `127.0.0.1`
    /// (`go1.27.3`, this host) — the IPv4 preference of `forResolve`.
    #[test]
    fn pick_for_resolve_prefers_ipv4_over_an_ipv6_first_resolver_entry() {
        assert_eq!(pick_for_resolve(&[v6(1), v4(1)], false), v4(1));
        assert_eq!(pick_for_resolve(&[v4(1), v6(1)], false), v4(1));
    }

    #[test]
    fn pick_for_resolve_keeps_the_ipv6_entry_of_a_bracketed_literal() {
        assert_eq!(pick_for_resolve(&[v6(1), v4(1)], true), v6(1));
        assert_eq!(pick_for_resolve(&[v4(1), v6(1)], true), v6(1));
    }

    /// `addrList.first` returns `addrs[0]` when no address matches the
    /// preference (`net/ipsock.go:100-107`), so an IPv6-only name is still
    /// dialable without brackets, and vice versa.
    #[test]
    fn pick_for_resolve_falls_back_to_the_first_entry() {
        assert_eq!(pick_for_resolve(&[v6(1)], false), v6(1));
        assert_eq!(pick_for_resolve(&[v4(1)], true), v4(1));
    }

    #[tokio::test]
    async fn resolve_peers_returns_a_literal_unchanged() {
        assert_eq!(resolve_peers("[::1]:7000").await.unwrap(), vec![v6(7000)]);
        assert_eq!(
            resolve_peers("127.0.0.1:7000").await.unwrap(),
            vec![v4(7000)]
        );
    }

    #[tokio::test]
    async fn resolve_peers_surfaces_a_resolver_failure() {
        // `.invalid` is reserved (RFC 2606) and never resolves.
        assert!(resolve_peers("frp-rs.invalid:7000").await.is_err());
    }
}
