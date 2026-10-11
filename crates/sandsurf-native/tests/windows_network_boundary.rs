//! Actual production socket admission, independent of WHPX availability.
#![cfg(windows)]
#[path = "support/network_boundary.rs"]
mod boundary;

#[test]
#[ignore = "requires running native firewall services and public Internet access"]
fn original_sockets_deny_local_delivery_and_allow_public_tcp() {
    boundary::original_sockets_deny_local_delivery_and_allow_public_tcp();
}
