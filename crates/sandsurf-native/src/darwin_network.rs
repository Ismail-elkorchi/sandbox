//! Darwin's socket-origin boundary requires an explicitly operator-owned,
//! exclusive stateless PF profile. No API here changes the host firewall.
use sandsurf_protocol::{Digest, bytes_digest};
use std::io;

pub const PF_RULES: &str = include_str!("../../../vmm/qemu/tests/darwin-local-delivery.conf");
const FILTER: [&str; 5] = [
    "@0 block drop out quick on lo0 proto tcp all user = 65530",
    "@1 block drop out quick on lo0 proto udp all user = 65530",
    "@2 pass out quick proto tcp all user = 65530 no state",
    "@3 pass out quick proto udp all user = 65530 no state",
    "@4 pass all no state",
];

pub(crate) fn verify_policy(
    rules: &[u8],
    nat: &[u8],
    anchors: &[u8],
    states: &[u8],
    info: &[u8],
    interfaces: &[u8],
) -> io::Result<Digest> {
    fn text(bytes: &[u8]) -> io::Result<&str> {
        if bytes.len() > 16384 {
            return Err(invalid("PF observation exceeds bound"));
        }
        std::str::from_utf8(bytes).map_err(|_| invalid("PF observation is not UTF-8"))
    }
    if !text(nat)?.trim().is_empty()
        || !text(anchors)?.trim().is_empty()
        || !text(states)?.trim().is_empty()
    {
        return Err(invalid(
            "PF has additional translation, anchors or cached state",
        ));
    }
    let mut observed = Vec::new();
    for line in text(rules)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with('@') {
            observed.push(line);
            continue;
        }
        // pfctl emits bounded counters after each verbose rule. They confer no
        // authority; cached states must remain zero under the stateless profile.
        if line.starts_with("[ Owner : nil") && line.ends_with("Priority : 0     ]") {
            continue;
        }
        if line.starts_with("[ Evaluations:") && line.ends_with("States: 0     ]") {
            continue;
        }
        if line.starts_with("[ Inserted: uid 0 pid ") && line.ends_with(" ]") {
            continue;
        }
        return Err(invalid("PF filter observation has an unknown clause"));
    }
    if observed != FILTER {
        return Err(invalid(
            "PF filter is not the exclusive stateless socket-origin boundary",
        ));
    }
    if !text(info)?
        .lines()
        .any(|line| line.starts_with("Status: Enabled for "))
    {
        return Err(invalid("PF is not enabled"));
    }
    let interfaces = text(interfaces)?;
    if !interfaces.lines().any(|line| line == "lo0") || interfaces.contains("skip") {
        return Err(invalid("PF local interface is absent or bypassed"));
    }
    Ok(bytes_digest(PF_RULES.as_bytes()))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(target_os = "macos")]
mod native {
    use std::io;
    // SAFETY: SDK-compiled shim uses fixed roles, original sockets and exact
    // initialized audit-token envelopes. No request selects paths or PIDs.
    unsafe extern "C" {
        pub(super) fn sandsurf_darwin_network_socket(family: i32, kind: i32, protocol: i32) -> i32;
        pub(super) fn sandsurf_darwin_peer_identity(socket: i32, identity: *mut u32) -> i32;
        pub(super) fn sandsurf_darwin_peer_alive(identity: *const u32) -> i32;
        pub(super) fn sandsurf_darwin_running_executable() -> i32;
    }
    pub(super) fn result(value: i32) -> io::Result<i32> {
        if value < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(value)
        }
    }
}
#[cfg(target_os = "macos")]
pub(crate) fn socket(ipv6: bool, udp: bool) -> io::Result<socket2::Socket> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: fixed role scalars; success returns one newly owned socket FD.
    let descriptor = native::result(unsafe {
        native::sandsurf_darwin_network_socket(
            if ipv6 { libc::AF_INET6 } else { libc::AF_INET },
            if udp {
                libc::SOCK_DGRAM
            } else {
                libc::SOCK_STREAM
            },
            if udp {
                libc::IPPROTO_UDP
            } else {
                libc::IPPROTO_TCP
            },
        )
    })?;
    // SAFETY: sole ownership of the successful native allocation.
    let original = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: set CLOEXEC before publishing this descriptor to any other thread.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket2::Socket::from(original))
}
#[cfg(target_os = "macos")]
pub(crate) fn peer(socket: &std::os::unix::net::UnixStream) -> io::Result<[u32; 8]> {
    use std::os::fd::AsRawFd;
    let mut identity = [0; 8];
    // SAFETY: retained original stream and exact initialized SDK envelope.
    native::result(unsafe {
        native::sandsurf_darwin_peer_identity(socket.as_raw_fd(), identity.as_mut_ptr())
    })?;
    alive(&identity)?;
    Ok(identity)
}
#[cfg(target_os = "macos")]
pub(crate) fn alive(identity: &[u32; 8]) -> io::Result<()> {
    // SAFETY: the retained original token came from the kernel, not a request.
    native::result(unsafe { native::sandsurf_darwin_peer_alive(identity.as_ptr()) })?;
    Ok(())
}
#[cfg(target_os = "macos")]
pub(crate) fn executable() -> io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: success returns an original read-only file matched to its mapped
    // native vnode; no installation pathname is accepted from another owner.
    let descriptor = native::result(unsafe { native::sandsurf_darwin_running_executable() })?;
    // SAFETY: the native function transferred this sole owned reference.
    Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rules() -> Vec<u8> {
        FILTER.join("\n").into_bytes()
    }
    #[test]
    fn exclusive_policy_rejects_state_anchors_nat_skip_disabled_and_extra_rules() {
        let rules = rules();
        let info = b"Status: Enabled for 0 days 00:00:01 Debug: Urgent\n";
        let interfaces = b"ALL\nen0\nlo0\n";
        assert_eq!(
            verify_policy(&rules, b"", b"", b"", info, interfaces).unwrap(),
            bytes_digest(PF_RULES.as_bytes())
        );
        for slot in 0..3 {
            let mut extras: [&[u8]; 3] = [b"", b"", b""];
            extras[slot] = b"additional authority";
            assert!(
                verify_policy(&rules, extras[0], extras[1], extras[2], info, interfaces).is_err()
            );
        }
        assert!(verify_policy(&rules, b"", b"", b"", b"Status: Disabled", interfaces).is_err());
        assert!(verify_policy(&rules, b"", b"", b"", info, b"ALL\nlo0\n  skip\n").is_err());
        assert!(verify_policy(&rules, b"", b"", b"", info, b"ALL\nen0\n").is_err());
        let changed = String::from_utf8(rules.clone())
            .unwrap()
            .replace("no state", "keep state");
        assert!(verify_policy(changed.as_bytes(), b"", b"", b"", info, interfaces).is_err());
        let mut extra = rules.clone();
        extra.extend_from_slice(b"\n@5 pass all keep state");
        assert!(verify_policy(&extra, b"", b"", b"", info, interfaces).is_err());
        let mut state = rules;
        state.extend_from_slice(b"\n[ Evaluations: 0 States: 1     ]");
        assert!(verify_policy(&state, b"", b"", b"", info, interfaces).is_err());
        assert!(PF_RULES.contains("user 65530"));
    }
}
