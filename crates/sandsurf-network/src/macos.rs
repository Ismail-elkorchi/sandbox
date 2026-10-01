//! A datagram packet attachment; shared NAT is deliberately never selected.
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;

pub fn packet_pair() -> io::Result<(UnixDatagram, UnixDatagram)> {
    let pair = UnixDatagram::pair()?;
    for socket in [&pair.0, &pair.1] {
        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            let size = 256 * 1024_i32;
            // SAFETY: live socket and pointer to an initialized c_int.
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&size as *const i32).cast(),
                    std::mem::size_of_val(&size) as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(pair)
}
