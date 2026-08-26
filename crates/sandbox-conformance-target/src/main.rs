#![deny(unsafe_op_in_unsafe_fn)]

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

fn main() {
    let result = match env::args().nth(1).as_deref() {
        Some("vm-files") => vm_files(),
        Some("control-plane") => control_plane(),
        Some("proxy-get") => proxy_get(),
        Some("direct-denied") => direct_denied(),
        Some("path-absent") => path_absent(),
        Some("daemon-sentinel") => daemon_sentinel(),
        Some("sentinel-absent") => sentinel_absent(),
        Some("echo") => echo(),
        Some("stdin") => stdin_echo(),
        Some("interactive") => interactive(),
        _ => Err("unknown conformance command".into()),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn vm_files() -> Result<(), String> {
    if fs::read_to_string("input").map_err(display)? != "old" {
        return Err("imported input content mismatch".into());
    }
    fs::rename("input", "renamed").map_err(display)?;
    fs::write("output", b"artifact").map_err(display)?;
    fs::create_dir("created").map_err(display)?;
    fs::write("created/nested", b"nested").map_err(display)?;
    control_plane()?;
    if env::args().nth(2).is_some() {
        path_absent()?;
    }
    Ok(())
}

fn control_plane() -> Result<(), String> {
    if Path::new("/dev/vsock").exists() {
        return Err("target can see /dev/vsock".into());
    }
    // SAFETY: socket has scalar arguments and returns a descriptor or -1.
    let descriptor = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if descriptor >= 0 {
        unsafe { libc::close(descriptor) };
        return Err("target can create AF_VSOCK sockets".into());
    }
    let devices = fs::read_to_string("/proc/net/dev").map_err(display)?;
    if devices.lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(name, _)| name.trim() != "lo")
    }) {
        return Err("target has a non-loopback network interface".into());
    }
    Ok(())
}

fn proxy_get() -> Result<(), String> {
    let url = env::args().nth(2).ok_or("proxy-get needs a URL")?;
    let proxy = env::var("HTTP_PROXY").map_err(display)?;
    let address = proxy
        .strip_prefix("http://")
        .ok_or("HTTP_PROXY is not an HTTP URL")?;
    let mut stream = TcpStream::connect(address).map_err(display)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(display)?;
    write!(
        stream,
        "GET {url} HTTP/1.1\r\nHost: conformance\r\nConnection: close\r\n\r\n"
    )
    .map_err(display)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(display)?;
    let response = String::from_utf8(response).map_err(display)?;
    if !response.starts_with("HTTP/1.1 200") || !response.ends_with("vm-network-ok") {
        let preview = response.chars().take(1024).collect::<String>();
        return Err(format!("unexpected proxy response: {preview}"));
    }
    Ok(())
}

fn direct_denied() -> Result<(), String> {
    let address: SocketAddr = env::args()
        .nth(2)
        .ok_or("direct-denied needs an address")?
        .parse()
        .map_err(display)?;
    match TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
        Ok(_) => Err("direct network connection bypassed the broker".into()),
        Err(_) => Ok(()),
    }
}

fn path_absent() -> Result<(), String> {
    let path = env::args().nth(2).ok_or("path-absent needs a path")?;
    if fs::symlink_metadata(path).is_ok() {
        Err("host path is visible inside the guest".into())
    } else {
        Ok(())
    }
}

fn daemon_sentinel() -> Result<(), String> {
    // SAFETY: fork creates a private child; the parent returns immediately and guest supervision
    // owns every descendant. No locks or buffered writers are used after the fork.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if child == 0 {
        // SAFETY: setsid has no pointer arguments and creates a detached session for this child.
        if unsafe { libc::setsid() } < 0 {
            // SAFETY: `_exit` terminates only this fresh child without flushing inherited buffers.
            unsafe { libc::_exit(2) };
        }
        // SAFETY: the second fork tests double-fork cleanup under guest tree ownership.
        let grandchild = unsafe { libc::fork() };
        if grandchild == 0 {
            std::thread::sleep(Duration::from_millis(750));
            let _ = fs::write("/workspace/daemon-survived", b"escaped");
        }
        // SAFETY: both branches are descendants created solely for this cleanup test.
        unsafe { libc::_exit(if grandchild < 0 { 3 } else { 0 }) };
    }
    Ok(())
}

fn sentinel_absent() -> Result<(), String> {
    std::thread::sleep(Duration::from_millis(1_000));
    if Path::new("/workspace/daemon-survived").exists() {
        Err("daemonized guest descendant survived process completion".into())
    } else {
        Ok(())
    }
}

fn echo() -> Result<(), String> {
    let value = env::args().skip(2).collect::<Vec<_>>().join("|");
    print!("{value}");
    Ok(())
}

fn stdin_echo() -> Result<(), String> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).map_err(display)?;
    std::io::stdout().write_all(&input).map_err(display)
}

fn interactive() -> Result<(), String> {
    print!("ready");
    std::io::stdout().flush().map_err(display)?;
    let mut byte = [0_u8; 1];
    std::io::stdin().read_exact(&mut byte).map_err(display)?;
    print!("-{}", byte[0]);
    Ok(())
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
