fn main() {
    println!("cargo:rerun-if-changed=src/darwin_socket.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/darwin_socket.c")
            .flag("-std=c11")
            .flag("-Wall")
            .flag("-Wextra")
            .flag("-Werror")
            .compile("sandsurf-darwin-socket");
    }
}
