#![deny(unsafe_code)]
#![allow(clippy::result_large_err)]

mod runtime;

fn main() {
    runtime::run();
}
