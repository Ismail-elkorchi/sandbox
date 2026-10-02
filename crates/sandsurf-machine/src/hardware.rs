//! Native device-model limits. Host assessment and actual launch validate the
//! same geometry; guest reports never enlarge the supported host envelope.
use sandsurf_protocol::VmEngine;
use std::io;

pub fn validate_hardware(engine: &VmEngine, vcpus: u64, memory_mib: u64) -> io::Result<()> {
    let minimum = match engine {
        VmEngine::Firecracker => 128,
        VmEngine::QemuHvf | VmEngine::QemuWhpx => 256,
    };
    if !(1..=32).contains(&vcpus) || !(minimum..=65_536).contains(&memory_mib) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{engine:?} requires 1–32 vCPUs and {minimum}–65536 MiB guest RAM"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_geometry_is_engine_specific_and_bounded() {
        for engine in [VmEngine::Firecracker, VmEngine::QemuHvf, VmEngine::QemuWhpx] {
            let minimum = if engine == VmEngine::Firecracker {
                128
            } else {
                256
            };
            for vcpus in [1, 2, 32] {
                for memory in [minimum, 512, 65_536] {
                    validate_hardware(&engine, vcpus, memory).unwrap();
                }
            }
            for vcpus in [0, 33, u64::MAX] {
                assert!(validate_hardware(&engine, vcpus, 512).is_err());
            }
            for memory in [0, minimum - 1, 65_537, u64::MAX] {
                assert!(validate_hardware(&engine, 1, memory).is_err());
            }
        }
    }
}
