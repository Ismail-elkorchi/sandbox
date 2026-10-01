//! Resource change semantics shared by native adapters. Guest cgroups and
//! guest filesystem free-space reports never influence host admission.
use sandsurf_protocol::{
    MachineObservation, ResourceChangeAssessment, ResourceChangeMode, Resources,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceCapabilities {
    pub native_topology: sandsurf_protocol::Capability,
    pub cpu_time: sandsurf_protocol::Capability,
    pub aggregate_host_memory: sandsurf_protocol::Capability,
    pub managed_admission: sandsurf_protocol::Capability,
    pub output_retention: sandsurf_protocol::Capability,
    pub storage_reservations: sandsurf_protocol::Capability,
    pub network_envelope: sandsurf_protocol::Capability,
    pub aggregate_physical_storage: sandsurf_protocol::Capability,
    pub shared_host_workers: sandsurf_protocol::Capability,
    pub complete_enforcement: sandsurf_protocol::Capability,
}

pub fn capabilities(root: &std::path::Path) -> ResourceCapabilities {
    use sandsurf_protocol::{Capability, Qualification};
    let implemented = || {
        Capability::Supported { qualification: Qualification::Unqualified {
        reasons: vec!["hardware qualification is scoped to the exact configurations in qualificationRecords".into()],
    } }
    };
    let unsupported = |reason: &str| Capability::Unsupported {
        reasons: vec![reason.into()],
    };
    let linux = |reason: &str| {
        if cfg!(target_os = "linux") {
            implemented()
        } else {
            unsupported(reason)
        }
    };
    ResourceCapabilities {
        native_topology: implemented(),
        cpu_time: linux("no external CPU scheduling implementation for this adapter"),
        aggregate_host_memory: linux(
            "no aggregate guardian/VMM/worker memory implementation for this adapter",
        ),
        managed_admission: implemented(),
        output_retention: implemented(),
        storage_reservations: implemented(),
        network_envelope: linux(
            "native network resource enforcement is unavailable for this adapter",
        ),
        aggregate_physical_storage: match sandsurf_native::volume::inspect(root) {
            Ok(_) => implemented(),
            Err(error) => unsupported(&error.to_string()),
        },
        shared_host_workers: linux(
            "no external API/artifact and image-worker process pools for this adapter",
        ),
        complete_enforcement: if cfg!(target_os = "linux")
            && sandsurf_native::volume::inspect(root).is_ok()
        {
            implemented()
        } else {
            unsupported(
                "complete enforcement requires operator-provisioned bounded host and machine volumes and Linux native resource mechanisms",
            )
        },
    }
}

pub fn require_machine_storage(
    root: &std::path::Path,
    id: &sandsurf_protocol::MachineId,
    resources: &Resources,
) -> std::io::Result<()> {
    let shared = sandsurf_native::volume::inspect(root)?;
    let machine = sandsurf_native::volume::require(
        &root
            .join("machines")
            .join(sandsurf_native::storage::object_name(id.as_str())),
        resources.physical_storage_bytes.get(),
    )?;
    if machine.device == shared.device {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "machine and shared host storage must have independent physical boundaries",
        ));
    }
    Ok(())
}

pub fn require_external_support(adapter: &str) -> std::io::Result<()> {
    if adapter == "linux" {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "complete external CPU and host-overhead enforcement is unavailable for this adapter; refusing an unenforced resource envelope",
        ))
    }
}

/// The native gateway currently has fixed, stricter bounds. Requested envelopes
/// may cover these bounds; reducing below them is explicitly unsupported until
/// that gateway can install a smaller limit. This never implies guest shaping.
pub fn require_network_capacity(resources: &Resources) -> std::io::Result<()> {
    if resources.network_connections.get() < sandsurf_network::MAX_FLOWS as u64
        || resources.network_bytes_per_second.get() < 8 * 1024 * 1024
        || resources.network_queue_bytes.get() < 16 * 1024 * 1024
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native gateway requires capacity for 128 flows, an 8MiB/s aggregate NIC rate, and 16MiB of packet/TCP windows; smaller limits are unsupported",
        ));
    }
    Ok(())
}

pub fn assess(
    requested: &Resources,
    applied: &Resources,
    _current: &MachineObservation,
) -> ResourceChangeAssessment {
    let result = |mode, reason: &str| ResourceChangeAssessment {
        mode,
        reasons: if reason.is_empty() {
            Vec::new()
        } else {
            vec![reason.into()]
        },
    };
    if let Err(error) = requested.validate() {
        return result(ResourceChangeMode::Unsupported, &error.to_string());
    }
    if let Err(error) = require_network_capacity(requested) {
        return result(ResourceChangeMode::Unsupported, &error.to_string());
    }
    if !cfg!(target_os = "linux") {
        return result(
            ResourceChangeMode::Unsupported,
            "this adapter has no complete external CPU/host-memory resource mechanism",
        );
    }
    if requested.disk_bytes != applied.disk_bytes {
        return result(
            ResourceChangeMode::Unsupported,
            "virtual disk resizing requires owned storage replacement; Linux filesystem resizing is separate",
        );
    }
    if requested.vcpus.get() > 32
        || requested.memory_mib.get() < 128
        || requested.memory_mib.get() > 65_536
    {
        return result(
            ResourceChangeMode::Unsupported,
            "requested hardware topology exceeds the native Firecracker envelope",
        );
    }
    if requested.vcpus != applied.vcpus || requested.memory_mib != applied.memory_mib {
        return result(
            ResourceChangeMode::RequiresReboot,
            "vCPU topology and guest RAM change at the next powered-off boot",
        );
    }
    result(ResourceChangeMode::Live, "")
}
