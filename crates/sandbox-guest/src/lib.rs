#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const GUEST_PROTOCOL_MAJOR: u16 = 1;
pub const GUEST_PROTOCOL_MINOR: u16 = 6;
pub const GUEST_CONTROL_PORT: u32 = 10789;
pub const GUEST_HTTP_PROXY_PORT: u16 = 3128;
pub const GUEST_SOCKS_PROXY_PORT: u16 = 1080;
pub const GUEST_HTTP_TUNNEL_PORT: u32 = 12080;
pub const GUEST_SOCKS_TUNNEL_PORT: u32 = 12081;
pub const GUEST_DNS_TCP_TUNNEL_PORT: u32 = 12082;
pub const GUEST_DNS_UDP_TUNNEL_PORT: u32 = 12083;
pub const MAX_GUEST_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum GuestRequest {
    Authenticate {
        protocol_major: u16,
        protocol_minor: u16,
        nonce_hex: String,
    },
    BeginImport {
        entries: Vec<GuestArtifactEntry>,
        max_bytes: u64,
    },
    ImportChunk {
        path: String,
        offset: u64,
        content_hex: String,
    },
    CompleteImport,
    Inspect {
        executable: String,
        cwd: String,
        mounts: Vec<GuestMount>,
        masks: Vec<GuestMask>,
        system_runtime: bool,
    },
    Run {
        executable: String,
        expected_executable_sha256: String,
        expected_executable_identity_digest: String,
        args: Vec<String>,
        cwd: String,
        expected_cwd_identity_digest: String,
        environment: BTreeMap<String, String>,
        mounts: Vec<GuestMount>,
        masks: Vec<GuestMask>,
        private_home: GuestPrivateDirectory,
        temporary: GuestPrivateDirectory,
        network_mode: String,
        system_runtime: bool,
        limits: GuestLimits,
    },
    WriteStdin {
        content_hex: String,
    },
    CloseStdin,
    PollRun,
    TerminateRun {
        reason: String,
    },
    Export {
        paths: Vec<String>,
        max_bytes: u64,
    },
    ReadArtifact {
        path: String,
        offset: u64,
        max_bytes: u64,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GuestResponse {
    Authenticated {
        protocol_major: u16,
        protocol_minor: u16,
        agent_version: String,
        agent_sha256: String,
    },
    ImportReady {
        entries: usize,
    },
    ImportChunkAccepted {
        path: String,
        bytes: u64,
    },
    Imported {
        entries: usize,
        bytes: u64,
    },
    Inspected {
        executable_sha256: String,
        executable_identity_digest: String,
        cwd_identity_digest: String,
    },
    RunStarted,
    StdinAccepted {
        bytes: u64,
    },
    StdinClosed,
    RunOutput {
        stdout_hex: String,
        stderr_hex: String,
    },
    TerminationStarted,
    RunComplete {
        exit_code: Option<i32>,
        signal: Option<i32>,
        termination_reason: Option<String>,
        runtime_error: Option<String>,
        stdout_hex: String,
        stderr_hex: String,
        stdout_bytes: u64,
        stderr_bytes: u64,
        wall_time_ms: u64,
        cpu_time_ms: Option<u64>,
        peak_memory_bytes: Option<u64>,
        max_concurrent_processes: Option<u64>,
    },
    Exported {
        entries: Vec<GuestArtifactEntry>,
        digest: String,
        bytes: u64,
    },
    ArtifactChunk {
        path: String,
        offset: u64,
        content_hex: String,
        complete: bool,
    },
    ShuttingDown,
    Error {
        code: String,
        message: String,
        target_executed: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestLimits {
    pub wall_time_ms: u64,
    pub cpu_time_ms: Option<u64>,
    pub memory_bytes: u64,
    pub max_processes: u64,
    pub max_open_files: Option<u64>,
    pub max_single_file_bytes: Option<u64>,
    pub max_output_bytes: u64,
    pub termination_grace_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestMask {
    pub target: String,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestPrivateDirectory {
    pub enabled: bool,
    pub size_bytes: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestArtifactEntry {
    pub path: String,
    pub kind: String,
    pub mode: u32,
    pub modified_unix_ms: i64,
    pub content_hex: Option<String>,
    pub link_target: Option<String>,
    pub sha256: Option<String>,
}
