use crate::{ProcessError, ProcessState, ProcessSupervisor};
use sandsurf_control::{EffectOutcome, WorkloadDriver};
use sandsurf_protocol::{
    Capability, Digest, Domain, Mutation, WorkloadRequest, bytes_digest, digest,
};
use std::time::Duration;

/// Guardian dispatch adapter for the protected Linux workload supervisor.
/// It consumes the exact request signed by the host; it neither keeps grants
/// nor infers authority from a process identity.
pub struct WorkloadService {
    processes: ProcessSupervisor,
}

impl WorkloadService {
    pub fn new(processes: ProcessSupervisor) -> Self {
        Self { processes }
    }

    pub fn processes(&self) -> &ProcessSupervisor {
        &self.processes
    }
}

impl WorkloadDriver for WorkloadService {
    fn dispatch(&mut self, mutation: &Mutation, capability: Capability) -> EffectOutcome {
        if mutation.validate().is_err() || mutation.required_capability() != capability {
            return EffectOutcome::NotApplied(bytes_digest(b"invalid-workload-authority"));
        }
        let result = match &mutation.request {
            WorkloadRequest::Spawn { request } => {
                self.processes.spawn((**request).clone()).map(drop)
            }
            WorkloadRequest::WriteInput {
                process_id,
                terminal_lease_id,
                bytes,
            } => self
                .processes
                .write_input(process_id, terminal_lease_id.as_ref(), bytes),
            WorkloadRequest::CloseInput {
                process_id,
                terminal_lease_id,
            } => self
                .processes
                .close_input(process_id, terminal_lease_id.as_ref()),
            WorkloadRequest::AcquireTerminalInput {
                process_id,
                terminal_lease_id,
            } => self
                .processes
                .acquire_terminal_input(process_id, terminal_lease_id),
            WorkloadRequest::ReleaseTerminalInput {
                process_id,
                terminal_lease_id,
            } => self
                .processes
                .release_terminal_input(process_id, terminal_lease_id),
            WorkloadRequest::ResizeTerminal { process_id, size } => {
                self.processes.resize_terminal(process_id, *size)
            }
            WorkloadRequest::Signal {
                process_id,
                signal,
                group,
            } => self
                .processes
                .signal(process_id, i32::from(*signal), *group),
            WorkloadRequest::Terminate {
                process_id,
                grace_millis,
            } => self
                .processes
                .terminate(process_id, Duration::from_millis(u64::from(*grace_millis))),
            WorkloadRequest::Filesystem { .. } => {
                return EffectOutcome::NotApplied(effect_digest(
                    mutation,
                    b"in-process-filesystem-driver-retired",
                ));
            }
        };
        match result {
            Ok(()) => EffectOutcome::Applied(effect_digest(mutation, b"workload-effect-applied")),
            Err(
                ProcessError::Invalid(_)
                | ProcessError::Conflict(_)
                | ProcessError::Missing
                | ProcessError::Timeout,
            ) => EffectOutcome::NotApplied(effect_digest(mutation, b"workload-effect-rejected")),
            Err(ProcessError::Io(_) | ProcessError::Spool(_) | ProcessError::Unknown(_)) => {
                EffectOutcome::Unknown
            }
        }
    }

    fn reconcile(
        &mut self,
        journal: &mut sandsurf_state::RuntimeJournal,
    ) -> sandsurf_state::Result<()> {
        let snapshots = self
            .processes
            .list()
            .map_err(|_| sandsurf_state::Error::Corrupt("guest process inventory unavailable"))?;
        for snapshot in snapshots {
            let process_id = &snapshot.request.process_id;
            journal.observe_process(&snapshot)?;
            let mut committed = journal.process_boundary(process_id)?;
            loop {
                let page = self
                    .processes
                    .read_output(
                        process_id,
                        committed.final_cursor,
                        sandsurf_protocol::MAX_STREAM_BYTES,
                    )
                    .map_err(|_| {
                        sandsurf_state::Error::Corrupt("guest output replay is unavailable")
                    })?;
                if page.required_bytes.is_some() {
                    return Err(sandsurf_state::Error::Corrupt(
                        "guest output chunk exceeds the protocol bound",
                    ));
                }
                if page.chunks.is_empty() {
                    break;
                }
                for chunk in page.chunks {
                    if chunk.cursor != committed.final_cursor {
                        return Err(sandsurf_state::Error::Corrupt(
                            "guest output cursor is not contiguous",
                        ));
                    }
                    committed = journal.append_output(
                        process_id,
                        committed.chunks.next()?,
                        chunk.stream,
                        &chunk.bytes,
                    )?;
                }
                if committed.final_cursor >= page.available {
                    break;
                }
            }
            if let ProcessState::Exited(completion) = snapshot.state {
                let source = &completion.output;
                if committed.final_cursor != source.final_cursor
                    || committed.chunks != source.chunks
                    || committed.stdout_bytes != source.stdout_bytes
                    || committed.stderr_bytes != source.stderr_bytes
                    || committed.terminal_bytes != source.terminal_bytes
                    || source.omitted_bytes != sandsurf_protocol::Counter::ZERO
                {
                    return Err(sandsurf_state::Error::Corrupt(
                        "guardian output does not completely cover guest completion",
                    ));
                }
                if journal.receipt(process_id)?.is_none() {
                    journal.publish_receipt(
                        process_id,
                        completion.outcome,
                        completion.cleanup_digest,
                        completion.accounting_digest,
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn effect_digest(mutation: &Mutation, outcome: &[u8]) -> Digest {
    digest(
        Domain::Operation,
        &(outcome, &mutation.operation_id, &mutation.request_digest),
    )
    .unwrap_or_else(|_| bytes_digest(b"workload-effect-digest-failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandsurf_protocol::*;
    use sandsurf_state::*;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandsurf-guardian-workload-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn n(value: u64) -> Counter {
        value.try_into().unwrap()
    }

    fn resources() -> Resources {
        Resources {
            vcpus: n(2),
            memory_mib: n(1024),
            disk_bytes: n(1024 * 1024),
            output_bytes: n(1024 * 1024),
            processes: n(16),
        }
    }

    #[test]
    fn guest_spool_is_completely_committed_before_receipt_publication() {
        let root = Temp::new();
        let sandbox: SandboxId = "box".try_into().unwrap();
        let create: OperationId = "create".try_into().unwrap();
        let image = bytes_digest(b"image");
        let mut host = HostCatalog::create(
            &root.0.join("host"),
            "host".try_into().unwrap(),
            CatalogLimits {
                identities: n(8),
                operations: n(64),
                grants: n(16),
                usage_records: n(64),
                image_bytes: n(16 * 1024 * 1024),
                resources: Resources {
                    vcpus: n(8),
                    memory_mib: n(8192),
                    disk_bytes: n(16 * 1024 * 1024),
                    output_bytes: n(16 * 1024 * 1024),
                    processes: n(128),
                },
            },
        )
        .unwrap();
        let workload = WorkloadConfiguration::default();
        let creation = digest(
            Domain::Sandbox,
            &(
                &sandbox,
                &image,
                resources(),
                &workload,
                &SandboxLifetime::default(),
                &create,
            ),
        )
        .unwrap();
        host.create_sandbox(
            SandboxAdmission {
                id: sandbox.clone(),
                image,
                resources: resources(),
                workload,
                lifetime: SandboxLifetime::default(),
                operation: create.clone(),
            },
            Approval {
                id: "approve-create".try_into().unwrap(),
                request_digest: creation,
            },
        )
        .unwrap();
        let mut journal = RuntimeJournal::create(
            &root.0.join("runtime"),
            sandbox.clone(),
            RuntimeLimits {
                identities: n(32),
                operations: n(64),
                observations: n(64),
                events: n(2048),
                chunks: n(1024),
                pins: n(32),
                output_bytes: n(1024 * 1024),
                disks: n(8),
                disk_bytes: n(4 * 1024 * 1024),
                disk_headroom_bytes: n(1024 * 1024),
            },
            host.authority_binding().clone(),
        )
        .unwrap();
        journal
            .observe(MachineObservation {
                sandbox_id: sandbox.clone(),
                epoch: Counter::ONE,
                sequence: Counter::ONE,
                state: MachineState::Creating,
                applied_revision: Counter::ONE,
                operation_id: create.clone(),
                evidence_digest: bytes_digest(b"created"),
            })
            .unwrap();
        let running = journal
            .observe(MachineObservation {
                sandbox_id: sandbox.clone(),
                epoch: Counter::ONE,
                sequence: n(2),
                state: MachineState::Running,
                applied_revision: Counter::ONE,
                operation_id: create,
                evidence_digest: bytes_digest(b"running"),
            })
            .unwrap();
        host.complete_intent(&running).unwrap();
        let grant: GrantId = "spawn".try_into().unwrap();
        let grant_operation: OperationId = "grant-spawn".try_into().unwrap();
        let scope = bytes_digest(b"workload");
        let grant_digest = digest(
            Domain::Grant,
            &(
                "sandsurf-grant-change-v1",
                &sandbox,
                &grant_operation,
                &grant,
                Counter::ONE,
                Capability::Spawn,
                &scope,
                false,
            ),
        )
        .unwrap();
        host.set_grant(
            GrantChange {
                sandbox_id: sandbox.clone(),
                operation_id: grant_operation,
                id: grant.clone(),
                expected_revision: Counter::ONE,
                capability: Capability::Spawn,
                scope_digest: scope.clone(),
                revoked: false,
            },
            Approval {
                id: "approve-spawn".try_into().unwrap(),
                request_digest: grant_digest,
            },
        )
        .unwrap();
        journal
            .observe(MachineObservation {
                sandbox_id: sandbox.clone(),
                epoch: Counter::ONE,
                sequence: n(3),
                state: MachineState::Running,
                applied_revision: n(2),
                operation_id: "grant-installed".try_into().unwrap(),
                evidence_digest: bytes_digest(b"revision-2"),
            })
            .unwrap();
        let process_id: ProcessId = "process".try_into().unwrap();
        let operation_id: OperationId = "spawn-process".try_into().unwrap();
        let spawn = SpawnRequest {
            sandbox_id: sandbox.clone(),
            epoch: Counter::ONE,
            process_id: process_id.clone(),
            operation_id: operation_id.clone(),
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf 'hello\\000world'".into(),
            ],
            cwd: "/".into(),
            environment: Default::default(),
            user: None,
            stdio: StdioMode::Pipes,
            terminal_size: None,
            lifetime: ProcessLifetime::Job,
            active_deadline_millis: None,
            elapsed_deadline_unix_millis: None,
            output_bytes: n(1024),
        };
        let mutation = Mutation::new(
            sandbox.clone(),
            Counter::ONE,
            operation_id.clone(),
            grant,
            n(2),
            WorkloadRequest::Spawn {
                request: Box::new(spawn),
            },
        )
        .unwrap();
        let authorization = host
            .authorize(mutation.clone(), Capability::Spawn, &scope)
            .unwrap();
        journal.admit(authorization.clone()).unwrap();
        journal
            .admit_process(process_id.clone(), &operation_id, n(1024), false)
            .unwrap();
        let processes =
            ProcessSupervisor::create(&root.0.join("guest-spool"), sandbox, Counter::ONE).unwrap();
        let mut service = WorkloadService::new(processes);
        match journal.begin_dispatch(authorization).unwrap() {
            DispatchDecision::Perform(permit) => {
                assert!(matches!(
                    permit.perform(|request, capability| service.dispatch(request, *capability)),
                    EffectOutcome::Applied(_)
                ));
            }
            DispatchDecision::Reconcile(_) => panic!("first dispatch unexpectedly reconciled"),
        }
        service
            .processes()
            .wait(&process_id, Some(Duration::from_secs(5)))
            .unwrap();
        service.reconcile(&mut journal).unwrap();
        let (receipt, _) = journal.receipt(&process_id).unwrap().unwrap();
        let observed = journal.process_snapshot(&process_id).unwrap().unwrap();
        assert!(matches!(observed.state, ProcessState::Exited(_)));
        assert_eq!(receipt.output.final_cursor.get(), 11);
        let page = journal
            .read_output(&process_id, Counter::ZERO, 1024)
            .unwrap();
        assert_eq!(page.chunks[0].bytes, b"hello\0world");
        // Reconciliation is idempotent and the protected guest spool remains
        // readable after guardian publication.
        service.reconcile(&mut journal).unwrap();
        assert_eq!(
            service
                .processes()
                .read_output(&process_id, Counter::ZERO, 1024)
                .unwrap()
                .chunks[0]
                .bytes,
            b"hello\0world"
        );
    }
}
