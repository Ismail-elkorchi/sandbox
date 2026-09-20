use crate::{ProcessError, ProcessSupervisor};
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
            WorkloadRequest::CloseInput { process_id } => self.processes.close_input(process_id),
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
}

fn effect_digest(mutation: &Mutation, outcome: &[u8]) -> Digest {
    digest(
        Domain::Operation,
        &(outcome, &mutation.operation_id, &mutation.request_digest),
    )
    .unwrap_or_else(|_| bytes_digest(b"workload-effect-digest-failed"))
}
