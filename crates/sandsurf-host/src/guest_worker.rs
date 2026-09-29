//! Guest-owned reports and byte transport, with no native handles or journal writer.

use crate::guardian::{EffectOutcome, GuestDriver, Result};
use sandsurf_protocol::{
    ExecutionId, ExecutionSnapshot, GuestCommand, GuestServiceRequest, GuestServiceResponse,
    OutputBoundary, RetainedPage,
};
use std::collections::BTreeMap;

pub struct ExecutionHint {
    pub generation: sandsurf_protocol::Counter,
    pub boundary: OutputBoundary,
    pub settled: bool,
}

pub type ExecutionHints = BTreeMap<ExecutionId, ExecutionHint>;

pub struct GuestProgress {
    pub snapshot: ExecutionSnapshot,
    pub output: Option<RetainedPage>,
}

#[derive(Default)]
pub struct GuestPoll {
    pub identity: Option<sandsurf_protocol::GuestManagementIdentity>,
    pub executions: Vec<GuestProgress>,
}

pub(crate) enum GuestJob {
    Dispatch(GuestCommand),
    Query(GuestServiceRequest),
    Poll(ExecutionHints),
}

pub(crate) enum GuestJobResult {
    Dispatch(EffectOutcome),
    Query(Result<GuestServiceResponse>),
    Progress(Result<GuestPoll>),
}

pub(crate) fn execute(driver: &mut dyn GuestDriver, job: GuestJob) -> GuestJobResult {
    match job {
        GuestJob::Dispatch(command) => GuestJobResult::Dispatch(driver.dispatch(&command)),
        GuestJob::Query(request) => GuestJobResult::Query(driver.query(request)),
        GuestJob::Poll(hints) => GuestJobResult::Progress(driver.poll(&hints)),
    }
}
