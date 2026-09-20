use crate::{
    Error, Result,
    authority::AuthorityVerifier,
    catalog::capacity,
    database::{Database, private_file, sync_directory, sync_file},
    decode, encode,
};
use rusqlite::{OptionalExtension, params};
use sandsurf_protocol::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE configuration(id INTEGER PRIMARY KEY CHECK(id=1), sandbox TEXT NOT NULL, limits TEXT NOT NULL, authority TEXT NOT NULL) STRICT;
CREATE TABLE observations(sequence INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE operations(id TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE lifecycle_operations(id TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE processes(id TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL REFERENCES operations(id), epoch INTEGER NOT NULL, output_limit INTEGER NOT NULL, terminal_mode INTEGER NOT NULL, boundary TEXT NOT NULL, receipt TEXT, receipt_digest TEXT, acknowledged INTEGER NOT NULL DEFAULT 0, release TEXT, cleanup_pending INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE chunks(process TEXT NOT NULL REFERENCES processes(id), sequence INTEGER NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, stream TEXT NOT NULL, bytes_digest TEXT NOT NULL, chain_digest TEXT NOT NULL, PRIMARY KEY(process,sequence)) STRICT;
CREATE INDEX chunks_by_offset ON chunks(process,offset);
CREATE TABLE pins(id TEXT PRIMARY KEY, process TEXT NOT NULL REFERENCES processes(id), receipt_digest TEXT NOT NULL) STRICT;
CREATE TABLE loss_authorizations(id TEXT PRIMARY KEY, process TEXT NOT NULL REFERENCES processes(id), receipt_digest TEXT NOT NULL, approval_digest TEXT NOT NULL) STRICT;
CREATE TABLE disks(id TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL, request TEXT NOT NULL, request_digest TEXT NOT NULL, phase TEXT NOT NULL, cleanup_digest TEXT) STRICT;
";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeLimits {
    pub identities: Counter,
    pub operations: Counter,
    pub observations: Counter,
    pub chunks: Counter,
    pub pins: Counter,
    pub output_bytes: Counter,
    pub disks: Counter,
    pub disk_bytes: Counter,
    pub disk_headroom_bytes: Counter,
}

/// Created only after a guardian journal commit. Host callers cannot construct/deserialise it.
pub struct CommittedObservation(MachineObservation);
impl CommittedObservation {
    pub fn value(&self) -> &MachineObservation {
        &self.0
    }
    pub fn reference(&self) -> Result<ObservationRef> {
        Ok(ObservationRef {
            sandbox_id: self.0.sandbox_id.clone(),
            epoch: self.0.epoch,
            sequence: self.0.sequence,
            digest: digest(Domain::Operation, &self.0)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputChunk {
    pub sequence: Counter,
    pub offset: Counter,
    pub stream: Stream,
    pub bytes: Vec<u8>,
    pub bytes_digest: Digest,
    pub chain_digest: Digest,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPage {
    pub cursor: Counter,
    pub available: Counter,
    pub chunks: Vec<OutputChunk>,
}

pub struct RuntimeJournal {
    pub(crate) db: Database,
    pub(crate) sandbox: SandboxId,
    pub(crate) limits: RuntimeLimits,
    authority: AuthorityVerifier,
}

/// A successful ledger write is not a reusable native-effect permission.
pub enum DispatchDecision<'guardian> {
    Perform(DispatchPermit<'guardian>),
    Reconcile(Operation),
}

/// One dispatch from a verified host envelope. The envelope is exact-operation,
/// one-way service traffic, not an application-held capability or grant cache.
pub struct DispatchPermit<'guardian> {
    authority: AuthorizedMutation,
    _guardian: &'guardian mut RuntimeJournal,
}

pub enum LifecycleDecision<'guardian> {
    Perform(LifecyclePermit<'guardian>),
    Reconcile(LifecycleOperation),
}

pub struct LifecyclePermit<'guardian> {
    authority: AuthorizedLifecycle,
    _guardian: &'guardian mut RuntimeJournal,
}
impl LifecyclePermit<'_> {
    pub fn perform<T>(self, effect: impl FnOnce(&LifecycleCommand) -> T) -> T {
        effect(&self.authority.statement.command)
    }
}
impl DispatchPermit<'_> {
    pub fn perform<T>(self, effect: impl FnOnce(&Mutation, &Capability) -> T) -> T {
        effect(
            &self.authority.statement.mutation,
            &self.authority.statement.capability,
        )
    }
}

impl RuntimeJournal {
    pub fn create(
        path: &Path,
        sandbox: SandboxId,
        limits: RuntimeLimits,
        binding: AuthorityBinding,
    ) -> Result<Self> {
        if [
            limits.identities,
            limits.operations,
            limits.observations,
            limits.chunks,
            limits.pins,
            limits.output_bytes,
            limits.disks,
            limits.disk_bytes,
        ]
        .contains(&Counter::ZERO)
        {
            return Err(Error::Capacity("runtime limits must be positive"));
        }
        let authority = AuthorityVerifier::new(binding)?;
        let db = Database::create(path, "guardian", SCHEMA)?;
        db.connection.execute(
            "INSERT INTO configuration VALUES (1,?1,?2,?3)",
            params![
                sandbox.as_str(),
                encode(&limits)?,
                encode(authority.binding())?
            ],
        )?;
        Ok(Self {
            db,
            sandbox,
            limits,
            authority,
        })
    }
    pub fn open(path: &Path, sandbox: &SandboxId) -> Result<Self> {
        let db = Database::open(path, "guardian")?;
        let (identity, limits, binding): (String, String, String) = db.connection.query_row(
            "SELECT sandbox,limits,authority FROM configuration WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if identity != sandbox.as_str() {
            return Err(Error::Conflict("guardian sandbox identity mismatch"));
        }
        Ok(Self {
            db,
            sandbox: sandbox.clone(),
            limits: decode(&limits)?,
            authority: AuthorityVerifier::new(decode(&binding)?)?,
        })
    }
    pub fn authority_binding(&self) -> &AuthorityBinding {
        self.authority.binding()
    }
    pub fn sandbox_id(&self) -> &SandboxId {
        &self.sandbox
    }
    pub fn last_observation(&self) -> Result<Option<CommittedObservation>> {
        Ok(observation(&self.db.connection)?.map(CommittedObservation))
    }
    pub fn observation_at(&self, reference: &ObservationRef) -> Result<CommittedObservation> {
        let raw: String = self.db.connection.query_row(
            "SELECT value FROM observations WHERE sequence=?1",
            [reference.sequence.get()],
            |r| r.get(0),
        )?;
        let value: MachineObservation = decode(&raw)?;
        if reference.sandbox_id != self.sandbox
            || reference.epoch != value.epoch
            || reference.digest != digest(Domain::Operation, &value)?
        {
            return Err(Error::Conflict(
                "observation reference does not match guardian history",
            ));
        }
        Ok(CommittedObservation(value))
    }
    pub fn observe(&mut self, value: MachineObservation) -> Result<CommittedObservation> {
        if value.sandbox_id != self.sandbox {
            return Err(Error::Conflict("observation belongs to another sandbox"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = observation(&tx)? {
            if old == value {
                return Ok(CommittedObservation(old));
            }
            if value.sequence != old.sequence.next()?
                || value.epoch < old.epoch
                || value.epoch > old.epoch.next()?
                || value.applied_revision < old.applied_revision
                || old.state == MachineState::Destroyed
            {
                return Err(Error::Conflict(
                    "stale, skipped, or rewound guardian observation",
                ));
            }
            if value.epoch != old.epoch
                && !matches!(
                    value.state,
                    MachineState::Starting | MachineState::Restoring
                )
            {
                return Err(Error::Conflict(
                    "new epoch requires an explicit boot/restore transition",
                ));
            }
            if !valid_transition(&old, &value) {
                return Err(Error::Conflict(
                    "machine observation requires a valid lifecycle/epoch transition",
                ));
            }
        } else if value.sequence != Counter::ONE
            || value.epoch != Counter::ONE
            || value.state != MachineState::Creating
        {
            return Err(Error::Conflict(
                "first observation must establish creation identity",
            ));
        }
        capacity(&tx, "observations", self.limits.observations)?;
        tx.execute(
            "INSERT INTO observations VALUES (?1,?2)",
            params![value.sequence.get(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(CommittedObservation(value))
    }
    pub fn operation(&self, id: &OperationId) -> Result<Option<Operation>> {
        operation(&self.db.connection, id)
    }

    pub fn lifecycle_operation(&self, id: &OperationId) -> Result<Option<LifecycleOperation>> {
        lifecycle_operation(&self.db.connection, id)
    }

    pub fn admit_lifecycle(
        &mut self,
        authorization: AuthorizedLifecycle,
    ) -> Result<LifecycleOperation> {
        self.authority.verify_lifecycle(&authorization)?;
        let command = authorization.statement.command;
        let tx = self.db.connection.transaction()?;
        if let Some(old) = lifecycle_operation(&tx, &command.operation_id)? {
            return if old.command == command {
                Ok(old)
            } else {
                Err(Error::Conflict(
                    "lifecycle operation identity already bound",
                ))
            };
        }
        let workload_operation: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1)",
            [command.operation_id.as_str()],
            |row| row.get(0),
        )?;
        let disk_operation: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM disks WHERE operation=?1)",
            [command.operation_id.as_str()],
            |row| row.get(0),
        )?;
        if workload_operation || disk_operation {
            return Err(Error::Conflict(
                "operation identity already belongs to another guardian operation",
            ));
        }
        require_lifecycle_state(&self.sandbox, observation(&tx)?.as_ref(), &command)?;
        operation_capacity(&tx, self.limits.operations)?;
        let value = LifecycleOperation {
            command,
            delivery: Delivery::Admitted,
            evidence_digest: None,
            observation: None,
        };
        tx.execute(
            "INSERT INTO lifecycle_operations VALUES (?1,?2)",
            params![value.command.operation_id.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn begin_lifecycle<'guardian>(
        &'guardian mut self,
        authorization: AuthorizedLifecycle,
    ) -> Result<LifecycleDecision<'guardian>> {
        self.authority.verify_lifecycle(&authorization)?;
        let command = &authorization.statement.command;
        let tx = self.db.connection.transaction()?;
        let mut value = lifecycle_operation(&tx, &command.operation_id)?
            .ok_or(Error::Missing("lifecycle operation is not admitted"))?;
        if value.command != *command {
            return Err(Error::Conflict("lifecycle authority mismatch"));
        }
        if value.delivery != Delivery::Admitted {
            return Ok(LifecycleDecision::Reconcile(value));
        }
        require_lifecycle_state(&self.sandbox, observation(&tx)?.as_ref(), command)?;
        value.delivery = Delivery::Dispatched;
        tx.execute(
            "UPDATE lifecycle_operations SET value=?2 WHERE id=?1",
            params![command.operation_id.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(LifecycleDecision::Perform(LifecyclePermit {
            authority: authorization,
            _guardian: self,
        }))
    }

    pub fn record_lifecycle_delivery(
        &mut self,
        id: &OperationId,
        request: &Digest,
        delivery: Delivery,
        evidence: Option<Digest>,
        observed: Option<ObservationRef>,
    ) -> Result<LifecycleOperation> {
        if matches!(delivery, Delivery::Admitted | Delivery::Dispatched) {
            return Err(Error::Conflict(
                "lifecycle admission and dispatch require their dedicated gates",
            ));
        }
        let committed = observed
            .as_ref()
            .map(|reference| self.observation_at(reference))
            .transpose()?;
        let tx = self.db.connection.transaction()?;
        let mut value = lifecycle_operation(&tx, id)?
            .ok_or(Error::Missing("lifecycle operation is missing"))?;
        if value.command.request_digest != *request {
            return Err(Error::Conflict("lifecycle request digest mismatch"));
        }
        if value.delivery == delivery
            && value.evidence_digest == evidence
            && value.observation == observed
        {
            return Ok(value);
        }
        let allowed = matches!(
            (value.delivery, delivery),
            (Delivery::Admitted, Delivery::NotApplied)
                | (
                    Delivery::Dispatched,
                    Delivery::Applied | Delivery::NotApplied | Delivery::Unknown
                )
                | (Delivery::Unknown, Delivery::Applied | Delivery::NotApplied)
        );
        if !allowed {
            return Err(Error::Conflict("invalid lifecycle delivery transition"));
        }
        match delivery {
            Delivery::Applied => {
                let observation = committed
                    .as_ref()
                    .ok_or(Error::Conflict("applied lifecycle requires an observation"))?
                    .value();
                if evidence.is_none()
                    || observation.operation_id != value.command.operation_id
                    || observation.sandbox_id != value.command.sandbox_id
                    || observation.applied_revision != value.command.revision
                    || !observation.state.satisfies(value.command.desired)
                {
                    return Err(Error::Conflict(
                        "lifecycle observation does not establish its postcondition",
                    ));
                }
            }
            Delivery::NotApplied => {
                if evidence.is_none() || observed.is_some() {
                    return Err(Error::Conflict(
                        "not-applied lifecycle requires evidence and no observation",
                    ));
                }
            }
            Delivery::Unknown => {
                if evidence.is_some() || observed.is_some() {
                    return Err(Error::Conflict(
                        "unknown lifecycle delivery cannot claim completion evidence",
                    ));
                }
            }
            Delivery::Admitted | Delivery::Dispatched => unreachable!(),
        }
        value.delivery = delivery;
        value.evidence_digest = evidence;
        value.observation = observed;
        tx.execute(
            "UPDATE lifecycle_operations SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn admit(&mut self, authorization: AuthorizedMutation) -> Result<Operation> {
        self.authority.verify_mutation(&authorization)?;
        let statement = authorization.statement;
        let request = statement.mutation;
        request.validate()?;
        if request.required_capability() != statement.capability {
            return Err(Error::Conflict(
                "authorized mutation capability does not match its request",
            ));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = operation(&tx, &request.operation_id)? {
            if old.request == request && old.capability == statement.capability {
                return Ok(old);
            }
            return Err(Error::Conflict("runtime operation identity already bound"));
        }
        let disk_operation: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM disks WHERE operation=?1)",
            [request.operation_id.as_str()],
            |row| row.get(0),
        )?;
        if disk_operation {
            return Err(Error::Conflict(
                "operation identity already belongs to disk provisioning",
            ));
        }
        let observed =
            observation(&tx)?.ok_or(Error::Missing("machine observation unavailable"))?;
        if request.sandbox_id != self.sandbox
            || request.epoch != observed.epoch
            || request.expected_revision != observed.applied_revision
            || observed.state != MachineState::Running
        {
            return Err(Error::Conflict(
                "machine epoch, applied revision or state does not admit work",
            ));
        }
        operation_capacity(&tx, self.limits.operations)?;
        let value = Operation {
            request,
            capability: statement.capability,
            delivery: Delivery::Admitted,
            evidence_digest: None,
        };
        tx.execute(
            "INSERT INTO operations VALUES (?1,?2)",
            params![value.request.operation_id.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Recheck current host authority and guardian state, then durably gate one effect.
    /// A crash after this commit requires reconciliation even if no effect took place.
    pub fn begin_dispatch<'guardian>(
        &'guardian mut self,
        authorization: AuthorizedMutation,
    ) -> Result<DispatchDecision<'guardian>> {
        self.authority.verify_mutation(&authorization)?;
        let tx = self.db.connection.transaction()?;
        let request = &authorization.statement.mutation;
        request.validate()?;
        if request.required_capability() != authorization.statement.capability {
            return Err(Error::Conflict(
                "authorized mutation capability does not match its request",
            ));
        }
        let mut value = operation(&tx, &request.operation_id)?
            .ok_or(Error::Missing("dispatch operation is not admitted"))?;
        if value.request != *request || value.capability != authorization.statement.capability {
            return Err(Error::Conflict("dispatch identity or authority mismatch"));
        }
        if value.delivery != Delivery::Admitted {
            return Ok(DispatchDecision::Reconcile(value));
        }
        let current = observation(&tx)?.ok_or(Error::Missing("machine observation unavailable"))?;
        if request.sandbox_id != self.sandbox
            || request.epoch != current.epoch
            || request.expected_revision != current.applied_revision
            || current.state != MachineState::Running
        {
            return Err(Error::Conflict("machine no longer admits dispatch"));
        }
        value.delivery = Delivery::Dispatched;
        tx.execute(
            "UPDATE operations SET value=?2 WHERE id=?1",
            params![request.operation_id.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(DispatchDecision::Perform(DispatchPermit {
            authority: authorization,
            _guardian: self,
        }))
    }

    /// Record delivery evidence only. Native dispatch requires begin_dispatch.
    pub fn record_delivery(
        &mut self,
        id: &OperationId,
        request: &Digest,
        delivery: Delivery,
        evidence: Option<Digest>,
    ) -> Result<Operation> {
        if delivery == Delivery::Dispatched {
            return Err(Error::Conflict(
                "dispatch requires a fresh single-use permission",
            ));
        }
        let tx = self.db.connection.transaction()?;
        let mut value = operation(&tx, id)?.ok_or(Error::Missing("operation missing"))?;
        if value.request.request_digest != *request {
            return Err(Error::Conflict("operation digest mismatch"));
        }
        if value.delivery == delivery && value.evidence_digest == evidence {
            return Ok(value);
        }
        let allowed = matches!(
            (value.delivery, delivery),
            (Delivery::Admitted, Delivery::NotApplied)
                | (
                    Delivery::Dispatched,
                    Delivery::Applied | Delivery::NotApplied | Delivery::Unknown
                )
                | (Delivery::Unknown, Delivery::Applied | Delivery::NotApplied)
        );
        if !allowed
            || (matches!(delivery, Delivery::Applied | Delivery::NotApplied) && evidence.is_none())
        {
            return Err(Error::Conflict(
                "invalid delivery transition or missing effect evidence",
            ));
        }
        value.delivery = delivery;
        value.evidence_digest = evidence;
        tx.execute(
            "UPDATE operations SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn admit_process(
        &mut self,
        id: ProcessId,
        operation_id: &OperationId,
        output_limit: Counter,
        terminal: bool,
    ) -> Result<()> {
        if output_limit == Counter::ZERO {
            return Err(Error::Capacity("output reservation must be positive"));
        }
        let tx = self.db.connection.transaction()?;
        let op =
            operation(&tx, operation_id)?.ok_or(Error::Missing("process operation missing"))?;
        if op.capability != Capability::Spawn {
            return Err(Error::Conflict("process creation requires spawn authority"));
        }
        let WorkloadRequest::Spawn { request } = &op.request.request else {
            return Err(Error::Conflict(
                "process reservation requires a spawn request",
            ));
        };
        if request.process_id != id
            || request.operation_id != *operation_id
            || request.output_bytes != output_limit
            || (request.stdio == StdioMode::Terminal) != terminal
        {
            return Err(Error::Conflict(
                "process reservation does not match the authorized spawn request",
            ));
        }
        if let Some((old_operation, old_epoch, old_limit, old_terminal)) = tx
            .query_row(
                "SELECT operation,epoch,output_limit,terminal_mode FROM processes WHERE id=?1",
                [id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()?
        {
            return if old_operation == operation_id.as_str()
                && old_epoch == op.request.epoch.get()
                && old_limit == output_limit.get()
                && old_terminal == terminal
            {
                Ok(())
            } else {
                Err(Error::Conflict("process identity already bound"))
            };
        }
        if op.delivery != Delivery::Admitted {
            return Err(Error::Conflict("process must be reserved before dispatch"));
        }
        capacity(&tx, "processes", self.limits.identities)?;
        // Retired data retained by independent pins continues to consume storage.
        let retained: u64 = tx.query_row(
            "SELECT coalesce(sum(output_limit),0) FROM processes",
            [],
            |r| r.get(0),
        )?;
        if Counter::try_from(retained)?.checked_add(output_limit.get())? > self.limits.output_bytes
        {
            return Err(Error::Capacity("output reservations exhausted"));
        }
        let boundary = empty_boundary(&self.sandbox, &id, op.request.epoch)?;
        tx.execute("INSERT INTO processes(id,operation,epoch,output_limit,terminal_mode,boundary) VALUES (?1,?2,?3,?4,?5,?6)", params![id.as_str(), operation_id.as_str(), op.request.epoch.get(), output_limit.get(), terminal, encode(&boundary)?])?;
        tx.commit()?;
        Ok(())
    }

    pub fn process_boundary(&self, id: &ProcessId) -> Result<OutputBoundary> {
        let raw: String = self.db.connection.query_row(
            "SELECT boundary FROM processes WHERE id=?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        decode(&raw)
    }

    pub fn append_output(
        &mut self,
        id: &ProcessId,
        sequence: Counter,
        stream: Stream,
        bytes: &[u8],
    ) -> Result<OutputBoundary> {
        if bytes.is_empty() || bytes.len() > MAX_STREAM_BYTES {
            return Err(Error::Capacity("invalid output chunk size"));
        }
        let path = self.db.root.join(format!("{}.output", id.as_str()));
        let tx = self.db.connection.transaction()?;
        let (raw, limit, terminal, receipt, released): (
            String,
            u64,
            bool,
            Option<String>,
            Option<String>,
        ) = tx.query_row(
            "SELECT boundary,output_limit,terminal_mode,receipt,release FROM processes WHERE id=?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let mut boundary: OutputBoundary = decode(&raw)?;
        if terminal != (stream == Stream::Terminal) {
            return Err(Error::Conflict(
                "PTY and pipe stream identities cannot be mixed",
            ));
        }
        let content = bytes_digest(bytes);
        if let Some((old_stream, old_digest, offset, length)) = tx
            .query_row(
                "SELECT stream,bytes_digest,offset,length FROM chunks WHERE process=?1 AND sequence=?2",
                params![id.as_str(), sequence.get()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?,r.get::<_,u64>(2)?,r.get::<_,usize>(3)?)),
            )
            .optional()?
        {
            if old_stream == encode(&stream)?
                && old_digest == content.as_str()
                && released.is_none()
            {
                if length != bytes.len() || offset.checked_add(length as u64).is_none_or(|end| end > boundary.final_cursor.get()) {
                    return Err(Error::Corrupt("replayed output index is inconsistent"));
                }
                let mut file = private_file(&path,false)?;
                let mut original = vec![0;length];
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut original)?;
                if original != bytes { return Err(Error::Corrupt("cannot acknowledge replay with missing or corrupt retained originals")); }
                return Ok(boundary);
            }
            return Err(Error::Conflict(
                "output sequence conflict or retired evidence",
            ));
        }
        if receipt.is_some() || released.is_some() {
            return Err(Error::Conflict("terminal output is immutable"));
        }
        if sequence != boundary.chunks.next()? {
            return Err(Error::Conflict("output sequence gap"));
        }
        let end = boundary.final_cursor.checked_add(bytes.len() as u64)?;
        if end.get() > limit {
            return Err(Error::Capacity(
                "output reservation full; producer must stop before dropping evidence",
            ));
        }
        capacity(&tx, "chunks", self.limits.chunks)?;
        let chain = digest(
            Domain::Output,
            &(
                &boundary.final_hash,
                sequence,
                boundary.final_cursor,
                stream,
                &content,
                bytes.len(),
            ),
        )?;
        let mut file = match private_file(&path, boundary.final_cursor == Counter::ZERO) {
            Ok(file) => file,
            Err(Error::Io(e))
                if e.kind() == std::io::ErrorKind::AlreadyExists
                    && boundary.final_cursor == Counter::ZERO =>
            {
                private_file(&path, false)?
            }
            Err(e) => return Err(e),
        };
        if file.metadata()?.len() < boundary.final_cursor.get() {
            return Err(Error::Corrupt("committed output is truncated"));
        }
        // Only discard the uncommitted tail. A crash before the SQLite commit never acknowledged it.
        file.set_len(boundary.final_cursor.get())?;
        file.seek(SeekFrom::Start(boundary.final_cursor.get()))?;
        file.write_all(bytes)?;
        sync_file(&file)?;
        sync_directory(&self.db.root)?;
        tx.execute(
            "INSERT INTO chunks VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                id.as_str(),
                sequence.get(),
                boundary.final_cursor.get(),
                bytes.len() as u64,
                encode(&stream)?,
                content.as_str(),
                chain.as_str()
            ],
        )?;
        match stream {
            Stream::Stdout => {
                boundary.stdout_bytes = boundary.stdout_bytes.checked_add(bytes.len() as u64)?
            }
            Stream::Stderr => {
                boundary.stderr_bytes = boundary.stderr_bytes.checked_add(bytes.len() as u64)?
            }
            Stream::Terminal => {
                boundary.terminal_bytes = boundary.terminal_bytes.checked_add(bytes.len() as u64)?
            }
        }
        boundary.final_cursor = end;
        boundary.chunks = sequence;
        boundary.final_hash = chain;
        tx.execute(
            "UPDATE processes SET boundary=?2 WHERE id=?1",
            params![id.as_str(), encode(&boundary)?],
        )?;
        tx.commit()?;
        Ok(boundary)
    }

    pub fn read_output(
        &self,
        id: &ProcessId,
        after: Counter,
        max_bytes: usize,
    ) -> Result<OutputPage> {
        if max_bytes == 0 || max_bytes > MAX_CONTROL_BYTES {
            return Err(Error::Capacity("output page must be 1..256 KiB"));
        }
        let (raw, released): (String, Option<String>) = self.db.connection.query_row(
            "SELECT boundary,release FROM processes WHERE id=?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if released.is_some() {
            return Err(Error::Conflict(
                "source evidence released; use the retaining owner's handle",
            ));
        }
        let boundary: OutputBoundary = decode(&raw)?;
        if let Some((receipt, _)) = self.receipt(id)?
            && boundary != receipt.output
        {
            return Err(Error::Corrupt(
                "output boundary disagrees with terminal receipt",
            ));
        }
        self.read_retained(id, boundary, after, max_bytes)
    }

    fn read_retained(
        &self,
        id: &ProcessId,
        boundary: OutputBoundary,
        after: Counter,
        max_bytes: usize,
    ) -> Result<OutputPage> {
        if after > boundary.final_cursor {
            return Err(Error::Conflict("output cursor beyond committed boundary"));
        }
        let mut page = OutputPage {
            cursor: after,
            available: boundary.final_cursor,
            chunks: Vec::new(),
        };
        if after == boundary.final_cursor {
            return Ok(page);
        }
        let mut file = private_file(&self.db.root.join(format!("{}.output", id.as_str())), false)?;
        // Indexed predecessor plus forward range: do not rescan prior output on every poll.
        let start: u64 = self.db.connection.query_row("SELECT offset FROM chunks WHERE process=?1 AND offset<=?2 ORDER BY offset DESC LIMIT 1", params![id.as_str(),after.get()], |r| r.get(0)).optional()?.ok_or(Error::Corrupt("output cursor has no retained segment"))?;
        let mut statement = self.db.connection.prepare("SELECT sequence,offset,length,stream,bytes_digest,chain_digest FROM chunks WHERE process=?1 AND offset>=?2 ORDER BY offset LIMIT 256")?;
        let rows = statement.query_map(params![id.as_str(), start], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, usize>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        let mut remaining = max_bytes;
        for row in rows {
            let (sequence, offset, length, stream, expected, chain) = row?;
            if sequence == 0
                || sequence > boundary.chunks.get()
                || length == 0
                || length > MAX_STREAM_BYTES
                || offset > page.cursor.get()
                || offset
                    .checked_add(length as u64)
                    .is_none_or(|end| end > boundary.final_cursor.get() || end <= page.cursor.get())
                || (!page.chunks.is_empty() && offset != page.cursor.get())
            {
                return Err(Error::Corrupt("invalid output segment index"));
            }
            let mut bytes = vec![0; length];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut bytes)?;
            let content = bytes_digest(&bytes);
            if content.as_str() != expected {
                return Err(Error::Corrupt("output segment digest mismatch"));
            }
            let skip = (page.cursor.get() - offset) as usize;
            let take = (length - skip).min(remaining);
            let stream: Stream = decode(&stream)?;
            let previous = if sequence == 1 {
                let epoch: u64 = self.db.connection.query_row(
                    "SELECT epoch FROM processes WHERE id=?1",
                    [id.as_str()],
                    |r| r.get(0),
                )?;
                empty_boundary(&self.sandbox, id, epoch.try_into()?)?.final_hash
            } else {
                let previous: String = self.db.connection.query_row(
                    "SELECT chain_digest FROM chunks WHERE process=?1 AND sequence=?2",
                    params![id.as_str(), sequence - 1],
                    |r| r.get(0),
                )?;
                previous.try_into()?
            };
            let actual_chain = digest(
                Domain::Output,
                &(
                    &previous,
                    Counter::try_from(sequence)?,
                    Counter::try_from(offset)?,
                    stream,
                    &content,
                    length,
                ),
            )?;
            if actual_chain.as_str() != chain
                || (sequence == boundary.chunks.get() && actual_chain != boundary.final_hash)
            {
                return Err(Error::Corrupt(
                    "output ordering or stream identity is corrupt",
                ));
            }
            // Payload hashes describe complete stored chunks; partial-page bytes are also hash-bound.
            let selected = bytes[skip..skip + take].to_vec();
            page.chunks.push(OutputChunk {
                sequence: sequence.try_into()?,
                offset: page.cursor,
                stream,
                bytes_digest: bytes_digest(&selected),
                bytes: selected,
                chain_digest: chain.try_into()?,
            });
            page.cursor = page.cursor.checked_add(take as u64)?;
            remaining -= take;
            if remaining == 0 {
                break;
            }
        }
        if page.cursor == after {
            return Err(Error::Corrupt("output coverage is missing"));
        }
        Ok(page)
    }

    pub fn publish_receipt(
        &mut self,
        id: &ProcessId,
        outcome: ProcessOutcome,
        cleanup: Digest,
        accounting: Digest,
    ) -> Result<(Receipt, Digest)> {
        let tx = self.db.connection.transaction()?;
        let (operation_id, epoch, boundary, old): (String, u64, String, Option<String>) = tx
            .query_row(
                "SELECT operation,epoch,boundary,receipt FROM processes WHERE id=?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        let operation_id: OperationId = operation_id.try_into()?;
        let mut op =
            operation(&tx, &operation_id)?.ok_or(Error::Corrupt("process operation is missing"))?;
        if !matches!(
            op.delivery,
            Delivery::Dispatched | Delivery::Applied | Delivery::NotApplied | Delivery::Unknown
        ) {
            return Err(Error::Conflict(
                "cannot settle a process before dispatch or confirmed non-application",
            ));
        }
        let receipt = Receipt {
            sandbox_id: self.sandbox.clone(),
            epoch: epoch.try_into()?,
            process_id: id.clone(),
            operation_id,
            request_digest: op.request.request_digest.clone(),
            outcome,
            output: decode(&boundary)?,
            cleanup_digest: cleanup,
            accounting_digest: accounting,
        };
        let receipt_digest = digest(Domain::Receipt, &receipt)?;
        if let Some(old) = old {
            if decode::<Receipt>(&old)? != receipt {
                return Err(Error::Conflict("terminal receipt is immutable"));
            }
            return Ok((receipt, receipt_digest));
        }
        let delivery = match receipt.outcome {
            ProcessOutcome::Exit { .. } | ProcessOutcome::Signal { .. } => Delivery::Applied,
            ProcessOutcome::SpawnFailed { .. } => Delivery::NotApplied,
            ProcessOutcome::Interrupted { .. } => op.delivery,
        };
        if matches!(
            (op.delivery, delivery),
            (Delivery::Applied, Delivery::NotApplied) | (Delivery::NotApplied, Delivery::Applied)
        ) {
            return Err(Error::Conflict(
                "receipt contradicts committed execution evidence",
            ));
        }
        op.delivery = delivery;
        op.evidence_digest = Some(receipt_digest.clone());
        tx.execute(
            "UPDATE operations SET value=?2 WHERE id=?1",
            params![op.request.operation_id.as_str(), encode(&op)?],
        )?;
        tx.execute(
            "UPDATE processes SET receipt=?2,receipt_digest=?3 WHERE id=?1",
            params![id.as_str(), encode(&receipt)?, receipt_digest.as_str()],
        )?;
        tx.commit()?;
        Ok((receipt, receipt_digest))
    }

    pub fn receipt(&self, id: &ProcessId) -> Result<Option<(Receipt, Digest)>> {
        receipt(&self.db.connection, id)
    }

    pub fn acknowledge_receipt(&mut self, id: &ProcessId, expected: &Digest) -> Result<()> {
        require_receipt(&self.db.connection, id, expected)?;
        self.db.connection.execute(
            "UPDATE processes SET acknowledged=1 WHERE id=?1",
            [id.as_str()],
        )?;
        Ok(())
    }

    pub fn pin(&mut self, id: &ProcessId, expected: &Digest, pin: PinId) -> Result<()> {
        let receipt = require_receipt(&self.db.connection, id, expected)?;
        let mut cursor = Counter::ZERO;
        while cursor < receipt.output.final_cursor {
            cursor = self.read_output(id, cursor, MAX_CONTROL_BYTES)?.cursor;
        }
        let tx = self.db.connection.transaction()?;
        require_receipt(&tx, id, expected)?;
        let released: Option<String> = tx.query_row(
            "SELECT release FROM processes WHERE id=?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        if released.is_some() {
            return Err(Error::Conflict(
                "cannot create a retention obligation after release",
            ));
        }
        if let Some((old_process, old_digest)) = tx
            .query_row(
                "SELECT process,receipt_digest FROM pins WHERE id=?1",
                [pin.as_str()],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()?
        {
            return if old_process == id.as_str() && old_digest == expected.as_str() {
                Ok(())
            } else {
                Err(Error::Conflict("pin identity conflict"))
            };
        }
        capacity(&tx, "pins", self.limits.pins)?;
        tx.execute(
            "INSERT INTO pins VALUES (?1,?2,?3)",
            params![pin.as_str(), id.as_str(), expected.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn read_pin(&self, pin: &PinId, after: Counter, max_bytes: usize) -> Result<OutputPage> {
        if max_bytes == 0 || max_bytes > MAX_CONTROL_BYTES {
            return Err(Error::Capacity("invalid output page bound"));
        }
        let id: String = self.db.connection.query_row(
            "SELECT process FROM pins WHERE id=?1",
            [pin.as_str()],
            |r| r.get(0),
        )?;
        let id: ProcessId = id.try_into()?;
        let (receipt, _) = self
            .receipt(&id)?
            .ok_or(Error::Corrupt("retention receipt is missing"))?;
        self.read_retained(&id, receipt.output, after, max_bytes)
    }

    /// Records delivery of a host-owned decision; the guardian cannot mint loss authority.
    pub fn record_loss_authorization(&mut self, authorized: AuthorizedLoss) -> Result<()> {
        self.authority.verify_loss(&authorized)?;
        let statement = authorized.statement;
        let id = &statement.process_id;
        let expected = &statement.receipt_digest;
        let receipt = require_receipt(&self.db.connection, id, expected)?;
        let binding = digest(
            Domain::Release,
            &(&self.sandbox, id, expected, &receipt.output, "loss"),
        )?;
        if statement.sandbox_id != self.sandbox
            || statement.output != receipt.output
            || statement.request_digest != binding
        {
            return Err(Error::Conflict(
                "loss approval must bind complete deletion scope",
            ));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = tx
            .query_row(
                "SELECT approval_digest FROM loss_authorizations WHERE id=?1",
                [statement.approval_id.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            return if old == binding.as_str() {
                Ok(())
            } else {
                Err(Error::Conflict("loss approval identity conflict"))
            };
        }
        capacity(&tx, "loss_authorizations", self.limits.operations)?;
        tx.execute(
            "INSERT INTO loss_authorizations VALUES (?1,?2,?3,?4)",
            params![
                statement.approval_id.as_str(),
                id.as_str(),
                expected.as_str(),
                binding.as_str()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Commits retirement only; cleanup is deliberately a second, retryable operation.
    pub fn release(&mut self, id: &ProcessId, request: ReleaseRequest) -> Result<ReleaseStatus> {
        let identity = digest(Domain::Release, &request)?;
        let tx = self.db.connection.transaction()?;
        let receipt = require_receipt(&tx, id, &request.receipt_digest)?;
        if receipt.output != request.output {
            return Err(Error::Conflict(
                "release scope does not cover all original output",
            ));
        }
        let (old, pending): (Option<String>, bool) = tx.query_row(
            "SELECT release,cleanup_pending FROM processes WHERE id=?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if let Some(old) = old {
            if decode::<ReleaseRequest>(&old)? != request {
                return Err(Error::Conflict("conflicting release disposition"));
            }
            return Ok(ReleaseStatus {
                request_digest: identity,
                cleanup_pending: pending,
            });
        }
        match &request.disposition {
            ReleaseDisposition::CompleteCapture { commitment } => {
                if commitment.receipt_digest != request.receipt_digest
                    || commitment.output != receipt.output
                {
                    return Err(Error::Conflict(
                        "capture commitment has incomplete original-byte coverage",
                    ));
                }
            }
            ReleaseDisposition::ContinuingRetention { pin } => {
                let pinned: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM pins WHERE id=?1 AND process=?2 AND receipt_digest=?3)", params![pin.as_str(),id.as_str(),request.receipt_digest.as_str()], |r| r.get(0))?;
                if !pinned {
                    return Err(Error::Conflict(
                        "reference has no committed independent retention obligation",
                    ));
                }
            }
            ReleaseDisposition::AuthorizedLoss { authorization } => {
                let authorized: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM loss_authorizations WHERE id=?1 AND process=?2 AND receipt_digest=?3)", params![authorization.as_str(),id.as_str(),request.receipt_digest.as_str()], |r| r.get(0))?;
                if !authorized {
                    return Err(Error::Conflict("loss has not been authorized"));
                }
            }
        }
        tx.execute(
            "UPDATE processes SET release=?2,cleanup_pending=1 WHERE id=?1",
            params![id.as_str(), encode(&request)?],
        )?;
        tx.commit()?;
        Ok(ReleaseStatus {
            request_digest: identity,
            cleanup_pending: true,
        })
    }

    pub fn cleanup_released(
        &mut self,
        id: &ProcessId,
        release_digest: &Digest,
    ) -> Result<ReleaseStatus> {
        let tx = self.db.connection.transaction()?;
        let raw: Option<String> = tx.query_row(
            "SELECT release FROM processes WHERE id=?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        let request: ReleaseRequest =
            decode(&raw.ok_or(Error::Conflict("evidence has not been released"))?)?;
        if digest(Domain::Release, &request)? != *release_digest {
            return Err(Error::Conflict("release digest mismatch"));
        }
        let pinned: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pins WHERE process=?1)",
            [id.as_str()],
            |r| r.get(0),
        )?;
        if !pinned {
            let path = self.db.root.join(format!("{}.output", id.as_str()));
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            sync_directory(&self.db.root)?;
            tx.execute("DELETE FROM chunks WHERE process=?1", [id.as_str()])?;
            tx.execute(
                "UPDATE processes SET output_limit=0 WHERE id=?1",
                [id.as_str()],
            )?;
        }
        tx.execute(
            "UPDATE processes SET cleanup_pending=0 WHERE id=?1",
            [id.as_str()],
        )?;
        tx.commit()?;
        Ok(ReleaseStatus {
            request_digest: release_digest.clone(),
            cleanup_pending: false,
        })
    }
}

fn observation(db: &rusqlite::Connection) -> Result<Option<MachineObservation>> {
    db.query_row(
        "SELECT value FROM observations ORDER BY sequence DESC LIMIT 1",
        [],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|s| decode(&s))
    .transpose()
}

fn valid_transition(old: &MachineObservation, new: &MachineObservation) -> bool {
    use MachineState::*;
    if old.epoch != new.epoch {
        return matches!(old.state, Stopped | Failed | Suspended)
            && matches!(new.state, Starting | Restoring);
    }
    if old.state == new.state {
        return old.state != Destroyed;
    }
    if new.state == Failed {
        return old.state != Destroyed;
    }
    if new.state == Destroying {
        return !matches!(old.state, Destroyed | Destroying);
    }
    matches!(
        (old.state, new.state),
        (Creating, Starting | Running | Stopped)
            | (Starting | Restoring, Running | Paused | Stopped)
            | (Running, Paused | Stopped | Suspended)
            | (Paused, Running | Stopped | Suspended)
            | (Suspended, Stopped)
            | (Failed, Stopped)
            | (Destroying, Destroyed)
    )
}
fn require_lifecycle_state(
    sandbox: &SandboxId,
    current: Option<&MachineObservation>,
    command: &LifecycleCommand,
) -> Result<()> {
    if &command.sandbox_id != sandbox {
        return Err(Error::Conflict(
            "lifecycle command belongs to another sandbox",
        ));
    }
    match current {
        None if command.revision == Counter::ONE && command.desired == DesiredState::Running => {
            Ok(())
        }
        Some(observed)
            if observed.state != MachineState::Destroyed
                && command.revision == observed.applied_revision.next()? =>
        {
            Ok(())
        }
        _ => Err(Error::Conflict(
            "lifecycle command is stale or incompatible with observed machine state",
        )),
    }
}
fn operation_capacity(db: &rusqlite::Connection, limit: Counter) -> Result<()> {
    let count: u64 = db.query_row(
        "SELECT (SELECT count(*) FROM operations) + (SELECT count(*) FROM lifecycle_operations)",
        [],
        |row| row.get(0),
    )?;
    if count >= limit.get() {
        return Err(Error::Capacity(
            "durable operation capacity exhausted; no evidence evicted",
        ));
    }
    Ok(())
}
fn operation(db: &rusqlite::Connection, id: &OperationId) -> Result<Option<Operation>> {
    db.query_row(
        "SELECT value FROM operations WHERE id=?1",
        [id.as_str()],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|s| decode(&s))
    .transpose()
}
fn lifecycle_operation(
    db: &rusqlite::Connection,
    id: &OperationId,
) -> Result<Option<LifecycleOperation>> {
    db.query_row(
        "SELECT value FROM lifecycle_operations WHERE id=?1",
        [id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| decode(&value))
    .transpose()
}
fn receipt(db: &rusqlite::Connection, id: &ProcessId) -> Result<Option<(Receipt, Digest)>> {
    let (raw, expected): (Option<String>, Option<String>) = db.query_row(
        "SELECT receipt,receipt_digest FROM processes WHERE id=?1",
        [id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    match (raw, expected) {
        (None, None) => Ok(None),
        (Some(raw), Some(expected)) => {
            let value: Receipt = decode(&raw)?;
            let actual = digest(Domain::Receipt, &value)?;
            if actual.as_str() != expected {
                return Err(Error::Corrupt("terminal receipt digest mismatch"));
            }
            Ok(Some((value, actual)))
        }
        _ => Err(Error::Corrupt("partial terminal receipt publication")),
    }
}
fn require_receipt(
    db: &rusqlite::Connection,
    id: &ProcessId,
    expected: &Digest,
) -> Result<Receipt> {
    let (value, actual) =
        receipt(db, id)?.ok_or(Error::Conflict("process has no terminal receipt"))?;
    if actual != *expected {
        return Err(Error::Conflict("receipt digest mismatch"));
    }
    Ok(value)
}
fn empty_boundary(sandbox: &SandboxId, id: &ProcessId, epoch: Counter) -> Result<OutputBoundary> {
    Ok(OutputBoundary {
        final_cursor: Counter::ZERO,
        chunks: Counter::ZERO,
        stdout_bytes: Counter::ZERO,
        stderr_bytes: Counter::ZERO,
        terminal_bytes: Counter::ZERO,
        omitted_bytes: Counter::ZERO,
        final_hash: digest(Domain::Output, &(sandbox, id, epoch))?,
    })
}
