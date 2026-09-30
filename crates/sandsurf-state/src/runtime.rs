use crate::{
    Error, Result, authority::AuthorityVerifier, catalog::capacity, database::Database, decode,
    encode,
};
use rusqlite::{OptionalExtension, params};
use sandsurf_protocol::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE configuration(id INTEGER PRIMARY KEY CHECK(id=1), machine TEXT NOT NULL, limits TEXT NOT NULL, authority TEXT NOT NULL, accepted_revision INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE observations(sequence INTEGER PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE INDEX observations_by_generation ON observations(json_extract(value,'$.generation'), sequence);
CREATE TABLE management_reports(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL) STRICT;
CREATE TABLE operations(id TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE lifecycle_operations(id TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE configuration_operations(id TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE events(sequence INTEGER PRIMARY KEY, value TEXT NOT NULL, digest TEXT NOT NULL) STRICT;
CREATE TABLE processes(id TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL REFERENCES operations(id), generation INTEGER NOT NULL, output_origin_generation INTEGER NOT NULL, output_limit INTEGER NOT NULL, reservation_active INTEGER NOT NULL DEFAULT 1 CHECK(reservation_active IN (0,1)), terminal_mode INTEGER NOT NULL, boundary TEXT NOT NULL, snapshot TEXT, receipt TEXT, receipt_digest TEXT, acknowledged INTEGER NOT NULL DEFAULT 0, release TEXT, cleanup_pending INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE chunks(process TEXT NOT NULL REFERENCES processes(id), sequence INTEGER NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, stream TEXT NOT NULL, bytes_digest TEXT NOT NULL, chain_digest TEXT NOT NULL, PRIMARY KEY(process,sequence)) STRICT;
CREATE INDEX chunks_by_offset ON chunks(process,offset);
CREATE INDEX chunks_by_digest ON chunks(bytes_digest);
CREATE UNIQUE INDEX chunks_identity_offset ON chunks(process,sequence,offset);
CREATE TABLE capture_writes(process TEXT PRIMARY KEY REFERENCES processes(id), sequence INTEGER NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, stream TEXT NOT NULL, bytes_digest TEXT NOT NULL, chain_digest TEXT NOT NULL) STRICT;
CREATE TABLE output_segments(id TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE segment_chunks(segment TEXT NOT NULL REFERENCES output_segments(id), process TEXT NOT NULL, sequence INTEGER NOT NULL, offset INTEGER NOT NULL, PRIMARY KEY(segment,sequence), FOREIGN KEY(process,sequence,offset) REFERENCES chunks(process,sequence,offset)) STRICT;
CREATE INDEX segment_chunks_by_offset ON segment_chunks(segment,offset);
CREATE INDEX segment_chunks_by_source ON segment_chunks(process,sequence);
CREATE VIEW segment_frames AS SELECT s.segment,c.sequence,s.offset,c.length,c.stream,c.bytes_digest,c.chain_digest FROM segment_chunks s JOIN chunks c ON c.process=s.process AND c.sequence=s.sequence;
CREATE TABLE acknowledgement_operations(id TEXT PRIMARY KEY, process TEXT NOT NULL REFERENCES processes(id), receipt_digest TEXT NOT NULL) STRICT;
CREATE TABLE output_seal_operations(id TEXT PRIMARY KEY, segment TEXT NOT NULL REFERENCES output_segments(id), request_digest TEXT NOT NULL) STRICT;
CREATE TABLE release_operations(id TEXT PRIMARY KEY, process TEXT NOT NULL REFERENCES processes(id), request_digest TEXT NOT NULL) STRICT;
CREATE TABLE loss_authorizations(id TEXT PRIMARY KEY, process TEXT NOT NULL REFERENCES processes(id), receipt_digest TEXT NOT NULL, approval_digest TEXT NOT NULL) STRICT;
";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeLimits {
    pub identities: Counter,
    /// Concurrent admitted executions, not guest Linux PIDs.
    pub managed_executions: Counter,
    pub operations: Counter,
    pub observations: Counter,
    pub events: Counter,
    pub chunks: Counter,
    pub output_segments: Counter,
    pub output_bytes: Counter,
}

/// Created only after a guardian journal commit. Host callers cannot construct/deserialise it.
pub struct CommittedObservation(MachineObservation);
impl CommittedObservation {
    pub fn value(&self) -> &MachineObservation {
        &self.0
    }
    pub fn reference(&self) -> Result<ObservationRef> {
        Ok(ObservationRef {
            machine_id: self.0.machine_id.clone(),
            generation: self.0.generation,
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
    pub after: Counter,
    pub cursor: Counter,
    pub available: Counter,
    pub chunks: Vec<OutputChunk>,
}

enum RetentionOwner<'a> {
    Execution(&'a ExecutionId),
    Segment(&'a OutputSegmentId),
}

struct RetentionSource<'a> {
    owner: RetentionOwner<'a>,
    machine: &'a MachineId,
    execution: &'a ExecutionId,
    generation: Counter,
}

impl RetentionOwner<'_> {
    fn index(&self) -> (&'static str, &'static str, &str) {
        match self {
            Self::Execution(id) => ("chunks", "process", id.as_str()),
            Self::Segment(id) => ("segment_frames", "segment", id.as_str()),
        }
    }
}

pub struct RuntimeJournal {
    pub(crate) db: Database,
    pub(crate) machine: MachineId,
    pub(crate) limits: RuntimeLimits,
    authority: AuthorityVerifier,
}

/// A successful ledger write is not a reusable native-effect permission.
pub enum DispatchDecision<'guardian> {
    Perform(DispatchPermit<'guardian>),
    Reconcile(Operation),
}

/// One generation-fenced dispatch received on the authenticated host channel.
pub struct DispatchPermit<'guardian> {
    command: GuestCommand,
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

pub enum ConfigurationDecision<'guardian> {
    Perform(ConfigurationPermit<'guardian>),
    Reconcile(ConfigurationOperation),
}

pub struct ConfigurationPermit<'guardian> {
    authority: AuthorizedConfiguration,
    _guardian: &'guardian mut RuntimeJournal,
}

impl ConfigurationPermit<'_> {
    pub fn perform<T>(self, effect: impl FnOnce(&ConfigurationCommand) -> T) -> T {
        effect(&self.authority.statement.command)
    }
}
impl LifecyclePermit<'_> {
    pub fn perform<T>(self, effect: impl FnOnce(&LifecycleCommand) -> T) -> T {
        effect(&self.authority.statement.command)
    }
}
impl DispatchPermit<'_> {
    pub fn perform<T>(self, effect: impl FnOnce(&GuestCommand) -> T) -> T {
        effect(&self.command)
    }
}

impl RuntimeJournal {
    pub fn create(
        path: &Path,
        machine: MachineId,
        limits: RuntimeLimits,
        binding: AuthorityBinding,
    ) -> Result<Self> {
        if [
            limits.identities,
            limits.managed_executions,
            limits.operations,
            limits.observations,
            limits.events,
            limits.chunks,
            limits.output_segments,
            limits.output_bytes,
        ]
        .contains(&Counter::ZERO)
        {
            return Err(Error::Capacity("runtime limits must be positive"));
        }
        let authority = AuthorityVerifier::new(binding)?;
        let db = Database::create(path, "guardian", SCHEMA)?;
        crate::output_store::create(&db.root)?;
        db.connection.execute(
            "INSERT INTO configuration(id,machine,limits,authority) VALUES (1,?1,?2,?3)",
            params![
                machine.as_str(),
                encode(&limits)?,
                encode(authority.binding())?
            ],
        )?;
        Ok(Self {
            db,
            machine,
            limits,
            authority,
        })
    }
    pub fn open(path: &Path, machine: &MachineId) -> Result<Self> {
        let db = Database::open(path, "guardian")?;
        let (identity, limits, binding): (String, String, String) = db.connection.query_row(
            "SELECT machine,limits,authority FROM configuration WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if identity != machine.as_str() {
            return Err(Error::Conflict("guardian machine identity mismatch"));
        }
        let mut journal = Self {
            db,
            machine: machine.clone(),
            limits: decode(&limits)?,
            authority: AuthorityVerifier::new(decode(&binding)?)?,
        };
        crate::output_store::validate(&journal.db.root)?;
        journal.recover_output_writes()?;
        Ok(journal)
    }
    pub fn authority_binding(&self) -> &AuthorityBinding {
        self.authority.binding()
    }
    pub fn machine_id(&self) -> &MachineId {
        &self.machine
    }
    pub fn last_management_report(&self) -> Result<Option<GuestManagementReport>> {
        self.db
            .connection
            .query_row(
                "SELECT value FROM management_reports WHERE id=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|raw| decode(&raw))
            .transpose()
    }

    pub fn record_management_report(&mut self, report: GuestManagementReport) -> Result<()> {
        if self
            .last_observation()?
            .is_none_or(|current| current.value().generation != report.generation)
        {
            return Err(Error::Conflict(
                "management report belongs to another execution generation",
            ));
        }
        self.db.connection.execute("INSERT INTO management_reports VALUES (1,?1) ON CONFLICT(id) DO UPDATE SET value=excluded.value", [encode(&report)?])?;
        Ok(())
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
        if reference.machine_id != self.machine
            || reference.generation != value.generation
            || reference.digest != digest(Domain::Operation, &value)?
        {
            return Err(Error::Conflict(
                "observation reference does not match guardian history",
            ));
        }
        Ok(CommittedObservation(value))
    }
    pub fn observe(&mut self, value: MachineObservation) -> Result<CommittedObservation> {
        if value.machine_id != self.machine {
            return Err(Error::Conflict("observation belongs to another machine"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = observation(&tx)? {
            if old == value {
                return Ok(CommittedObservation(old));
            }
            match &value.cause {
                ObservationCause::Native {}
                    if value.generation != old.generation
                        || value.applied_revision != old.applied_revision =>
                {
                    return Err(Error::Conflict(
                        "native measurement cannot install authority or assign a generation",
                    ));
                }
                ObservationCause::Configuration { .. }
                    if value.generation != old.generation || value.state != old.state =>
                {
                    return Err(Error::Conflict(
                        "configuration installation cannot change native power state",
                    ));
                }
                _ => {}
            }
            if value.sequence != old.sequence.next()?
                || value.generation < old.generation
                || value.generation > old.generation.next()?
                || value.applied_revision < old.applied_revision
                || old.state == MachineState::Destroyed
            {
                return Err(Error::Conflict(
                    "stale, skipped, or rewound guardian observation",
                ));
            }
            if value.generation != old.generation
                && !matches!(
                    value.state,
                    MachineState::Starting | MachineState::Restoring
                )
            {
                return Err(Error::Conflict(
                    "new generation requires an explicit boot/restore transition",
                ));
            }
            if !valid_transition(&old, &value) {
                return Err(Error::Conflict(
                    "machine observation requires a valid lifecycle/generation transition",
                ));
            }
        } else if !matches!(value.cause, ObservationCause::Lifecycle { .. })
            || value.sequence != Counter::ONE
            || value.generation != Counter::ONE
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
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::Machine {
                observation: value.clone(),
            },
        )?;
        tx.commit()?;
        Ok(CommittedObservation(value))
    }
    pub fn operation(&self, id: &OperationId) -> Result<Option<Operation>> {
        operation(&self.db.connection, id)
    }

    pub fn runtime_operation(&self, id: &OperationId) -> Result<Option<RuntimeOperationRecord>> {
        let db = &self.db.connection;
        let mut records = Vec::new();
        if let Some(operation) = operation(db, id)? {
            records.push(RuntimeOperationRecord::Guest { operation });
        }
        if let Some((process, receipt_digest)) = db
            .query_row(
                "SELECT process,receipt_digest FROM acknowledgement_operations WHERE id=?1",
                [id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            records.push(RuntimeOperationRecord::ReceiptAcknowledgement {
                operation_id: id.clone(),
                execution_id: process.try_into()?,
                receipt_digest: receipt_digest.try_into()?,
            });
        }
        if let Some((segment, request_digest)) = db
            .query_row(
                "SELECT segment,request_digest FROM output_seal_operations WHERE id=?1",
                [id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            records.push(RuntimeOperationRecord::OutputSeal {
                operation_id: id.clone(),
                request_digest: request_digest.try_into()?,
                segment: self.output_segment(&segment.try_into()?)?,
            });
        }
        if let Some((process, request_digest, raw_request, cleanup_pending)) = db
            .query_row(
                "SELECT r.process,r.request_digest,p.release,p.cleanup_pending FROM release_operations r JOIN processes p ON p.id=r.process WHERE r.id=?1",
                [id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()?
        {
            let raw_request = raw_request.ok_or(Error::Corrupt(
                "release operation has no committed disposition",
            ))?;
            let request: ReleaseRequest = decode(&raw_request)?;
            let expected = digest(Domain::Release, &request)?;
            if request.operation_id != *id || expected.as_str() != request_digest {
                return Err(Error::Corrupt("release operation binding is invalid"));
            }
            records.push(RuntimeOperationRecord::EvidenceRelease {
                execution_id: process.try_into()?,
                request,
                status: ReleaseStatus {
                    request_digest: expected,
                    cleanup_pending,
                },
            });
        }
        match records.len() {
            0 => Ok(None),
            1 => Ok(records.pop()),
            _ => Err(Error::Corrupt(
                "runtime operation identity is bound to multiple commands",
            )),
        }
    }

    pub fn event_cursor(&self) -> Result<Counter> {
        let available: u64 = self.db.connection.query_row(
            "SELECT coalesce(max(sequence),0) FROM events",
            [],
            |row| row.get(0),
        )?;
        Ok(Counter::try_from(available)?)
    }

    pub fn events(&self, after: Counter, maximum: u16) -> Result<RuntimeEventPage> {
        if maximum == 0 || maximum > 256 {
            return Err(Error::Capacity("event page must contain 1..256 entries"));
        }
        let available = self.event_cursor()?;
        if after > available {
            return Err(Error::Conflict("event cursor is beyond committed history"));
        }
        let mut statement = self.db.connection.prepare(
            "SELECT sequence,value,digest FROM events WHERE sequence>?1 ORDER BY sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after.get(), maximum], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut cursor = after;
        let mut events = Vec::new();
        let mut encoded_bytes = serde_json::to_vec(&RuntimeEventPage {
            cursor: available,
            available,
            events: Vec::new(),
        })?
        .len();
        for row in rows {
            let (sequence, raw, stored_digest) = row?;
            let sequence = Counter::try_from(sequence)?;
            if sequence != cursor.next()? {
                return Err(Error::Corrupt("runtime event history has a gap"));
            }
            let value: RuntimeEventValue = decode(&raw)?;
            let event_digest = runtime_event_digest(&self.machine, sequence, &value)?;
            if event_digest.as_str() != stored_digest {
                return Err(Error::Corrupt("runtime event digest mismatch"));
            }
            let event = RuntimeEvent {
                cursor: sequence,
                value,
                digest: event_digest,
            };
            let bytes = serde_json::to_vec(&event)?.len() + usize::from(!events.is_empty());
            if encoded_bytes + bytes > MAX_EVENT_PAGE_BYTES {
                if events.is_empty() {
                    return Err(Error::Capacity(
                        "one journal event exceeds its transport page bound",
                    ));
                }
                break;
            }
            encoded_bytes += bytes;
            events.push(event);
            cursor = sequence;
        }
        Ok(RuntimeEventPage {
            cursor,
            available,
            events,
        })
    }

    pub fn lifecycle_operation(&self, id: &OperationId) -> Result<Option<LifecycleOperation>> {
        lifecycle_operation(&self.db.connection, id)
    }

    pub fn configuration_operation(
        &self,
        id: &OperationId,
    ) -> Result<Option<ConfigurationOperation>> {
        configuration_operation(&self.db.connection, id)
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
        runtime_operation_identity_available(&tx, &command.operation_id)?;
        require_lifecycle_state(&self.machine, observation(&tx)?.as_ref(), &command)?;
        advance_authority_fence(&tx, command.revision)?;
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
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::LifecycleOperation {
                operation: value.clone(),
            },
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
        if !matches!(value.delivery, Delivery::Admitted | Delivery::NotApplied) {
            return Ok(LifecycleDecision::Reconcile(value));
        }
        require_lifecycle_state(&self.machine, observation(&tx)?.as_ref(), command)?;
        require_authority_fence(&tx, command.revision)?;
        value.delivery = Delivery::Dispatched;
        value.evidence_digest = None;
        value.observation = None;
        tx.execute(
            "UPDATE lifecycle_operations SET value=?2 WHERE id=?1",
            params![command.operation_id.as_str(), encode(&value)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::LifecycleOperation {
                operation: value.clone(),
            },
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
                    || observation.cause
                        != (ObservationCause::Lifecycle {
                            operation_id: value.command.operation_id.clone(),
                        })
                    || observation.machine_id != value.command.machine_id
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
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::LifecycleOperation {
                operation: value.clone(),
            },
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn admit_configuration(
        &mut self,
        authorization: AuthorizedConfiguration,
    ) -> Result<ConfigurationOperation> {
        self.authority.verify_configuration(&authorization)?;
        let command = authorization.statement.command;
        if let Some(old) = self.configuration_operation(&command.operation_id)? {
            return if old.command == command {
                Ok(old)
            } else {
                Err(Error::Conflict(
                    "configuration operation identity already bound",
                ))
            };
        }
        self.validate_resource_envelope(&command.configuration.resources)?;
        let tx = self.db.connection.transaction()?;
        runtime_operation_identity_available(&tx, &command.operation_id)?;
        require_configuration_state(&self.machine, observation(&tx)?.as_ref(), &command)?;
        advance_authority_fence(&tx, command.revision)?;
        operation_capacity(&tx, self.limits.operations)?;
        let value = ConfigurationOperation {
            command,
            delivery: Delivery::Admitted,
            evidence_digest: None,
            observation: None,
        };
        tx.execute(
            "INSERT INTO configuration_operations VALUES (?1,?2)",
            params![value.command.operation_id.as_str(), encode(&value)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::ConfigurationOperation {
                operation: value.clone(),
            },
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn begin_configuration<'guardian>(
        &'guardian mut self,
        authorization: AuthorizedConfiguration,
    ) -> Result<ConfigurationDecision<'guardian>> {
        self.authority.verify_configuration(&authorization)?;
        let command = &authorization.statement.command;
        let tx = self.db.connection.transaction()?;
        let mut value = configuration_operation(&tx, &command.operation_id)?
            .ok_or(Error::Missing("configuration operation is not admitted"))?;
        if value.command != *command {
            return Err(Error::Conflict("configuration authority mismatch"));
        }
        if matches!(
            value.delivery,
            Delivery::Dispatched | Delivery::Unknown | Delivery::Applied
        ) {
            return Ok(ConfigurationDecision::Reconcile(value));
        }
        // `NotApplied` is positive evidence that the prior dispatch had no
        // effect. Configuration installation is an idempotent control-plane
        // postcondition, so the same signed command may be dispatched again.
        // Unknown delivery remains non-replayable above.
        if value.delivery != Delivery::Admitted && value.delivery != Delivery::NotApplied {
            return Err(Error::Conflict(
                "configuration operation has an invalid retry state",
            ));
        }
        require_configuration_state(&self.machine, observation(&tx)?.as_ref(), command)?;
        require_authority_fence(&tx, command.revision)?;
        value.delivery = Delivery::Dispatched;
        tx.execute(
            "UPDATE configuration_operations SET value=?2 WHERE id=?1",
            params![command.operation_id.as_str(), encode(&value)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::ConfigurationOperation {
                operation: value.clone(),
            },
        )?;
        tx.commit()?;
        Ok(ConfigurationDecision::Perform(ConfigurationPermit {
            authority: authorization,
            _guardian: self,
        }))
    }

    pub fn record_configuration_delivery(
        &mut self,
        id: &OperationId,
        request: &Digest,
        delivery: Delivery,
        evidence: Option<Digest>,
        observed: Option<ObservationRef>,
    ) -> Result<ConfigurationOperation> {
        if matches!(delivery, Delivery::Admitted | Delivery::Dispatched) {
            return Err(Error::Conflict(
                "configuration admission and dispatch require their dedicated gates",
            ));
        }
        let committed = observed
            .as_ref()
            .map(|reference| self.observation_at(reference))
            .transpose()?;
        let tx = self.db.connection.transaction()?;
        let mut value = configuration_operation(&tx, id)?
            .ok_or(Error::Missing("configuration operation is missing"))?;
        if value.command.request_digest != *request {
            return Err(Error::Conflict("configuration request digest mismatch"));
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
            return Err(Error::Conflict("invalid configuration delivery transition"));
        }
        match delivery {
            Delivery::Applied => {
                let observation = committed
                    .as_ref()
                    .ok_or(Error::Conflict(
                        "applied configuration requires an observation",
                    ))?
                    .value();
                if evidence.is_none()
                    || observation.cause
                        != (ObservationCause::Configuration {
                            operation_id: value.command.operation_id.clone(),
                        })
                    || observation.machine_id != value.command.machine_id
                    || observation.applied_revision != value.command.revision
                {
                    return Err(Error::Conflict(
                        "configuration observation does not establish its postcondition",
                    ));
                }
            }
            Delivery::NotApplied => {
                if evidence.is_none() || observed.is_some() {
                    return Err(Error::Conflict(
                        "not-applied configuration requires evidence and no observation",
                    ));
                }
            }
            Delivery::Unknown => {
                if evidence.is_some() || observed.is_some() {
                    return Err(Error::Conflict(
                        "unknown configuration cannot claim completion evidence",
                    ));
                }
            }
            Delivery::Admitted | Delivery::Dispatched => unreachable!(),
        }
        let mut applied_limits = None;
        if delivery == Delivery::Applied {
            let mut limits = self.limits.clone();
            limits.output_bytes = value.command.configuration.resources.output_bytes;
            limits.managed_executions = value.command.configuration.resources.managed_executions;
            tx.execute(
                "UPDATE configuration SET limits=?1 WHERE id=1",
                [encode(&limits)?],
            )?;
            applied_limits = Some(limits);
        }
        value.delivery = delivery;
        value.evidence_digest = evidence;
        value.observation = observed;
        tx.execute(
            "UPDATE configuration_operations SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::ConfigurationOperation {
                operation: value.clone(),
            },
        )?;
        tx.commit()?;
        if let Some(limits) = applied_limits {
            self.limits = limits;
        }
        Ok(value)
    }

    /// Managed admission capacity is independent of output retention. Native
    /// interruption can free a slot without inventing a guest exit, receipt,
    /// capture boundary, or authorization to discard original bytes.
    pub fn managed_execution_slots_held(&self) -> Result<Counter> {
        Ok(Counter::try_from(managed_execution_slots(
            &self.db.connection,
        )?)?)
    }

    /// Management unavailability cannot free either kind of reservation.
    pub fn validate_resource_envelope(&self, resources: &Resources) -> Result<()> {
        resources.validate()?;
        let active = managed_execution_slots(&self.db.connection)?;
        let reserved: u64 = self.db.connection.query_row(
            "SELECT coalesce(sum(output_limit),0) FROM processes WHERE reservation_active=1",
            [],
            |row| row.get(0),
        )?;
        let retained: u64 = self.db.connection.query_row(
            "SELECT coalesce(sum(c.length),0) FROM chunks c JOIN processes p ON p.id=c.process WHERE p.reservation_active=0",
            [], |row| row.get(0),
        )?;
        if active > resources.managed_executions.get()
            || reserved
                .checked_add(retained)
                .is_none_or(|bytes| bytes > resources.output_bytes.get())
        {
            return Err(Error::Capacity(
                "resource reduction excludes retained bytes or active reservations",
            ));
        }
        Ok(())
    }

    pub fn admit(&mut self, request: GuestCommand) -> Result<Operation> {
        let admission = request.admission()?;
        let tx = self.db.connection.transaction()?;
        if let Some(old) = operation(&tx, &request.operation_id)? {
            if old.admission == admission {
                return Ok(old);
            }
            return Err(Error::Conflict("runtime operation identity already bound"));
        }
        runtime_operation_identity_available(&tx, &request.operation_id)?;
        let observed =
            observation(&tx)?.ok_or(Error::Missing("machine observation unavailable"))?;
        if request.machine_id != self.machine
            || request.generation != observed.generation
            || observed.state != MachineState::Running
        {
            return Err(Error::Conflict(
                "machine generation or power state does not admit work",
            ));
        }
        operation_capacity(&tx, self.limits.operations)?;
        let value = Operation {
            admission,
            delivery: Delivery::Admitted,
            evidence_digest: None,
        };
        tx.execute(
            "INSERT INTO operations VALUES (?1,?2)",
            params![
                value.admission.request.operation_id.as_str(),
                encode(&value)?
            ],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::GuestOperation {
                operation: value.clone(),
            },
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Recheck native power and generation, then durably gate one effect.
    /// A crash after this commit requires reconciliation even if no effect took place.
    pub fn begin_dispatch<'guardian>(
        &'guardian mut self,
        command: GuestCommand,
    ) -> Result<DispatchDecision<'guardian>> {
        let tx = self.db.connection.transaction()?;
        let request = &command;
        request.validate()?;
        let mut value = operation(&tx, &request.operation_id)?
            .ok_or(Error::Missing("dispatch operation is not admitted"))?;
        if value.admission != request.admission()? {
            return Err(Error::Conflict("dispatch identity mismatch"));
        }
        if value.delivery != Delivery::Admitted {
            return Ok(DispatchDecision::Reconcile(value));
        }
        let current = observation(&tx)?.ok_or(Error::Missing("machine observation unavailable"))?;
        if request.machine_id != self.machine
            || request.generation != current.generation
            || current.state != MachineState::Running
        {
            return Err(Error::Conflict("machine no longer admits dispatch"));
        }
        value.delivery = Delivery::Dispatched;
        tx.execute(
            "UPDATE operations SET value=?2 WHERE id=?1",
            params![request.operation_id.as_str(), encode(&value)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::GuestOperation {
                operation: value.clone(),
            },
        )?;
        tx.commit()?;
        Ok(DispatchDecision::Perform(DispatchPermit {
            command,
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
        if value.admission.request.request_digest != *request {
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
        if delivery == Delivery::NotApplied
            && matches!(&value.admission.request.request, GuestRequest::Spawn { .. })
        {
            let progressed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM processes p WHERE p.operation=?1 AND (p.snapshot IS NOT NULL OR p.receipt IS NOT NULL OR EXISTS(SELECT 1 FROM chunks c WHERE c.process=p.id)))",
                [id.as_str()],
                |row| row.get(0),
            )?;
            if progressed {
                return Err(Error::Conflict(
                    "non-application contradicts observed process evidence",
                ));
            }
            tx.execute(
                "UPDATE processes SET reservation_active=0 WHERE operation=?1",
                [id.as_str()],
            )?;
        }
        value.delivery = delivery;
        value.evidence_digest = evidence;
        tx.execute(
            "UPDATE operations SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::GuestOperation {
                operation: value.clone(),
            },
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn admit_process(
        &mut self,
        id: ExecutionId,
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
        let GuestRequest::Spawn { request } = &op.admission.request.request else {
            return Err(Error::Conflict(
                "process reservation requires a spawn request",
            ));
        };
        if request.execution_id != id
            || request.operation_id != *operation_id
            || request.output_bytes != output_limit
            || (request.stdio == StdioMode::Terminal) != terminal
        {
            return Err(Error::Conflict(
                "process reservation does not match the authorized spawn request",
            ));
        }
        if let Some((old_operation, old_generation, old_limit, old_terminal, released)) = tx
            .query_row(
                "SELECT operation,generation,output_limit,terminal_mode,release FROM processes WHERE id=?1",
                [id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?
        {
            if released.is_some() {
                return Err(Error::Conflict("process evidence identity was retired"));
            }
            return if old_operation == operation_id.as_str()
                && old_generation == op.admission.request.generation.get()
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
        let active = managed_execution_slots(&tx)?;
        if active >= self.limits.managed_executions.get() {
            return Err(Error::Capacity("managed execution reservations exhausted"));
        }
        // Unsettled capture promises reserve their full limit, including after
        // native interruption. An in-flight capture may still commit bytes;
        // reclaiming an execution slot cannot discharge that obligation.
        // Settled processes consume
        // only their actual retained bytes; unused headroom returns at the
        // same commit that publishes a terminal receipt.
        let reserved: u64 = tx.query_row(
            "SELECT coalesce(sum(output_limit),0) FROM processes WHERE reservation_active=1",
            [],
            |r| r.get(0),
        )?;
        let retained: u64 = tx.query_row(
            "SELECT coalesce(sum(c.length),0) FROM chunks c JOIN processes p ON p.id=c.process WHERE p.reservation_active=0",
            [],
            |r| r.get(0),
        )?;
        if reserved
            .checked_add(retained)
            .and_then(|used| used.checked_add(output_limit.get()))
            .is_none_or(|used| used > self.limits.output_bytes.get())
        {
            return Err(Error::Capacity("output reservations exhausted"));
        }
        let boundary = empty_boundary(&self.machine, &id, op.admission.request.generation)?;
        tx.execute("INSERT INTO processes(id,operation,generation,output_origin_generation,output_limit,terminal_mode,boundary) VALUES (?1,?2,?3,?3,?4,?5,?6)", params![id.as_str(), operation_id.as_str(), op.admission.request.generation.get(), output_limit.get(), terminal, encode(&boundary)?])?;
        tx.commit()?;
        Ok(())
    }

    pub fn process_boundary(&self, id: &ExecutionId) -> Result<OutputBoundary> {
        let raw: String = self.db.connection.query_row(
            "SELECT boundary FROM processes WHERE id=?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        decode(&raw)
    }

    pub fn observe_process(&mut self, snapshot: &ExecutionSnapshot) -> Result<()> {
        let tx = self.db.connection.transaction()?;
        let (operation_id, generation, old, receipt): (
            String,
            u64,
            Option<String>,
            Option<String>,
        ) = tx.query_row(
            "SELECT operation,generation,snapshot,receipt FROM processes WHERE id=?1",
            [snapshot.request.execution_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        let operation_id: OperationId = operation_id.try_into()?;
        let admitted =
            operation(&tx, &operation_id)?.ok_or(Error::Corrupt("process operation is missing"))?;
        let GuestRequest::Spawn { request } = &admitted.admission.request.request else {
            return Err(Error::Corrupt("process operation is not a spawn"));
        };
        let admitted_matches = if **request == snapshot.request {
            true
        } else if let Some(lineage) = &snapshot.lineage {
            let mut restored = (**request).clone();
            restored.machine_id = snapshot.request.machine_id.clone();
            restored.generation = snapshot.request.generation;
            lineage.source_machine_id == request.machine_id
                && lineage.source_generation == request.generation
                && restored == snapshot.request
        } else {
            false
        };
        if !admitted_matches
            || snapshot.request.generation.get() != generation
            || snapshot.guest_pid == 0
        {
            return Err(Error::Conflict(
                "process observation does not match admitted spawn",
            ));
        }
        if let Some(old) = old {
            let old: ExecutionSnapshot = decode(&old)?;
            if old.request != snapshot.request || old.guest_pid != snapshot.guest_pid {
                return Err(Error::Conflict("process observation identity changed"));
            }
            if matches!(
                old.state,
                ExecutionState::Exited(_) | ExecutionState::Unknown { .. }
            ) && old.state != snapshot.state
            {
                return Err(Error::Conflict("terminal process observation changed"));
            }
        }
        if let Some(receipt) = receipt {
            let receipt: Receipt = decode(&receipt)?;
            let expected = ExecutionState::Exited(ExecutionCompletion {
                outcome: receipt.outcome,
                output: receipt.output,
                cleanup_digest: receipt.cleanup_digest,
                accounting_digest: receipt.accounting_digest,
            });
            if snapshot.state != expected {
                return Err(Error::Conflict(
                    "process observation contradicts its terminal receipt",
                ));
            }
        }
        tx.execute(
            "UPDATE processes SET snapshot=?2 WHERE id=?1",
            params![snapshot.request.execution_id.as_str(), encode(snapshot)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::Process {
                process: snapshot.clone(),
            },
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn process_snapshot(&self, id: &ExecutionId) -> Result<Option<ExecutionSnapshot>> {
        let raw: Option<String> = self.db.connection.query_row(
            "SELECT snapshot FROM processes WHERE id=?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        raw.map(|value| decode(&value)).transpose()
    }

    pub fn execution_generation(&self, id: &ExecutionId) -> Result<Counter> {
        let generation: u64 = self.db.connection.query_row(
            "SELECT generation FROM processes WHERE id=?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        Ok(Counter::try_from(generation)?)
    }

    pub fn execution_ids(&self) -> Result<Vec<ExecutionId>> {
        let mut statement = self
            .db
            .connection
            .prepare("SELECT id FROM processes ORDER BY id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(row?.try_into()?)).collect()
    }

    /// Derived from the sole native observation history, not another status
    /// journal. Pause and suspend retain machine execution state; management
    /// unavailability supplies no native evidence at all. Cold boot and full
    /// restore invalidate old generation handles, without asserting that every
    /// captured Linux process was killed.
    pub fn execution_interruption(
        &self,
        generation: Counter,
    ) -> Result<Option<MachineObservation>> {
        if generation == Counter::ZERO {
            return Err(Error::Conflict("execution generation must be positive"));
        }
        let raw: Option<String> = self.db.connection.query_row(
            "SELECT value FROM observations WHERE json_extract(value,'$.generation')=?1 AND json_extract(value,'$.state') IN ('stopped','destroyed','failed') ORDER BY sequence LIMIT 1",
            [generation.get()],
            |row| row.get(0),
        ).optional()?;
        let raw = match raw {
            Some(raw) => Some(raw),
            None => self.db.connection.query_row(
                "SELECT value FROM observations WHERE json_extract(value,'$.generation')>?1 ORDER BY json_extract(value,'$.generation'),sequence LIMIT 1",
                [generation.get()],
                |row| row.get(0),
            ).optional()?,
        };
        raw.map(|raw| decode(&raw)).transpose()
    }

    /// Native resume admission, not inferred from management connectivity or
    /// merely from a numerically newer cold-boot generation.
    pub fn generation_was_restored(&self, generation: Counter) -> Result<bool> {
        Ok(self.db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM observations WHERE json_extract(value,'$.generation')=?1 AND json_extract(value,'$.state')='restoring' AND json_extract(value,'$.cause.kind')='lifecycle')",
            [generation.get()], |row| row.get(0),
        )?)
    }

    pub fn process_request(&self, id: &ExecutionId) -> Result<sandsurf_protocol::SpawnRequest> {
        let operation_id: String = self.db.connection.query_row(
            "SELECT operation FROM processes WHERE id=?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        let operation_id: OperationId = operation_id.try_into()?;
        let operation = operation(&self.db.connection, &operation_id)?
            .ok_or(Error::Corrupt("reserved process has no admission"))?;
        let GuestRequest::Spawn { request } = operation.admission.request.request else {
            return Err(Error::Corrupt("reserved process has no spawn request"));
        };
        if request.execution_id != *id {
            return Err(Error::Corrupt(
                "process identity differs from its admission",
            ));
        }
        Ok(*request)
    }

    pub fn process_snapshots(&self) -> Result<Vec<ExecutionSnapshot>> {
        let mut statement = self
            .db
            .connection
            .prepare("SELECT snapshot FROM processes WHERE snapshot IS NOT NULL ORDER BY id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut values = Vec::new();
        for row in rows {
            values.push(decode(&row?)?);
        }
        Ok(values)
    }

    /// One native epoch's host admissions, including ambiguous deliveries and
    /// reservations with no guest report. Older execution history is not part
    /// of the resumed computer's managed-execution membership.
    pub fn capture_executions(&self, generation: Counter) -> Result<Vec<CapturedExecution>> {
        if generation == Counter::ZERO {
            return Err(Error::Conflict("capture generation must be positive"));
        }
        let mut statement = self.db.connection.prepare(
            "SELECT id,snapshot,boundary FROM processes WHERE generation=?1 AND release IS NULL ORDER BY id",
        )?;
        let rows = statement.query_map([generation.get()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut captured = Vec::new();
        let mut encoded_bytes = 0usize;
        for row in rows {
            let (id, observation, boundary) = row?;
            let id = id.try_into()?;
            let admission = self.process_request(&id)?;
            // Admission identities are immutable; never invent a different
            // admission from a cooperative report after an epoch change.
            if admission.machine_id != self.machine || admission.generation != generation {
                return Err(Error::Conflict("capture admission identity mismatch"));
            }
            let observation: Option<ExecutionSnapshot> =
                observation.map(|value| decode(&value)).transpose()?;
            if observation
                .as_ref()
                .is_some_and(|value| value.request != admission)
            {
                return Err(Error::Conflict("capture observation identity mismatch"));
            }
            let value = CapturedExecution {
                admission,
                observation,
                output: decode(&boundary)?,
            };
            encoded_bytes = encoded_bytes
                .checked_add(serde_json::to_vec(&value)?.len() + 1)
                .ok_or(Error::Capacity("capture membership size overflow"))?;
            // Leave framing and native metadata space in the bounded response.
            if encoded_bytes > MAX_CONTROL_BYTES / 2 {
                return Err(Error::Capacity(
                    "capture membership exceeds transport bound",
                ));
            }
            captured.push(value);
        }
        Ok(captured)
    }

    /// Admission facts are available before a guest has reported its first snapshot.
    pub fn unsettled_execution_boundaries(
        &self,
        generation: Counter,
    ) -> Result<Vec<(ExecutionId, OutputBoundary)>> {
        let mut statement = self.db.connection.prepare(
            "SELECT id,boundary FROM processes WHERE generation=?1 AND receipt IS NULL AND release IS NULL ORDER BY id",
        )?;
        let rows = statement.query_map([generation.get()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, boundary) = row?;
            Ok((id.try_into()?, decode(&boundary)?))
        })
        .collect()
    }

    /// Rebind process observations after a trusted full-state restore. Host
    /// operations and receipts remain historical; only the current process
    /// handle generation and explicit snapshot lineage move forward.
    pub fn rebind_processes(
        &mut self,
        snapshot_id: &SnapshotId,
        source_machine_id: &MachineId,
        source_generation: Counter,
        generation: Counter,
    ) -> Result<()> {
        if generation == Counter::ZERO || generation == source_generation {
            return Err(Error::Conflict("restored process generation is invalid"));
        }
        let tx = self.db.connection.transaction()?;
        let mut statement =
            tx.prepare("SELECT id,generation,snapshot FROM processes ORDER BY id")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut updates = Vec::new();
        for row in rows {
            let (id, old_generation, snapshot) = row?;
            if Counter::try_from(old_generation)? != source_generation {
                // Historical processes from earlier cold-boot generations are not
                // live in this captured VM and retain their original identity.
                continue;
            }
            let snapshot = snapshot
                .map(|value| decode::<ExecutionSnapshot>(&value))
                .transpose()?;
            let Some(mut snapshot) = snapshot else {
                return Err(Error::Corrupt(
                    "captured process reservation has no observation",
                ));
            };
            if snapshot.request.machine_id != *source_machine_id
                || snapshot.request.generation != source_generation
                || snapshot.request.execution_id.as_str() != id
            {
                return Err(Error::Conflict(
                    "captured process identity does not match restore lineage",
                ));
            }
            snapshot.request.machine_id = self.machine.clone();
            snapshot.request.generation = generation;
            snapshot.lineage = Some(ExecutionLineage {
                source_machine_id: source_machine_id.clone(),
                source_generation,
                snapshot_id: snapshot_id.clone(),
            });
            updates.push((id, encode(&snapshot)?));
        }
        drop(statement);
        for (id, snapshot) in updates {
            tx.execute(
                "UPDATE processes SET generation=?2,snapshot=?3 WHERE id=?1",
                params![id, generation.get(), snapshot],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Bytes whose complete payload is still durably retained by this guardian.
    /// Receipt references are deliberately not counted unless their bytes remain
    /// available either through the execution or an independent output segment.
    pub fn retained_output_bytes(&self) -> Result<Counter> {
        let retained: u64 = self.db.connection.query_row(
            "SELECT coalesce(sum(length),0) FROM chunks",
            [],
            |row| row.get(0),
        )?;
        Ok(retained.try_into()?)
    }

    pub fn append_output(
        &mut self,
        id: &ExecutionId,
        sequence: Counter,
        stream: Stream,
        bytes: &[u8],
    ) -> Result<OutputBoundary> {
        if bytes.is_empty() || bytes.len() > MAX_STREAM_BYTES {
            return Err(Error::Capacity("invalid output chunk size"));
        }
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
                let original = crate::output_store::read(&self.db.root, &content, length)?;
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
        let next_boundary = extend_output_boundary(&boundary, sequence, stream, bytes)?;
        if next_boundary.final_cursor.get() > limit {
            return Err(Error::Capacity(
                "output reservation full; producer must stop before dropping evidence",
            ));
        }
        output_index_capacity(&tx, self.limits.chunks, 1)?;
        capacity(&tx, "events", self.limits.events)?;
        let chain = next_boundary.final_hash.clone();
        let shared: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM chunks WHERE bytes_digest=?1)",
            [content.as_str()],
            |r| r.get(0),
        )?;
        if shared && crate::output_store::read(&self.db.root, &content, bytes.len())? != bytes {
            return Err(Error::Corrupt(
                "shared output originals are unavailable or changed",
            ));
        }
        let prepared = (
            sequence.get(),
            boundary.final_cursor.get(),
            bytes.len() as u64,
            encode(&stream)?,
            content.as_str().to_owned(),
            chain.as_str().to_owned(),
        );
        type WriteIdentity = (u64, u64, u64, String, String, String);
        let pending: Option<WriteIdentity> = tx.query_row(
            "SELECT sequence,offset,length,stream,bytes_digest,chain_digest FROM capture_writes WHERE process=?1",
            [id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).optional()?;
        if let Some(pending) = pending {
            if pending != prepared {
                return Err(Error::Conflict(
                    "pending output capture has a different identity",
                ));
            }
        } else {
            tx.execute(
                "INSERT INTO capture_writes VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id.as_str(),
                    prepared.0,
                    prepared.1,
                    prepared.2,
                    prepared.3,
                    prepared.4,
                    prepared.5
                ],
            )?;
        }
        // Ownership precedes filesystem effects. A published object without
        // the final chunk commit is recovered from this exact durable intent.
        tx.commit()?;
        crate::output_store::publish(&self.db.root, &content, bytes)?;
        let tx = self.db.connection.transaction()?;
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
        boundary = next_boundary;
        tx.execute(
            "UPDATE processes SET boundary=?2 WHERE id=?1",
            params![id.as_str(), encode(&boundary)?],
        )?;
        tx.execute("DELETE FROM capture_writes WHERE process=?1", [id.as_str()])?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::Output {
                execution_id: id.clone(),
                boundary: boundary.clone(),
            },
        )?;
        tx.commit()?;
        Ok(boundary)
    }

    fn recover_output_writes(&mut self) -> Result<()> {
        loop {
            type PendingWrite = (String, u64, u64, usize, String, String, String);
            let pending: Option<PendingWrite> = self.db.connection.query_row(
                "SELECT process,sequence,offset,length,stream,bytes_digest,chain_digest FROM capture_writes ORDER BY process LIMIT 1",
                [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            ).optional()?;
            let Some((process, sequence, offset, length, stream, digest, chain)) = pending else {
                break;
            };
            let id: ExecutionId = process.try_into()?;
            let digest: Digest = digest.try_into()?;
            let stream: Stream = decode(&stream)?;
            let (raw, limit, terminal, settled): (String, u64, bool, bool) = self.db.connection.query_row(
                "SELECT boundary,output_limit,terminal_mode,receipt IS NOT NULL OR release IS NOT NULL FROM processes WHERE id=?1",
                [id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
            )?;
            let boundary: OutputBoundary = decode(&raw)?;
            if length == 0
                || length > MAX_STREAM_BYTES
                || settled
                || sequence != boundary.chunks.next()?.get()
                || offset != boundary.final_cursor.get()
                || offset
                    .checked_add(length as u64)
                    .is_none_or(|end| end > limit)
                || terminal != (stream == Stream::Terminal)
                || sandsurf_protocol::digest(
                    Domain::Output,
                    &(
                        &boundary.final_hash,
                        Counter::try_from(sequence)?,
                        Counter::try_from(offset)?,
                        stream,
                        &digest,
                        length,
                    ),
                )?
                .as_str()
                    != chain
            {
                return Err(Error::Corrupt("pending output capture identity is invalid"));
            }
            if let Some(bytes) = crate::output_store::recover(&self.db.root, &digest, length)? {
                self.append_output(&id, sequence.try_into()?, stream, &bytes)?;
            } else {
                // No complete payload ever became visible or acknowledged.
                // The guest may retry the same next sequence after reconnect.
                self.db
                    .connection
                    .execute("DELETE FROM capture_writes WHERE process=?1", [id.as_str()])?;
            }
        }
        Ok(())
    }

    pub fn read_output(
        &self,
        id: &ExecutionId,
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
        let generation: u64 = self.db.connection.query_row(
            "SELECT output_origin_generation FROM processes WHERE id=?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        self.read_retained(
            RetentionSource {
                owner: RetentionOwner::Execution(id),
                machine: &self.machine,
                execution: id,
                generation: generation.try_into()?,
            },
            boundary,
            after,
            max_bytes,
        )
    }

    fn read_retained(
        &self,
        source: RetentionSource<'_>,
        boundary: OutputBoundary,
        after: Counter,
        max_bytes: usize,
    ) -> Result<OutputPage> {
        if after > boundary.final_cursor {
            return Err(Error::Conflict("output cursor beyond committed boundary"));
        }
        let mut page = OutputPage {
            after,
            cursor: after,
            available: boundary.final_cursor,
            chunks: Vec::new(),
        };
        if after == boundary.final_cursor {
            return Ok(page);
        }
        // Indexed predecessor plus forward range: do not rescan prior output on every poll.
        let (table, column, owner) = source.owner.index();
        let start: u64 = self.db.connection.query_row(&format!("SELECT offset FROM {table} WHERE {column}=?1 AND offset<=?2 ORDER BY offset DESC LIMIT 1"), params![owner,after.get()], |r| r.get(0)).optional()?.ok_or(Error::Corrupt("output cursor has no retained segment"))?;
        let mut statement = self.db.connection.prepare(&format!("SELECT sequence,offset,length,stream,bytes_digest,chain_digest FROM {table} WHERE {column}=?1 AND offset>=?2 AND sequence<=?3 ORDER BY offset LIMIT 256"))?;
        let rows = statement.query_map(params![owner, start, boundary.chunks.get()], |r| {
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
            let bytes = crate::output_store::read(
                &self.db.root,
                &Digest::try_from(expected.clone())?,
                length,
            )?;
            let content = bytes_digest(&bytes);
            if content.as_str() != expected {
                return Err(Error::Corrupt("output segment digest mismatch"));
            }
            let skip = (page.cursor.get() - offset) as usize;
            let take = (length - skip).min(remaining);
            let stream: Stream = decode(&stream)?;
            let previous = if sequence == 1 {
                empty_boundary(source.machine, source.execution, source.generation)?.final_hash
            } else {
                let previous: String = self.db.connection.query_row(
                    &format!("SELECT chain_digest FROM {table} WHERE {column}=?1 AND sequence=?2"),
                    params![owner, sequence - 1],
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
        id: &ExecutionId,
        outcome: ExecutionOutcome,
        cleanup: Digest,
        accounting: Digest,
    ) -> Result<(Receipt, Digest)> {
        let tx = self.db.connection.transaction()?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM capture_writes WHERE process=?1)",
            [id.as_str()],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(Error::Conflict(
                "output capture must settle before a terminal receipt",
            ));
        }
        let (operation_id, generation, boundary, old): (String, u64, String, Option<String>) = tx
            .query_row(
            "SELECT operation,generation,boundary,receipt FROM processes WHERE id=?1",
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
            machine_id: self.machine.clone(),
            generation: generation.try_into()?,
            execution_id: id.clone(),
            operation_id,
            request_digest: op.admission.request.request_digest.clone(),
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
            ExecutionOutcome::Exit { .. }
            | ExecutionOutcome::Signal { .. }
            | ExecutionOutcome::DeadlineExceeded => Delivery::Applied,
            ExecutionOutcome::SpawnFailed { .. } => Delivery::NotApplied,
            ExecutionOutcome::Interrupted { .. } => op.delivery,
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
            params![op.admission.request.operation_id.as_str(), encode(&op)?],
        )?;
        tx.execute(
            "UPDATE processes SET receipt=?2,receipt_digest=?3,reservation_active=0 WHERE id=?1",
            params![id.as_str(), encode(&receipt)?, receipt_digest.as_str()],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::GuestOperation {
                operation: op.clone(),
            },
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::Receipt {
                execution_id: id.clone(),
                receipt_digest: receipt_digest.clone(),
            },
        )?;
        tx.commit()?;
        Ok((receipt, receipt_digest))
    }

    pub fn receipt(&self, id: &ExecutionId) -> Result<Option<(Receipt, Digest)>> {
        receipt(&self.db.connection, id)
    }

    pub fn acknowledge_receipt(
        &mut self,
        operation: &OperationId,
        id: &ExecutionId,
        expected: &Digest,
    ) -> Result<()> {
        let tx = self.db.connection.transaction()?;
        if let Some((old_process, old_digest)) = tx
            .query_row(
                "SELECT process,receipt_digest FROM acknowledgement_operations WHERE id=?1",
                [operation.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            return if old_process == id.as_str() && old_digest == expected.as_str() {
                Ok(())
            } else {
                Err(Error::Conflict(
                    "acknowledgement operation identity conflict",
                ))
            };
        }
        require_receipt(&tx, id, expected)?;
        runtime_operation_identity_available(&tx, operation)?;
        operation_capacity(&tx, self.limits.operations)?;
        tx.execute(
            "INSERT INTO acknowledgement_operations VALUES (?1,?2,?3)",
            params![operation.as_str(), id.as_str(), expected.as_str()],
        )?;
        tx.execute(
            "UPDATE processes SET acknowledged=1 WHERE id=?1",
            [id.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn seal_output(
        &mut self,
        operation: &OperationId,
        id: &ExecutionId,
        generation: Counter,
        expected: Option<&OutputBoundary>,
        segment_id: OutputSegmentId,
    ) -> Result<OutputSegment> {
        let request_digest = digest(
            Domain::Output,
            &(&self.machine, id, generation, expected, &segment_id),
        )?;
        if let Some(prior) = self.runtime_operation(operation)? {
            return match prior {
                RuntimeOperationRecord::OutputSeal {
                    request_digest: old,
                    segment,
                    ..
                } if old == request_digest => Ok(segment),
                _ => Err(Error::Conflict("output seal operation identity conflict")),
            };
        }
        let (raw, origin_generation, released): (String, u64, Option<String>) =
            self.db.connection.query_row(
                "SELECT boundary,output_origin_generation,release FROM processes WHERE id=?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
        if released.is_some() {
            return Err(Error::Conflict("cannot seal output after source release"));
        }
        if generation == Counter::ZERO || generation.get() != origin_generation {
            return Err(Error::Conflict("output capture generation mismatch"));
        }
        let current: OutputBoundary = decode(&raw)?;
        let boundary = expected.cloned().unwrap_or(current.clone());
        if boundary.chunks > current.chunks || boundary.final_cursor > current.final_cursor {
            return Err(Error::Conflict("segment extends beyond captured output"));
        }
        let mut observed = empty_boundary(&self.machine, id, generation)?;
        if boundary.chunks != Counter::ZERO {
            let (count, length, stdout, stderr, terminal): (u64, u64, u64, u64, u64) = self.db.connection.query_row(
                "SELECT count(*),coalesce(sum(length),0),coalesce(sum(CASE WHEN stream='\"stdout\"' THEN length ELSE 0 END),0),coalesce(sum(CASE WHEN stream='\"stderr\"' THEN length ELSE 0 END),0),coalesce(sum(CASE WHEN stream='\"terminal\"' THEN length ELSE 0 END),0) FROM chunks WHERE process=?1 AND sequence<=?2",
                params![id.as_str(), boundary.chunks.get()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
            )?;
            let (offset, last_length, hash): (u64, u64, String) = self.db.connection.query_row(
                "SELECT offset,length,chain_digest FROM chunks WHERE process=?1 AND sequence=?2",
                params![id.as_str(), boundary.chunks.get()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            if offset.checked_add(last_length) != Some(length) {
                return Err(Error::Corrupt("segment framing has incomplete coverage"));
            }
            observed = OutputBoundary {
                final_cursor: length.try_into()?,
                chunks: count.try_into()?,
                stdout_bytes: stdout.try_into()?,
                stderr_bytes: stderr.try_into()?,
                terminal_bytes: terminal.try_into()?,
                omitted_bytes: Counter::ZERO,
                final_hash: hash.try_into()?,
            };
        }
        if observed != boundary {
            return Err(Error::Conflict(
                "segment boundary does not identify an exact captured prefix",
            ));
        }
        let mut cursor = Counter::ZERO;
        while cursor < boundary.final_cursor {
            cursor = self
                .read_retained(
                    RetentionSource {
                        owner: RetentionOwner::Execution(id),
                        machine: &self.machine,
                        execution: id,
                        generation,
                    },
                    boundary.clone(),
                    cursor,
                    MAX_CONTROL_BYTES,
                )?
                .cursor;
        }
        let segment = OutputSegment {
            id: segment_id,
            machine_id: self.machine.clone(),
            execution_id: id.clone(),
            generation,
            output: boundary,
        };
        let tx = self.db.connection.transaction()?;
        runtime_operation_identity_available(&tx, operation)?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT value FROM output_segments WHERE id=?1",
                [segment.id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            if decode::<OutputSegment>(&prior)? != segment {
                return Err(Error::Conflict("output segment identity conflict"));
            }
        } else {
            capacity(&tx, "output_segments", self.limits.output_segments)?;
            output_index_capacity(&tx, self.limits.chunks, segment.output.chunks.get())?;
            tx.execute(
                "INSERT INTO output_segments VALUES (?1,?2)",
                params![segment.id.as_str(), encode(&segment)?],
            )?;
            tx.execute(
                "INSERT INTO segment_chunks SELECT ?1,process,sequence,offset FROM chunks WHERE process=?2 AND sequence<=?3",
                params![segment.id.as_str(), id.as_str(), segment.output.chunks.get()],
            )?;
        }
        operation_capacity(&tx, self.limits.operations)?;
        tx.execute(
            "INSERT INTO output_seal_operations VALUES (?1,?2,?3)",
            params![
                operation.as_str(),
                segment.id.as_str(),
                request_digest.as_str()
            ],
        )?;
        tx.commit()?;
        Ok(segment)
    }

    pub fn output_segment(&self, id: &OutputSegmentId) -> Result<OutputSegment> {
        let raw: String = self.db.connection.query_row(
            "SELECT value FROM output_segments WHERE id=?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        let segment: OutputSegment = decode(&raw)?;
        if segment.id != *id {
            return Err(Error::Corrupt("output segment identity mismatch"));
        }
        Ok(segment)
    }

    pub fn read_output_segment(
        &self,
        id: &OutputSegmentId,
        after: Counter,
        max_bytes: usize,
    ) -> Result<OutputPage> {
        if max_bytes == 0 || max_bytes > MAX_CONTROL_BYTES {
            return Err(Error::Capacity("invalid output page bound"));
        }
        let segment = self.output_segment(id)?;
        self.read_retained(
            RetentionSource {
                owner: RetentionOwner::Segment(id),
                machine: &segment.machine_id,
                execution: &segment.execution_id,
                generation: segment.generation,
            },
            segment.output,
            after,
            max_bytes,
        )
    }

    /// Records delivery of a host-owned decision; the guardian cannot mint loss authority.
    pub fn record_loss_authorization(&mut self, authorized: AuthorizedLoss) -> Result<()> {
        self.authority.verify_loss(&authorized)?;
        let statement = authorized.statement;
        let id = &statement.execution_id;
        let expected = &statement.receipt_digest;
        let receipt = require_receipt(&self.db.connection, id, expected)?;
        let binding = digest(
            Domain::Release,
            &(&self.machine, id, expected, &receipt.output, "loss"),
        )?;
        if statement.machine_id != self.machine
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
    pub fn release(&mut self, id: &ExecutionId, request: ReleaseRequest) -> Result<ReleaseStatus> {
        if let ReleaseDisposition::ContinuingRetention { segment } = &request.disposition {
            let retained = self.output_segment(segment)?;
            let original = require_receipt(&self.db.connection, id, &request.receipt_digest)?;
            if retained.execution_id != *id
                || retained.machine_id != original.machine_id
                || retained.generation != original.generation
                || retained.output != original.output
            {
                return Err(Error::Conflict(
                    "segment does not retain the entire released output",
                ));
            }
            let mut cursor = Counter::ZERO;
            while cursor < retained.output.final_cursor {
                cursor = self
                    .read_output_segment(segment, cursor, MAX_CONTROL_BYTES)?
                    .cursor;
            }
        }
        let identity = digest(Domain::Release, &request)?;
        let tx = self.db.connection.transaction()?;
        if let Some((old_process, old_digest)) = tx
            .query_row(
                "SELECT process,request_digest FROM release_operations WHERE id=?1",
                [request.operation_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if old_process != id.as_str() || old_digest != identity.as_str() {
                return Err(Error::Conflict("release operation identity conflict"));
            }
            let pending: bool = tx.query_row(
                "SELECT cleanup_pending FROM processes WHERE id=?1",
                [id.as_str()],
                |row| row.get(0),
            )?;
            return Ok(ReleaseStatus {
                request_digest: identity,
                cleanup_pending: pending,
            });
        }
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
            ReleaseDisposition::ContinuingRetention { .. } => {}
            ReleaseDisposition::AuthorizedLoss { authorization } => {
                let authorized: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM loss_authorizations WHERE id=?1 AND process=?2 AND receipt_digest=?3)", params![authorization.as_str(),id.as_str(),request.receipt_digest.as_str()], |r| r.get(0))?;
                if !authorized {
                    return Err(Error::Conflict("loss has not been authorized"));
                }
            }
        }
        runtime_operation_identity_available(&tx, &request.operation_id)?;
        operation_capacity(&tx, self.limits.operations)?;
        tx.execute(
            "INSERT INTO release_operations VALUES (?1,?2,?3)",
            params![
                request.operation_id.as_str(),
                id.as_str(),
                identity.as_str()
            ],
        )?;
        tx.execute(
            "UPDATE processes SET release=?2,cleanup_pending=1 WHERE id=?1",
            params![id.as_str(), encode(&request)?],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::EvidenceRelease {
                execution_id: id.clone(),
                request_digest: identity.clone(),
                cleanup_pending: true,
            },
        )?;
        tx.commit()?;
        Ok(ReleaseStatus {
            request_digest: identity,
            cleanup_pending: true,
        })
    }

    pub fn cleanup_released(
        &mut self,
        id: &ExecutionId,
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
        // Reserve the replay record before deleting any original bytes. Event
        // exhaustion must never turn a failed cleanup commit into silent loss.
        capacity(&tx, "events", self.limits.events)?;
        {
            let mut statement = tx.prepare("SELECT DISTINCT c.bytes_digest FROM chunks c WHERE c.process=?1 AND NOT EXISTS(SELECT 1 FROM chunks other WHERE other.bytes_digest=c.bytes_digest AND other.process<>?1) AND NOT EXISTS(SELECT 1 FROM segment_chunks retained JOIN chunks frame ON frame.process=retained.process AND frame.sequence=retained.sequence WHERE frame.bytes_digest=c.bytes_digest) AND NOT EXISTS(SELECT 1 FROM capture_writes pending WHERE pending.bytes_digest=c.bytes_digest)")?;
            let digests = statement.query_map([id.as_str()], |row| row.get::<_, String>(0))?;
            for digest in digests {
                crate::output_store::remove_blob(&self.db.root, &Digest::try_from(digest?)?)?;
            }
            drop(statement);
            tx.execute("DELETE FROM chunks WHERE process=?1 AND NOT EXISTS(SELECT 1 FROM segment_chunks retained WHERE retained.process=chunks.process AND retained.sequence=chunks.sequence)", [id.as_str()])?;
        }
        tx.execute(
            "UPDATE processes SET cleanup_pending=0 WHERE id=?1",
            [id.as_str()],
        )?;
        append_event(
            &tx,
            &self.machine,
            self.limits.events,
            RuntimeEventValue::EvidenceRelease {
                execution_id: id.clone(),
                request_digest: release_digest.clone(),
                cleanup_pending: false,
            },
        )?;
        tx.commit()?;
        Ok(ReleaseStatus {
            request_digest: release_digest.clone(),
            cleanup_pending: false,
        })
    }
}

fn output_index_capacity(db: &rusqlite::Connection, limit: Counter, additional: u64) -> Result<()> {
    let count: u64 = db.query_row(
        "SELECT (SELECT count(*) FROM chunks) + (SELECT count(*) FROM segment_chunks)",
        [],
        |r| r.get(0),
    )?;
    if count
        .checked_add(additional)
        .is_none_or(|total| total > limit.get())
    {
        return Err(Error::Capacity(
            "retained output framing capacity exhausted",
        ));
    }
    Ok(())
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

fn append_event(
    db: &rusqlite::Connection,
    machine: &MachineId,
    limit: Counter,
    value: RuntimeEventValue,
) -> Result<()> {
    capacity(db, "events", limit)?;
    let previous: u64 =
        db.query_row("SELECT coalesce(max(sequence),0) FROM events", [], |row| {
            row.get(0)
        })?;
    let sequence = Counter::try_from(previous)?.next()?;
    let event_digest = runtime_event_digest(machine, sequence, &value)?;
    db.execute(
        "INSERT INTO events VALUES (?1,?2,?3)",
        params![sequence.get(), encode(&value)?, event_digest.as_str()],
    )?;
    Ok(())
}

fn managed_execution_slots(db: &rusqlite::Connection) -> Result<u64> {
    let Some(current) = observation(db)? else {
        return Ok(0);
    };
    // Derive the slot lifetime from the existing authoritative native history,
    // not guest process reports or another persisted lifecycle/status field.
    let ended: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM observations WHERE json_extract(value,'$.generation')=?1 AND json_extract(value,'$.state') IN ('stopped','destroyed','failed'))",
        [current.generation.get()], |row| row.get(0),
    )?;
    if ended {
        return Ok(0);
    }
    Ok(db.query_row(
        "SELECT count(*) FROM processes WHERE reservation_active=1 AND generation=?1",
        [current.generation.get()],
        |row| row.get(0),
    )?)
}

fn valid_transition(old: &MachineObservation, new: &MachineObservation) -> bool {
    use MachineState::*;
    if old.generation != new.generation {
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
    machine: &MachineId,
    current: Option<&MachineObservation>,
    command: &LifecycleCommand,
) -> Result<()> {
    if &command.machine_id != machine {
        return Err(Error::Conflict(
            "lifecycle command belongs to another machine",
        ));
    }
    match current {
        None if command.revision > Counter::ZERO
            && matches!(
                command.desired,
                DesiredState::Running | DesiredState::Stopped | DesiredState::Destroyed
            ) =>
        {
            Ok(())
        }
        Some(observed)
            if observed.state != MachineState::Destroyed
                && command.revision > observed.applied_revision =>
        {
            Ok(())
        }
        _ => Err(Error::Conflict(
            "lifecycle command is stale or incompatible with observed machine state",
        )),
    }
}
fn require_configuration_state(
    machine: &MachineId,
    current: Option<&MachineObservation>,
    command: &ConfigurationCommand,
) -> Result<()> {
    if &command.machine_id != machine {
        return Err(Error::Conflict(
            "configuration command belongs to another machine",
        ));
    }
    match current {
        Some(observed)
            if observed.state != MachineState::Destroyed
                && command.revision > observed.applied_revision =>
        {
            Ok(())
        }
        _ => Err(Error::Conflict(
            "configuration command is stale or has no machine identity",
        )),
    }
}
fn operation_capacity(db: &rusqlite::Connection, limit: Counter) -> Result<()> {
    let count: u64 = db.query_row(
        "SELECT (SELECT count(*) FROM operations) + (SELECT count(*) FROM lifecycle_operations) + (SELECT count(*) FROM configuration_operations) + (SELECT count(*) FROM acknowledgement_operations) + (SELECT count(*) FROM output_seal_operations) + (SELECT count(*) FROM release_operations)",
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

/// A complete signed host decision can supersede an unapplied revision.
/// Acceptance is an anti-replay fence, not evidence that any effect occurred.
fn advance_authority_fence(db: &rusqlite::Connection, revision: Counter) -> Result<()> {
    let changed = db.execute(
        "UPDATE configuration SET accepted_revision=?1 WHERE id=1 AND accepted_revision<?1",
        [revision.get()],
    )?;
    if changed != 1 {
        return Err(Error::Conflict("host authority revision was superseded"));
    }
    Ok(())
}

fn require_authority_fence(db: &rusqlite::Connection, revision: Counter) -> Result<()> {
    let accepted: u64 = db.query_row(
        "SELECT accepted_revision FROM configuration WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    if accepted != revision.get() {
        return Err(Error::Conflict("host authority revision was superseded"));
    }
    Ok(())
}
fn runtime_operation_identity_available(db: &rusqlite::Connection, id: &OperationId) -> Result<()> {
    let conflicting: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1) OR EXISTS(SELECT 1 FROM lifecycle_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM configuration_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM acknowledgement_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM output_seal_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM release_operations WHERE id=?1)",
        [id.as_str()],
        |row| row.get(0),
    )?;
    if conflicting {
        return Err(Error::Conflict(
            "operation identity already belongs to another guardian operation",
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
    .map(|s| {
        let mut value: Operation = decode(&s)?;
        value.admission.validate_admission()?;
        Ok(value)
    })
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
fn configuration_operation(
    db: &rusqlite::Connection,
    id: &OperationId,
) -> Result<Option<ConfigurationOperation>> {
    db.query_row(
        "SELECT value FROM configuration_operations WHERE id=?1",
        [id.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| decode(&value))
    .transpose()
}
fn receipt(db: &rusqlite::Connection, id: &ExecutionId) -> Result<Option<(Receipt, Digest)>> {
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
    id: &ExecutionId,
    expected: &Digest,
) -> Result<Receipt> {
    let (value, actual) =
        receipt(db, id)?.ok_or(Error::Conflict("process has no terminal receipt"))?;
    if actual != *expected {
        return Err(Error::Conflict("receipt digest mismatch"));
    }
    Ok(value)
}
fn empty_boundary(
    machine: &MachineId,
    id: &ExecutionId,
    generation: Counter,
) -> Result<OutputBoundary> {
    Ok(initial_output_boundary(machine, id, generation)?)
}
