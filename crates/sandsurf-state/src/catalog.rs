use crate::{Error, Result, authority::HostAuthority, database::Database, decode, encode};
use rusqlite::{OptionalExtension, params};
use sandsurf_protocol::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE configuration(id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, limits TEXT NOT NULL, authority TEXT NOT NULL) STRICT;
CREATE TABLE sandboxes(id TEXT PRIMARY KEY, image TEXT NOT NULL, resources TEXT NOT NULL, revision INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE intents(id TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), request TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE grants(id TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), value TEXT NOT NULL) STRICT;
CREATE TABLE usage(id TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), digest TEXT NOT NULL, cpu INTEGER NOT NULL, network INTEGER NOT NULL) STRICT;
CREATE TABLE approvals(id TEXT PRIMARY KEY, digest TEXT NOT NULL) STRICT;
CREATE TABLE image_imports(operation TEXT PRIMARY KEY, request_digest TEXT NOT NULL, phase TEXT NOT NULL, image TEXT) STRICT;
CREATE TABLE images(digest TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogLimits {
    pub identities: Counter,
    pub operations: Counter,
    pub grants: Counter,
    pub usage_records: Counter,
    pub resources: Resources,
}

/// Trusted host-side authorization decision. Not accepted as a guest API message.
#[derive(Debug, Clone)]
pub struct Approval {
    pub id: CommitmentId,
    pub request_digest: Digest,
}

#[derive(Debug, Clone)]
pub struct GrantChange {
    pub sandbox_id: SandboxId,
    pub id: GrantId,
    pub expected_revision: Counter,
    pub capability: Capability,
    pub scope_digest: Digest,
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservationState {
    Held,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImageImportPhase {
    Admitted,
    Published,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageRecord {
    pub digest: Digest,
    pub source_digest: Digest,
    pub platform: String,
    pub architecture: String,
    pub logical_bytes: Counter,
    pub provenance_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageImportRecord {
    pub operation_id: OperationId,
    pub request_digest: Digest,
    pub phase: ImageImportPhase,
    pub image: Option<ImageRecord>,
}

/// Host-owned identity, configuration, and reservation facts. Machine state is
/// deliberately absent: callers obtain that separately from the guardian.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxRecord {
    pub id: SandboxId,
    pub image_digest: Digest,
    pub resources: Resources,
    pub configuration_revision: Counter,
    pub reservation: ReservationState,
    pub latest_intent: LifecycleIntent,
}

pub struct HostCatalog {
    db: Database,
    host: HostId,
    limits: CatalogLimits,
    authority: HostAuthority,
}

impl HostCatalog {
    pub fn create(path: &Path, host: HostId, limits: CatalogLimits) -> Result<Self> {
        limits.resources.validate()?;
        if [
            limits.identities,
            limits.operations,
            limits.grants,
            limits.usage_records,
        ]
        .contains(&Counter::ZERO)
        {
            return Err(Error::Capacity("catalog limits must be positive"));
        }
        let db = Database::create(path, "host", SCHEMA)?;
        let authority = HostAuthority::create(&db.root, host.clone())?;
        db.connection.execute(
            "INSERT INTO configuration VALUES (1, ?1, ?2, ?3)",
            params![
                host.as_str(),
                encode(&limits)?,
                encode(authority.binding())?
            ],
        )?;
        Ok(Self {
            db,
            host,
            limits,
            authority,
        })
    }
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::open(path, "host")?;
        let (host, limits, binding): (String, String, String) = db.connection.query_row(
            "SELECT host, limits, authority FROM configuration WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let host: HostId = host.try_into()?;
        let binding: AuthorityBinding = decode(&binding)?;
        if binding.host_id != host {
            return Err(Error::Corrupt(
                "authority binding has the wrong host identity",
            ));
        }
        let authority = HostAuthority::open(&db.root, &binding)?;
        Ok(Self {
            db,
            host,
            limits: decode(&limits)?,
            authority,
        })
    }
    pub fn host_id(&self) -> &HostId {
        &self.host
    }

    /// Admit an image mutation before any source is read or builder is run.
    /// The catalog stores only the exact request digest, never registry
    /// credentials or an independently mutable copy of image metadata.
    pub fn admit_image_import(
        &mut self,
        operation_id: OperationId,
        request_digest: Digest,
        approval: Approval,
    ) -> Result<ImageImportRecord> {
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("image import approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = image_import(&tx, &operation_id)? {
            return if old.request_digest == request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict("image import operation identity conflict"))
            };
        }
        capacity(&tx, "image_imports", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let value = ImageImportRecord {
            operation_id,
            request_digest,
            phase: ImageImportPhase::Admitted,
            image: None,
        };
        tx.execute(
            "INSERT INTO image_imports VALUES (?1,?2,?3,NULL)",
            params![
                value.operation_id.as_str(),
                value.request_digest.as_str(),
                encode(&value.phase)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn complete_image_import(
        &mut self,
        operation_id: &OperationId,
        request_digest: &Digest,
        image: ImageRecord,
    ) -> Result<ImageImportRecord> {
        let tx = self.db.connection.transaction()?;
        let old = image_import(&tx, operation_id)?
            .ok_or(Error::Missing("image import operation is missing"))?;
        if &old.request_digest != request_digest {
            return Err(Error::Conflict("image import request digest changed"));
        }
        if old.phase == ImageImportPhase::Published {
            return if old.image.as_ref() == Some(&image) {
                Ok(old)
            } else {
                Err(Error::Conflict(
                    "image import already published another image",
                ))
            };
        }
        if let Some(existing) = image_record(&tx, &image.digest)? {
            if existing != image {
                return Err(Error::Conflict(
                    "image digest is bound to different metadata",
                ));
            }
        } else {
            capacity(&tx, "images", self.limits.identities)?;
            tx.execute(
                "INSERT INTO images VALUES (?1,?2)",
                params![image.digest.as_str(), encode(&image)?],
            )?;
        }
        tx.execute(
            "UPDATE image_imports SET phase=?2,image=?3 WHERE operation=?1",
            params![
                operation_id.as_str(),
                encode(&ImageImportPhase::Published)?,
                image.digest.as_str()
            ],
        )?;
        tx.commit()?;
        Ok(ImageImportRecord {
            operation_id: operation_id.clone(),
            request_digest: request_digest.clone(),
            phase: ImageImportPhase::Published,
            image: Some(image),
        })
    }

    pub fn image_import(&self, operation: &OperationId) -> Result<Option<ImageImportRecord>> {
        image_import(&self.db.connection, operation)
    }

    pub fn image(&self, digest: &Digest) -> Result<Option<ImageRecord>> {
        image_record(&self.db.connection, digest)
    }

    pub fn images(&self, after: Option<&Digest>, limit: Counter) -> Result<Vec<ImageRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("image page limit must be in 1..=256"));
        }
        let mut statement = self
            .db
            .connection
            .prepare("SELECT value FROM images WHERE digest>?1 ORDER BY digest ASC LIMIT ?2")?;
        statement
            .query_map(
                params![after.map_or("", Digest::as_str), limit.get()],
                |row| row.get::<_, String>(0),
            )?
            .map(|value| decode(&value?))
            .collect()
    }
    pub fn authority_binding(&self) -> &AuthorityBinding {
        self.authority.binding()
    }

    pub fn sandbox(&self, id: &SandboxId) -> Result<Option<SandboxRecord>> {
        sandbox_record(&self.db.connection, id)
    }

    /// Stable identity pagination. The bounded result is an observation of the
    /// host catalog, not an ownership token or a cache of machine state.
    pub fn sandboxes(
        &self,
        after: Option<&SandboxId>,
        limit: Counter,
    ) -> Result<Vec<SandboxRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("sandbox page limit must be in 1..=256"));
        }
        let after = after.map_or("", SandboxId::as_str);
        let mut statement = self
            .db
            .connection
            .prepare("SELECT id FROM sandboxes WHERE id>?1 ORDER BY id ASC LIMIT ?2")?;
        let identities = statement
            .query_map(params![after, limit.get()], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        identities
            .into_iter()
            .map(|id| {
                let id: SandboxId = id.try_into()?;
                sandbox_record(&self.db.connection, &id)?.ok_or(Error::Corrupt(
                    "listed sandbox disappeared from the host transaction view",
                ))
            })
            .collect()
    }

    pub fn create_sandbox(
        &mut self,
        id: SandboxId,
        image: Digest,
        resources: Resources,
        operation: OperationId,
        approval: Approval,
    ) -> Result<LifecycleIntent> {
        resources.validate()?;
        let request = digest(Domain::Sandbox, &(&id, &image, &resources, &operation))?;
        if request != approval.request_digest {
            return Err(Error::Conflict(
                "creation approval does not bind the exact request",
            ));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = intent(&tx, &operation)? {
            if old.request_digest == request {
                return Ok(old);
            }
            return Err(Error::Conflict(
                "operation identity already bound to another request",
            ));
        }
        capacity(&tx, "sandboxes", self.limits.identities)?;
        capacity(&tx, "intents", self.limits.operations)?;
        let mut total = resources.clone();
        {
            let mut statement = tx.prepare("SELECT resources FROM sandboxes WHERE released=0")?;
            let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
            for row in rows {
                total = total.checked_add(&decode::<Resources>(&row?)?)?;
            }
        }
        if !total.within(&self.limits.resources) {
            return Err(Error::Capacity("host resource reservations exhausted"));
        }
        record_approval(&tx, &approval, self.limits.operations)?;
        tx.execute(
            "INSERT INTO sandboxes(id,image,resources,revision) VALUES (?1,?2,?3,1)",
            params![id.as_str(), image.as_str(), encode(&resources)?],
        )?;
        let value = LifecycleIntent {
            sandbox_id: id,
            operation_id: operation,
            desired: DesiredState::Running,
            revision: Counter::ONE,
            request_digest: request,
            completion: None,
        };
        save_intent(&tx, &value)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn request_lifecycle(
        &mut self,
        sandbox: &SandboxId,
        operation: OperationId,
        expected: Counter,
        desired: DesiredState,
        approval: Approval,
    ) -> Result<LifecycleIntent> {
        let request = digest(Domain::Operation, &(sandbox, &operation, expected, desired))?;
        if approval.request_digest != request {
            return Err(Error::Conflict("lifecycle approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = intent(&tx, &operation)? {
            if old.request_digest == request {
                return Ok(old);
            }
            return Err(Error::Conflict("operation identity conflict"));
        }
        require_revision(&tx, sandbox, expected)?;
        capacity(&tx, "intents", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let revision = expected.next()?;
        let value = LifecycleIntent {
            sandbox_id: sandbox.clone(),
            operation_id: operation,
            desired,
            revision,
            request_digest: request,
            completion: None,
        };
        tx.execute(
            "UPDATE sandboxes SET revision=?2 WHERE id=?1",
            params![sandbox.as_str(), revision.get()],
        )?;
        save_intent(&tx, &value)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn intent(&self, operation: &OperationId) -> Result<Option<LifecycleIntent>> {
        intent(&self.db.connection, operation)
    }

    pub fn authorize_lifecycle(&self, operation: &OperationId) -> Result<AuthorizedLifecycle> {
        let intent = self
            .intent(operation)?
            .ok_or(Error::Missing("lifecycle intent is missing"))?;
        self.authority.authorize_lifecycle(LifecycleCommand {
            sandbox_id: intent.sandbox_id,
            operation_id: intent.operation_id,
            desired: intent.desired,
            revision: intent.revision,
            request_digest: intent.request_digest,
        })
    }

    /// Authorize installation of the host-owned configuration revision without
    /// manufacturing a lifecycle intent. The guardian records the applied
    /// revision as an observation; this catalog remains the only grant writer.
    pub fn authorize_configuration(
        &self,
        sandbox: &SandboxId,
        revision: Counter,
    ) -> Result<AuthorizedConfiguration> {
        require_revision(&self.db.connection, sandbox, revision)?;
        let operation_id: OperationId = format!("configuration-{}", revision.get()).try_into()?;
        let request_digest = digest(
            Domain::Grant,
            &("sandsurf-apply-configuration-v1", sandbox, revision),
        )?;
        self.authority
            .authorize_configuration(ConfigurationCommand {
                sandbox_id: sandbox.clone(),
                operation_id,
                revision,
                request_digest,
            })
    }

    /// Called with evidence read from the exclusively owned guardian journal, not client observations.
    pub fn complete_intent(
        &mut self,
        evidence: &crate::CommittedObservation,
    ) -> Result<LifecycleIntent> {
        let observation = evidence.value();
        let reference = evidence.reference()?;
        self.complete_intent_observation(observation, reference)
    }

    /// Commit a host reference to lifecycle evidence received over the trusted
    /// host/guardian route. The guardian operation and observation are checked
    /// together; neither an application acknowledgement nor cached state suffices.
    pub fn complete_lifecycle_operation(
        &mut self,
        operation: &LifecycleOperation,
        observation: &MachineObservation,
    ) -> Result<LifecycleIntent> {
        let reference = operation
            .observation
            .clone()
            .ok_or(Error::Conflict("lifecycle operation has no observation"))?;
        if operation.delivery != Delivery::Applied
            || operation.evidence_digest.is_none()
            || operation.command.sandbox_id != observation.sandbox_id
            || operation.command.operation_id != observation.operation_id
            || operation.command.revision != observation.applied_revision
            || !observation.state.satisfies(operation.command.desired)
            || reference.sandbox_id != observation.sandbox_id
            || reference.epoch != observation.epoch
            || reference.sequence != observation.sequence
            || reference.digest != digest(Domain::Operation, observation)?
        {
            return Err(Error::Conflict(
                "guardian lifecycle evidence does not establish completion",
            ));
        }
        self.complete_intent_observation(observation, reference)
    }

    fn complete_intent_observation(
        &mut self,
        observation: &MachineObservation,
        reference: ObservationRef,
    ) -> Result<LifecycleIntent> {
        let tx = self.db.connection.transaction()?;
        let mut value = intent(&tx, &observation.operation_id)?
            .ok_or(Error::Missing("lifecycle intent is missing"))?;
        if value.sandbox_id != observation.sandbox_id
            || !observation.state.satisfies(value.desired)
            || observation.applied_revision != value.revision
        {
            return Err(Error::Conflict(
                "guardian evidence does not establish the requested postcondition",
            ));
        }
        if let Some(old) = &value.completion {
            if *old != reference {
                return Err(Error::Conflict(
                    "intent already completed by different evidence",
                ));
            }
            return Ok(value);
        }
        value.completion = Some(reference);
        tx.execute(
            "UPDATE intents SET value=?2 WHERE id=?1",
            params![value.operation_id.as_str(), encode(&value)?],
        )?;
        if value.desired == DesiredState::Destroyed {
            // A Destroyed guardian observation is the lifecycle postcondition
            // that releases this machine reservation. Runtime receipts and
            // other retained evidence remain governed by their own ledgers.
            tx.execute(
                "UPDATE sandboxes SET released=1 WHERE id=?1",
                [value.sandbox_id.as_str()],
            )?;
        }
        tx.commit()?;
        Ok(value)
    }

    pub fn revision(&self, sandbox: &SandboxId) -> Result<Counter> {
        revision(&self.db.connection, sandbox)
    }

    pub fn set_grant(&mut self, change: GrantChange, approval: Approval) -> Result<Grant> {
        let GrantChange {
            sandbox_id,
            id,
            expected_revision: expected,
            capability,
            scope_digest: scope,
            revoked,
        } = change;
        let sandbox = &sandbox_id;
        let request = digest(
            Domain::Grant,
            &(sandbox, &id, expected, capability, &scope, revoked),
        )?;
        if approval.request_digest != request {
            return Err(Error::Conflict("grant approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old_digest) = tx
            .query_row(
                "SELECT digest FROM approvals WHERE id=?1",
                [approval.id.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            if old_digest != request.as_str() {
                return Err(Error::Conflict("approval identity conflict"));
            }
            // A retry is observation, never reinstalling a prior revision after revocation.
            let old = get_grant(&tx, &id)?.ok_or(Error::Corrupt("approved grant is missing"))?;
            return Ok(old);
        }
        require_revision(&tx, sandbox, expected)?;
        if let Some(old) = get_grant(&tx, &id)? {
            if old.sandbox_id != *sandbox
                || old.capability != capability
                || old.scope_digest != scope
                || old.revoked
                || !revoked
            {
                return Err(Error::Conflict(
                    "grant identity cannot be reassigned or revived",
                ));
            }
        } else {
            if revoked {
                return Err(Error::Missing("cannot revoke a missing grant"));
            }
            capacity(&tx, "grants", self.limits.grants)?;
        }
        record_approval(&tx, &approval, self.limits.operations)?;
        let next = expected.next()?;
        let value = Grant {
            id,
            sandbox_id: sandbox.clone(),
            capability,
            scope_digest: scope,
            revision: next,
            revoked,
        };
        tx.execute("INSERT INTO grants VALUES (?1,?2,?3) ON CONFLICT(id) DO UPDATE SET value=excluded.value", params![value.id.as_str(), sandbox.as_str(), encode(&value)?])?;
        tx.execute(
            "UPDATE sandboxes SET revision=?2 WHERE id=?1",
            params![sandbox.as_str(), next.get()],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn grant(&self, id: &GrantId) -> Result<Option<Grant>> {
        get_grant(&self.db.connection, id)
    }

    /// Validate an application precondition against the host's authoritative
    /// grant record. Returning the grant does not delegate it or create a
    /// second authority store.
    pub fn require_grant(
        &self,
        sandbox: &SandboxId,
        expected_revision: Counter,
        id: &GrantId,
        capability: Capability,
        scope: &Digest,
    ) -> Result<Grant> {
        require_revision(&self.db.connection, sandbox, expected_revision)?;
        let grant = self
            .grant(id)?
            .ok_or(Error::Missing("host grant is missing"))?;
        if grant.revoked
            || &grant.sandbox_id != sandbox
            || grant.capability != capability
            || &grant.scope_digest != scope
            || grant.revision > expected_revision
        {
            return Err(Error::Conflict(
                "host grant does not authorize this observation",
            ));
        }
        Ok(grant)
    }

    pub fn active_grant(
        &self,
        sandbox: &SandboxId,
        expected_revision: Counter,
        capability: Capability,
        scope: &Digest,
    ) -> Result<Grant> {
        require_revision(&self.db.connection, sandbox, expected_revision)?;
        let mut statement = self
            .db
            .connection
            .prepare("SELECT value FROM grants WHERE sandbox=?1 ORDER BY id ASC")?;
        let mut matched = None;
        for value in statement.query_map([sandbox.as_str()], |row| row.get::<_, String>(0))? {
            let grant: Grant = decode(&value?)?;
            if !grant.revoked && grant.capability == capability && &grant.scope_digest == scope {
                if matched.is_some() {
                    return Err(Error::Conflict(
                        "multiple active grants match the requested authority",
                    ));
                }
                matched = Some(grant);
            }
        }
        matched.ok_or(Error::Missing("matching host grant is missing"))
    }

    pub fn authorize(
        &self,
        mutation: Mutation,
        capability: Capability,
        scope: &Digest,
    ) -> Result<AuthorizedMutation> {
        mutation.validate()?;
        if mutation.required_capability() != capability {
            return Err(Error::Conflict(
                "mutation request does not match the requested capability",
            ));
        }
        require_revision(
            &self.db.connection,
            &mutation.sandbox_id,
            mutation.expected_revision,
        )?;
        let latest: String = self.db.connection.query_row(
            "SELECT value FROM intents WHERE sandbox=?1 ORDER BY rowid DESC LIMIT 1",
            [mutation.sandbox_id.as_str()],
            |r| r.get(0),
        )?;
        if decode::<LifecycleIntent>(&latest)?.desired != DesiredState::Running {
            return Err(Error::Conflict(
                "host lifecycle intent gates new workload operations",
            ));
        }
        let grant = self
            .grant(&mutation.grant_id)?
            .ok_or(Error::Missing("host grant is missing"))?;
        if grant.revoked
            || grant.sandbox_id != mutation.sandbox_id
            || grant.capability != capability
            || grant.scope_digest != *scope
        {
            return Err(Error::Conflict(
                "host grant does not authorize this operation",
            ));
        }
        self.authority
            .authorize_mutation(mutation, capability, scope.clone(), grant.revision)
    }

    pub fn authorize_output_loss(
        &mut self,
        sandbox: &SandboxId,
        process: &ProcessId,
        receipt: &Digest,
        output: &OutputBoundary,
        approval: Approval,
    ) -> Result<AuthorizedLoss> {
        let binding = digest(
            Domain::Release,
            &(sandbox, process, receipt, output, "loss"),
        )?;
        if approval.request_digest != binding {
            return Err(Error::Conflict(
                "loss approval must bind the sandbox and complete evidence scope",
            ));
        }
        let tx = self.db.connection.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sandboxes WHERE id=?1)",
            [sandbox.as_str()],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::Missing(
                "loss decision has no host-owned sandbox identity",
            ));
        }
        if let Some(old) = tx
            .query_row(
                "SELECT digest FROM approvals WHERE id=?1",
                [approval.id.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
        {
            if old != binding.as_str() {
                return Err(Error::Conflict("loss approval identity conflict"));
            }
        } else {
            record_approval(&tx, &approval, self.limits.operations)?;
        }
        tx.commit()?;
        self.authority.authorize_loss(
            sandbox.clone(),
            process.clone(),
            receipt.clone(),
            output.clone(),
            approval.id,
            approval.request_digest,
        )
    }

    /// Usage IDs survive rollback. Repeated delivery cannot double-charge.
    pub fn account(
        &mut self,
        id: &OperationId,
        sandbox: &SandboxId,
        cpu: Counter,
        network: Counter,
    ) -> Result<()> {
        let identity = digest(Domain::Operation, &(sandbox, cpu, network))?;
        let tx = self.db.connection.transaction()?;
        if let Some(old) = tx
            .query_row("SELECT digest FROM usage WHERE id=?1", [id.as_str()], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
        {
            return if old == identity.as_str() {
                Ok(())
            } else {
                Err(Error::Conflict("usage identity conflict"))
            };
        }
        capacity(&tx, "usage", self.limits.usage_records)?;
        let (old_cpu, old_network): (u64, u64) = tx.query_row(
            "SELECT coalesce(sum(cpu),0),coalesce(sum(network),0) FROM usage",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Counter::try_from(old_cpu)?.checked_add(cpu.get())?;
        Counter::try_from(old_network)?.checked_add(network.get())?;
        tx.execute(
            "INSERT INTO usage VALUES (?1,?2,?3,?4,?5)",
            params![
                id.as_str(),
                sandbox.as_str(),
                identity.as_str(),
                cpu.get(),
                network.get()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn usage(&self, sandbox: &SandboxId) -> Result<(Counter, Counter)> {
        let (cpu, network): (u64, u64) = self.db.connection.query_row(
            "SELECT coalesce(sum(cpu),0),coalesce(sum(network),0) FROM usage WHERE sandbox=?1",
            [sandbox.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((cpu.try_into()?, network.try_into()?))
    }
}

fn sandbox_record(db: &rusqlite::Connection, sandbox: &SandboxId) -> Result<Option<SandboxRecord>> {
    let row = db
        .query_row(
            "SELECT image,resources,revision,released FROM sandboxes WHERE id=?1",
            [sandbox.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((image, resources, revision, released)) = row else {
        return Ok(None);
    };
    let latest: String = db.query_row(
        "SELECT value FROM intents WHERE sandbox=?1 ORDER BY rowid DESC LIMIT 1",
        [sandbox.as_str()],
        |row| row.get(0),
    )?;
    let reservation = match released {
        0 => ReservationState::Held,
        1 => ReservationState::Released,
        _ => return Err(Error::Corrupt("sandbox reservation flag is invalid")),
    };
    Ok(Some(SandboxRecord {
        id: sandbox.clone(),
        image_digest: image.try_into()?,
        resources: decode(&resources)?,
        configuration_revision: revision.try_into()?,
        reservation,
        latest_intent: decode(&latest)?,
    }))
}

fn revision(db: &rusqlite::Connection, sandbox: &SandboxId) -> Result<Counter> {
    let value = db
        .query_row(
            "SELECT revision FROM sandboxes WHERE id=?1 AND released=0",
            [sandbox.as_str()],
            |r| r.get::<_, u64>(0),
        )
        .optional()?
        .ok_or(Error::Missing("sandbox identity is missing or retired"))?;
    Ok(value.try_into()?)
}
fn require_revision(
    db: &rusqlite::Connection,
    sandbox: &SandboxId,
    expected: Counter,
) -> Result<()> {
    if revision(db, sandbox)? != expected {
        return Err(Error::Conflict("stale host configuration revision"));
    }
    Ok(())
}
fn intent(db: &rusqlite::Connection, operation: &OperationId) -> Result<Option<LifecycleIntent>> {
    db.query_row(
        "SELECT value FROM intents WHERE id=?1",
        [operation.as_str()],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|s| decode(&s))
    .transpose()
}
fn get_grant(db: &rusqlite::Connection, id: &GrantId) -> Result<Option<Grant>> {
    db.query_row("SELECT value FROM grants WHERE id=?1", [id.as_str()], |r| {
        r.get::<_, String>(0)
    })
    .optional()?
    .map(|s| decode(&s))
    .transpose()
}

fn image_record(db: &rusqlite::Connection, digest: &Digest) -> Result<Option<ImageRecord>> {
    db.query_row(
        "SELECT value FROM images WHERE digest=?1",
        [digest.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| decode(&value))
    .transpose()
}

fn image_import(
    db: &rusqlite::Connection,
    operation: &OperationId,
) -> Result<Option<ImageImportRecord>> {
    let row: Option<(String, String, Option<String>)> = db
        .query_row(
            "SELECT request_digest,phase,image FROM image_imports WHERE operation=?1",
            [operation.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(request_digest, phase, image)| {
        let image = image
            .map(|digest| {
                image_record(db, &Digest::try_from(digest)?)?
                    .ok_or(Error::Corrupt("published image import has no image record"))
            })
            .transpose()?;
        let phase: ImageImportPhase = decode(&phase)?;
        if (phase == ImageImportPhase::Published) != image.is_some() {
            return Err(Error::Corrupt("image import phase and result disagree"));
        }
        Ok(ImageImportRecord {
            operation_id: operation.clone(),
            request_digest: request_digest.try_into()?,
            phase,
            image,
        })
    })
    .transpose()
}
fn save_intent(db: &rusqlite::Connection, value: &LifecycleIntent) -> Result<()> {
    db.execute(
        "INSERT INTO intents VALUES (?1,?2,?3,?4)",
        params![
            value.operation_id.as_str(),
            value.sandbox_id.as_str(),
            value.request_digest.as_str(),
            encode(value)?
        ],
    )?;
    Ok(())
}
pub(crate) fn capacity(
    db: &rusqlite::Connection,
    table: &'static str,
    limit: Counter,
) -> Result<()> {
    // Table names originate only from this crate, never from protocol strings.
    let count: u64 = db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
    if count >= limit.get() {
        return Err(Error::Capacity(
            "durable identity capacity exhausted; no evidence evicted",
        ));
    }
    Ok(())
}
fn record_approval(db: &rusqlite::Connection, approval: &Approval, limit: Counter) -> Result<()> {
    capacity(db, "approvals", limit)?;
    db.execute(
        "INSERT INTO approvals VALUES (?1,?2)",
        params![approval.id.as_str(), approval.request_digest.as_str()],
    )?;
    Ok(())
}
