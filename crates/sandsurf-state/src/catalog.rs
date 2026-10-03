use crate::{
    Error, ImageImportInput, Result, authority::HostAuthority, database::Database, decode, encode,
};
use rusqlite::{OptionalExtension, params};
use sandsurf_protocol::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE configuration(id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, limits TEXT NOT NULL, authority TEXT NOT NULL) STRICT;
CREATE TABLE machines(id TEXT PRIMARY KEY, image TEXT NOT NULL, configuration TEXT NOT NULL, defaults TEXT NOT NULL, lifetime TEXT NOT NULL, activity INTEGER NOT NULL, revision INTEGER NOT NULL, sensitive INTEGER NOT NULL CHECK(sensitive IN (0,1)), released INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE INDEX active_machines ON machines(id) WHERE released=0;
CREATE TABLE intents(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE INDEX completed_lifecycle_intents ON intents(machine) WHERE json_extract(value,'$.completion') IS NOT NULL;
CREATE TABLE configuration_operations(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE transfer_operations(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE usage(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), digest TEXT NOT NULL, cpu INTEGER NOT NULL, network INTEGER NOT NULL) STRICT;
CREATE TABLE approvals(id TEXT PRIMARY KEY, digest TEXT NOT NULL) STRICT;
CREATE TABLE image_imports(operation TEXT PRIMARY KEY, request_digest TEXT NOT NULL, input TEXT NOT NULL, dependency_image TEXT REFERENCES images(digest), dependency_snapshot TEXT REFERENCES snapshots(id), phase TEXT NOT NULL, candidate TEXT, image TEXT, candidate_cleanup_pending INTEGER NOT NULL CHECK(candidate_cleanup_pending IN (0,1)),
 CHECK(candidate_cleanup_pending=0 OR json_extract(phase,'$')='published'),
 CHECK((json_extract(phase,'$') IN ('admitted','cancelling','cancelled') AND candidate IS NULL AND image IS NULL) OR (json_extract(phase,'$')='prepared' AND candidate IS NOT NULL AND image IS NULL) OR (json_extract(phase,'$')='published' AND candidate IS NULL AND image IS NOT NULL))) STRICT;
CREATE INDEX pending_image_imports ON image_imports(operation) WHERE json_extract(phase,'$') NOT IN ('published','cancelled');
CREATE INDEX pending_import_image ON image_imports(dependency_image) WHERE json_extract(phase,'$') NOT IN ('published','cancelled');
CREATE INDEX pending_import_snapshot ON image_imports(dependency_snapshot) WHERE json_extract(phase,'$') NOT IN ('published','cancelled');
CREATE INDEX prepared_image_target ON image_imports(json_extract(candidate,'$.digest')) WHERE json_extract(phase,'$')='prepared';
CREATE INDEX pending_candidate_cleanup ON image_imports(operation) WHERE candidate_cleanup_pending=1;
CREATE TABLE images(digest TEXT PRIMARY KEY, value TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE image_releases(operation TEXT PRIMARY KEY, image TEXT NOT NULL REFERENCES images(digest), request_digest TEXT NOT NULL, cleanup_pending INTEGER NOT NULL) STRICT;
CREATE INDEX pending_image_releases ON image_releases(operation) WHERE cleanup_pending=1;
CREATE UNIQUE INDEX pending_image_cleanup ON image_releases(image) WHERE cleanup_pending=1;
CREATE TABLE secret_deliveries(operation TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE INDEX secret_delivery_version ON secret_deliveries(machine,json_extract(value,'$.delivery.secret.id'),json_extract(value,'$.delivery.secret.version'),operation) WHERE json_extract(value,'$.disclosure')<>'not-sent';
CREATE TABLE secret_revocations(operation TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE INDEX secret_revocation_version ON secret_revocations(machine,json_extract(value,'$.secret.id'),json_extract(value,'$.secret.version'));
CREATE TABLE secret_puts(operation TEXT PRIMARY KEY, request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE snapshots(id TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL, machine TEXT NOT NULL REFERENCES machines(id), value TEXT NOT NULL) STRICT;
CREATE INDEX capturing_disk_snapshots ON snapshots(id) WHERE json_extract(value,'$.phase')='capturing' AND json_extract(value,'$.request.kind')='disk';
CREATE INDEX snapshot_image ON snapshots(json_extract(value,'$.imageDigest'));
CREATE INDEX retained_snapshot_capacity ON snapshots(machine) WHERE json_extract(value,'$.phase') IS NOT 'released';
CREATE TABLE snapshot_releases(operation TEXT PRIMARY KEY, snapshot TEXT UNIQUE NOT NULL REFERENCES snapshots(id), value TEXT NOT NULL) STRICT;
CREATE INDEX pending_snapshot_releases ON snapshot_releases(operation) WHERE json_extract(value,'$.cleanupPending')=1;
CREATE TABLE rollbacks(operation TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), value TEXT NOT NULL) STRICT;
CREATE UNIQUE INDEX pending_rollback_machine ON rollbacks(machine) WHERE json_extract(value,'$.phase') IS NOT 'applied';
CREATE INDEX pending_rollback_snapshot ON rollbacks(json_extract(value,'$.snapshotId')) WHERE json_extract(value,'$.phase') IS NOT 'applied';
CREATE TABLE usage_observations(machine TEXT PRIMARY KEY REFERENCES machines(id), generation INTEGER NOT NULL, raw TEXT NOT NULL, cumulative TEXT NOT NULL) STRICT;
CREATE TABLE suspension_captures(snapshot TEXT PRIMARY KEY REFERENCES snapshots(id), lifecycle TEXT UNIQUE NOT NULL REFERENCES intents(id)) STRICT;
CREATE TABLE forks(machine TEXT PRIMARY KEY REFERENCES machines(id), operation TEXT UNIQUE NOT NULL REFERENCES intents(id), snapshot TEXT NOT NULL REFERENCES snapshots(id), value TEXT NOT NULL) STRICT;
CREATE INDEX pending_fork_snapshot ON forks(snapshot,machine) WHERE json_extract(value,'$.materializedDisk') IS NULL;
";

// Suspension is derived from one captured-input relationship and lifecycle
// completion. There is no separately installed/cleared suspension authority
// and no crash window after committing the native lifecycle reference.
const SUSPENSION_INPUTS: &str = "SELECT c.snapshot,i.id AS lifecycle,i.machine,json_extract(i.value,'$.completion') AS completed FROM suspension_captures c JOIN intents i ON c.lifecycle=i.id WHERE NOT EXISTS(SELECT 1 FROM intents newer WHERE newer.machine=i.machine AND newer.rowid>i.rowid AND json_extract(newer.value,'$.completion') IS NOT NULL)";

const SECRET_CLEANUP_SELECTION: &str = "SELECT value FROM secret_deliveries WHERE machine=?1 AND json_extract(value,'$.delivery.secret.id')=?2 AND json_extract(value,'$.delivery.secret.version')=?3 AND json_extract(value,'$.disclosure')<>'not-sent' ORDER BY operation LIMIT 1025";
const SECRET_REVOCATION_OBSERVATION: &str = "SELECT operation,value FROM secret_revocations WHERE machine=?1 AND json_extract(value,'$.secret.id')=?2 AND json_extract(value,'$.secret.version')=?3 ORDER BY rowid LIMIT 1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogLimits {
    pub identities: Counter,
    pub operations: Counter,
    pub usage_records: Counter,
    pub image_bytes: Counter,
    /// Shared scheduling and RAM capacity only. Machine disks, snapshots,
    /// output and network queues belong to independently enforced machine
    /// envelopes, not to the host image/catalog volume.
    pub cpu_quota_micros: Counter,
    pub host_memory_bytes: Counter,
}

/// Trusted host-side authorization decision. Not accepted as a guest API message.
#[derive(Debug, Clone)]
pub struct Approval {
    pub id: CommitmentId,
    pub request_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostConfigurationOperation {
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub request_digest: Digest,
    pub revision: Counter,
    pub configuration: RuntimeConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTransferOperation {
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub request_digest: Digest,
    pub approval_id: Option<CommitmentId>,
    pub applied: bool,
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
    /// Host cancellation intent. Original native/storage owners still pin inputs.
    Cancelling,
    /// Private materialization bytes were reclaimed under original custody.
    Cancelled,
    Prepared,
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
    pub storage_bytes: Counter,
    pub provenance_digest: Digest,
    pub sensitive: bool,
}

/// Host-owned creation intent. Storage publication and clone customization
/// must complete before any Running authorization is issued for this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForkRecord {
    pub machine_id: MachineId,
    pub operation_id: OperationId,
    pub snapshot_id: SnapshotId,
    pub request_digest: Digest,
    pub materialized_disk: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageReleaseRecord {
    pub operation_id: OperationId,
    pub image_digest: Digest,
    pub request_digest: Digest,
    pub cleanup_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotReleaseRecord {
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub snapshot_id: SnapshotId,
    pub request_digest: Digest,
    pub cleanup_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageImportRecord {
    pub operation_id: OperationId,
    pub request_digest: Digest,
    pub phase: ImageImportPhase,
    pub image: Option<ImageRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretDeliveryRecord {
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub request_digest: Digest,
    pub delivery: SecretDelivery,
    pub disclosure: SecretDisclosure,
    pub revocation_operation: Option<OperationId>,
    pub revoked: bool,
}

/// Approval input, not an application-supplied disclosure/revocation state.
#[derive(Debug, Clone)]
pub struct SecretDeliveryAdmission {
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub request_digest: Digest,
    pub delivery: SecretDelivery,
}

/// Only delivery facts are persisted here. Revocation has exactly one owner:
/// the version/audience decision in secret_revocations. Public delivery views
/// derive their current revocation reference from that decision.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredSecretDelivery {
    operation_id: OperationId,
    machine_id: MachineId,
    request_digest: Digest,
    delivery: SecretDelivery,
    disclosure: SecretDisclosure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretPutRecord {
    pub operation_id: OperationId,
    pub request_digest: Digest,
    pub secret: SecretVersion,
    pub applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretRevocationRecord {
    pub operation_id: OperationId,
    pub machine_id: MachineId,
    pub request_digest: Digest,
    pub secret: SecretVersion,
    pub deliveries: Vec<SecretDelivery>,
    /// Bounded cooperative cleanup targets, not the scope of host revocation.
    /// False means more known disclosures exist than this selection covers.
    pub cleanup_selection_complete: bool,
    pub terminate_recipients: bool,
    pub guest_cleanup_report: Option<SecretCleanupReport>,
}

#[derive(Debug, Clone)]
pub struct SecretRevocationAdmission {
    pub machine_id: MachineId,
    pub operation_id: OperationId,
    pub expected_revision: Counter,
    pub secret: SecretVersion,
    pub terminate_recipients: bool,
    pub request_digest: Digest,
}

/// Host-owned identity, configuration, and reservation facts. Machine state is
/// deliberately absent: callers obtain that separately from the guardian.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MachineRecord {
    pub id: MachineId,
    pub image_digest: Digest,
    pub runtime_configuration: RuntimeConfiguration,
    pub execution_defaults: ExecutionDefaults,
    pub lifetime: MachineLifetime,
    pub last_activity_unix_millis: Counter,
    pub configuration_revision: Counter,
    pub reservation: ReservationState,
    /// Sticky host classification: possible disclosure or inherited sensitive storage.
    /// False is not an attestation that an administrator has stored no secrets.
    pub known_sensitive: bool,
    pub latest_intent: LifecycleIntent,
}

/// Derived resumable-input view, never a separately persisted state owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspensionRecord {
    pub machine_id: MachineId,
    pub lifecycle_operation_id: OperationId,
    pub snapshot_id: SnapshotId,
    pub manifest_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAdmission {
    pub id: MachineId,
    pub image: Digest,
    pub resources: Resources,
    pub defaults: ExecutionDefaults,
    /// Host-verified metadata from the exact admitted immutable image.
    /// Resolved preferences are persisted once; later reads need no image.
    pub image_defaults: ExecutionDefaults,
    pub lifetime: MachineLifetime,
    pub operation: OperationId,
}

/// Immutable host-authority result for reconciling a caller operation ID.
/// Machine observations and defaults effects remain in the guardian journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum HostOperationRecord {
    Lifecycle(LifecycleIntent),
    Configuration(HostConfigurationOperation),
    Transfer(HostTransferOperation),
    ImageImport(ImageImportRecord),
    ImageRelease(ImageReleaseRecord),
    SecretDelivery(SecretDeliveryRecord),
    SecretPut(SecretPutRecord),
    SecretRevocation(SecretRevocationRecord),
    Snapshot(Box<Snapshot>),
    SnapshotRelease(SnapshotReleaseRecord),
    Rollback(RollbackRecord),
}

impl HostOperationRecord {
    pub fn machine_id(&self) -> Option<&MachineId> {
        match self {
            Self::Lifecycle(value) => Some(&value.machine_id),
            Self::Configuration(value) => Some(&value.machine_id),
            Self::Transfer(value) => Some(&value.machine_id),
            Self::SecretDelivery(value) => Some(&value.machine_id),
            Self::SecretRevocation(value) => Some(&value.machine_id),
            Self::Snapshot(value) => Some(&value.request.machine_id),
            Self::SnapshotRelease(value) => Some(&value.machine_id),
            Self::Rollback(value) => Some(&value.machine_id),
            Self::ImageImport(_) | Self::ImageRelease(_) | Self::SecretPut(_) => None,
        }
    }
}

pub struct HostCatalog {
    db: Database,
    host: HostId,
    limits: CatalogLimits,
    authority: HostAuthority,
}

impl HostCatalog {
    pub fn create(path: &Path, host: HostId, limits: CatalogLimits) -> Result<Self> {
        if [
            limits.identities,
            limits.operations,
            limits.usage_records,
            limits.image_bytes,
            limits.cpu_quota_micros,
            limits.host_memory_bytes,
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
        let db = Database::open(path, "host", SCHEMA)?;
        let orphaned: bool = db.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM machines m LEFT JOIN images i ON m.image=i.digest WHERE m.released=0 AND (i.digest IS NULL OR i.retired<>0))",
            [], |row| row.get(0),
        )?;
        if orphaned {
            return Err(Error::Corrupt(
                "active machine has no admitted image; catalog preserved intact",
            ));
        }
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

    pub fn operation(&self, operation: &OperationId) -> Result<Option<HostOperationRecord>> {
        let db = &self.db.connection;
        let mut result = Vec::new();
        if let Some(value) = intent(db, operation)? {
            result.push(HostOperationRecord::Lifecycle(value));
        }
        if let Some(value) = db
            .query_row(
                "SELECT value FROM configuration_operations WHERE id=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::Configuration(decode(&value)?));
        }
        if let Some(value) = db
            .query_row(
                "SELECT value FROM transfer_operations WHERE id=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::Transfer(decode(&value)?));
        }
        if let Some(value) = image_import(db, operation)? {
            result.push(HostOperationRecord::ImageImport(value));
        }
        if let Some(value) = image_release(db, operation)? {
            result.push(HostOperationRecord::ImageRelease(value));
        }
        if let Some(value) = snapshot_release(db, operation)? {
            result.push(HostOperationRecord::SnapshotRelease(value));
        }
        if let Some(value) = db
            .query_row(
                "SELECT value FROM secret_deliveries WHERE operation=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::SecretDelivery(
                observe_secret_delivery(db, decode(&value)?)?,
            ));
        }
        if let Some(value) = db
            .query_row(
                "SELECT value FROM secret_puts WHERE operation=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::SecretPut(decode(&value)?));
        }
        if let Some(value) = db
            .query_row(
                "SELECT value FROM secret_revocations WHERE operation=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::SecretRevocation(decode(&value)?));
        }
        if let Some(value) = db
            .query_row(
                "SELECT value FROM snapshots WHERE operation=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::Snapshot(Box::new(decode(&value)?)));
        }
        if let Some(value) = db
            .query_row(
                "SELECT value FROM rollbacks WHERE operation=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::Rollback(decode(&value)?));
        }
        match result.len() {
            0 => Ok(None),
            1 => Ok(result.pop()),
            _ => Err(Error::Corrupt(
                "host operation identity is bound to multiple authorities",
            )),
        }
    }

    pub fn admit_transfer_operation(
        &mut self,
        operation_id: OperationId,
        machine_id: MachineId,
        request_digest: Digest,
        approval: Option<Approval>,
    ) -> Result<HostTransferOperation> {
        if approval
            .as_ref()
            .is_some_and(|approval| approval.request_digest != request_digest)
        {
            return Err(Error::Conflict(
                "transfer approval does not bind its request",
            ));
        }
        let approval_id = approval.as_ref().map(|approval| approval.id.clone());
        let tx = self.db.connection.transaction()?;
        if let Some(raw) = tx
            .query_row(
                "SELECT value FROM transfer_operations WHERE id=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: HostTransferOperation = decode(&raw)?;
            return if old.machine_id == machine_id
                && old.request_digest == request_digest
                && old.approval_id == approval_id
            {
                Ok(old)
            } else {
                Err(Error::Conflict("transfer operation identity conflict"))
            };
        }
        host_operation_identity_available(&tx, &operation_id)?;
        capacity(&tx, "transfer_operations", self.limits.operations)?;
        if let Some(approval) = approval {
            record_approval(&tx, &approval, self.limits.operations)?;
        }
        let value = HostTransferOperation {
            operation_id,
            machine_id,
            request_digest,
            approval_id,
            applied: false,
        };
        tx.execute(
            "INSERT INTO transfer_operations VALUES (?1,?2,?3,?4)",
            params![
                value.operation_id.as_str(),
                value.machine_id.as_str(),
                value.request_digest.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn complete_transfer_operation(
        &mut self,
        operation_id: &OperationId,
        request_digest: &Digest,
    ) -> Result<HostTransferOperation> {
        let tx = self.db.connection.transaction()?;
        let raw: String = tx.query_row(
            "SELECT value FROM transfer_operations WHERE id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )?;
        let mut value: HostTransferOperation = decode(&raw)?;
        if value.request_digest != *request_digest {
            return Err(Error::Conflict("transfer request digest changed"));
        }
        if !value.applied {
            value.applied = true;
            tx.execute(
                "UPDATE transfer_operations SET value=?2 WHERE id=?1",
                params![operation_id.as_str(), encode(&value)?],
            )?;
        }
        tx.commit()?;
        Ok(value)
    }

    pub fn admit_secret_put(
        &mut self,
        operation_id: OperationId,
        request_digest: Digest,
        secret: SecretVersion,
        approval: Approval,
    ) -> Result<SecretPutRecord> {
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("secret put approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(raw) = tx
            .query_row(
                "SELECT value FROM secret_puts WHERE operation=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: SecretPutRecord = decode(&raw)?;
            return if old.request_digest == request_digest && old.secret == secret {
                Ok(old)
            } else {
                Err(Error::Conflict("secret put operation identity conflict"))
            };
        }
        host_operation_identity_available(&tx, &operation_id)?;
        capacity(&tx, "secret_puts", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let value = SecretPutRecord {
            operation_id,
            request_digest,
            secret,
            applied: false,
        };
        tx.execute(
            "INSERT INTO secret_puts VALUES (?1,?2,?3)",
            params![
                value.operation_id.as_str(),
                value.request_digest.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn complete_secret_put(
        &mut self,
        operation_id: &OperationId,
        request_digest: &Digest,
        secret: &SecretVersion,
    ) -> Result<SecretPutRecord> {
        let tx = self.db.connection.transaction()?;
        let raw: String = tx.query_row(
            "SELECT value FROM secret_puts WHERE operation=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )?;
        let mut value: SecretPutRecord = decode(&raw)?;
        if value.request_digest != *request_digest || value.secret != *secret {
            return Err(Error::Conflict("secret put completion changed"));
        }
        if !value.applied {
            value.applied = true;
            tx.execute(
                "UPDATE secret_puts SET value=?2 WHERE operation=?1",
                params![operation_id.as_str(), encode(&value)?],
            )?;
        }
        tx.commit()?;
        Ok(value)
    }

    pub fn admit_secret_delivery(
        &mut self,
        admission: SecretDeliveryAdmission,
        expected_revision: Counter,
        approval: Approval,
    ) -> Result<SecretDeliveryRecord> {
        let record = StoredSecretDelivery {
            operation_id: admission.operation_id,
            machine_id: admission.machine_id,
            request_digest: admission.request_digest,
            delivery: admission.delivery,
            disclosure: SecretDisclosure::NotSent,
        };
        record.delivery.validate()?;
        if approval.request_digest != record.request_digest {
            return Err(Error::Conflict("secret delivery approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(encoded) = tx
            .query_row(
                "SELECT value FROM secret_deliveries WHERE operation=?1",
                [record.operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: StoredSecretDelivery = decode(&encoded)?;
            if old.request_digest == record.request_digest {
                return observe_secret_delivery(&tx, old);
            }
            return Err(Error::Conflict(
                "secret delivery operation identity conflict",
            ));
        }
        host_operation_identity_available(&tx, &record.operation_id)?;
        require_revision(&tx, &record.machine_id, expected_revision)?;
        if secret_version_revoked(&tx, &record.machine_id, &record.delivery.secret)? {
            return Err(Error::Conflict(
                "secret delivery starts undisclosed and requires unrevoked host authority",
            ));
        }
        record_approval(&tx, &approval, self.limits.operations)?;
        tx.execute(
            "INSERT INTO secret_deliveries(operation,machine,request_digest,value) VALUES (?1,?2,?3,?4)",
            params![
                record.operation_id.as_str(),
                record.machine_id.as_str(),
                record.request_digest.as_str(),
                encode(&record)?
            ],
        )?;
        tx.commit()?;
        observe_secret_delivery(&self.db.connection, record)
    }

    pub fn begin_secret_disclosure(
        &mut self,
        operation: &OperationId,
        request: &Digest,
    ) -> Result<SecretDeliveryRecord> {
        let tx = self.db.connection.transaction()?;
        let raw: String = tx.query_row(
            "SELECT value FROM secret_deliveries WHERE operation=?1 AND request_digest=?2",
            params![operation.as_str(), request.as_str()],
            |row| row.get(0),
        )?;
        let mut record: StoredSecretDelivery = decode(&raw)?;
        if record.disclosure != SecretDisclosure::NotSent
            || secret_version_revoked(&tx, &record.machine_id, &record.delivery.secret)?
        {
            return Err(Error::Conflict(
                "secret disclosure is already dispatched or revoked; reconcile without redelivery",
            ));
        }
        record.disclosure = SecretDisclosure::Possible;
        tx.execute(
            "UPDATE machines SET sensitive=1 WHERE id=?1",
            [record.machine_id.as_str()],
        )?;
        tx.execute(
            "UPDATE secret_deliveries SET value=?2 WHERE operation=?1",
            params![operation.as_str(), encode(&record)?],
        )?;
        tx.commit()?;
        observe_secret_delivery(&self.db.connection, record)
    }

    pub fn complete_secret_delivery(
        &mut self,
        operation: &OperationId,
        request: &Digest,
    ) -> Result<SecretDeliveryRecord> {
        let tx = self.db.connection.transaction()?;
        let raw: String = tx.query_row(
            "SELECT value FROM secret_deliveries WHERE operation=?1 AND request_digest=?2",
            params![operation.as_str(), request.as_str()],
            |row| row.get(0),
        )?;
        let mut record: StoredSecretDelivery = decode(&raw)?;
        if record.disclosure == SecretDisclosure::NotSent {
            return Err(Error::Conflict(
                "guest receipt cannot precede the durable disclosure boundary",
            ));
        }
        record.disclosure = SecretDisclosure::GuestReportedReceived;
        tx.execute(
            "UPDATE secret_deliveries SET value=?2 WHERE operation=?1",
            params![operation.as_str(), encode(&record)?],
        )?;
        tx.commit()?;
        observe_secret_delivery(&self.db.connection, record)
    }

    pub fn secret_version_revoked(
        &self,
        machine: &MachineId,
        secret: &SecretVersion,
    ) -> Result<bool> {
        secret_version_revoked(&self.db.connection, machine, secret)
    }

    pub fn admit_secret_revocation(
        &mut self,
        request: SecretRevocationAdmission,
        approval: Approval,
    ) -> Result<SecretRevocationRecord> {
        if approval.request_digest != request.request_digest {
            return Err(Error::Conflict("secret revocation approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(encoded) = tx
            .query_row(
                "SELECT value FROM secret_revocations WHERE operation=?1",
                [request.operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: SecretRevocationRecord = decode(&encoded)?;
            return if old.request_digest == request.request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict(
                    "secret revocation operation identity conflict",
                ))
            };
        }
        host_operation_identity_available(&tx, &request.operation_id)?;
        require_revision(&tx, &request.machine_id, request.expected_revision)?;
        let mut statement = tx.prepare(SECRET_CLEANUP_SELECTION)?;
        let mut rows = statement.query(params![
            request.machine_id.as_str(),
            request.secret.id.as_str(),
            request.secret.version.as_str()
        ])?;
        let mut deliveries = Vec::new();
        let mut selection_bytes = 0_usize;
        let mut cleanup_selection_complete = true;
        while let Some(row) = rows.next()? {
            let record: StoredSecretDelivery = decode(&row.get::<_, String>(0)?)?;
            if record.delivery.secret != request.secret || record.machine_id != request.machine_id {
                return Err(Error::Corrupt("secret cleanup selection binding changed"));
            }
            let bytes = encode(&record.delivery)?.len() + 1;
            // Leave bounded room for host/wire envelopes and cleanup evidence.
            // Authority must commit even when cooperative targets do not fit.
            if deliveries.len() == 1024
                || bytes > sandsurf_protocol::MAX_CONTROL_BYTES - 16 * 1024 - selection_bytes
            {
                cleanup_selection_complete = false;
                break;
            }
            selection_bytes += bytes;
            deliveries.push(record.delivery);
        }
        drop(rows);
        drop(statement);
        capacity(&tx, "secret_revocations", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let record = SecretRevocationRecord {
            operation_id: request.operation_id,
            machine_id: request.machine_id,
            request_digest: request.request_digest,
            secret: request.secret,
            deliveries,
            cleanup_selection_complete,
            terminate_recipients: request.terminate_recipients,
            guest_cleanup_report: None,
        };
        tx.execute(
            "INSERT INTO secret_revocations(operation,machine,request_digest,value) VALUES (?1,?2,?3,?4)",
            params![
                record.operation_id.as_str(),
                record.machine_id.as_str(),
                record.request_digest.as_str(),
                encode(&record)?
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    /// Record an untrusted cleanup observation. Host revocation already took effect.
    pub fn record_secret_cleanup_report(
        &mut self,
        operation_id: &OperationId,
        request_digest: &Digest,
        report: SecretCleanupReport,
    ) -> Result<SecretRevocationRecord> {
        let tx = self.db.connection.transaction()?;
        let raw: String = tx.query_row(
            "SELECT value FROM secret_revocations WHERE operation=?1 AND request_digest=?2",
            params![operation_id.as_str(), request_digest.as_str()],
            |row| row.get(0),
        )?;
        let mut record: SecretRevocationRecord = decode(&raw)?;
        if let Some(old) = &record.guest_cleanup_report {
            return if old == &report {
                Ok(record)
            } else {
                Err(Error::Conflict(
                    "cleanup observation identity already recorded",
                ))
            };
        }
        record.guest_cleanup_report = Some(report);
        tx.execute(
            "UPDATE secret_revocations SET value=?2 WHERE operation=?1",
            params![operation_id.as_str(), encode(&record)?],
        )?;
        tx.commit()?;
        Ok(record)
    }

    /// Admit an image command before any source is read or builder is run.
    /// Atomically bind executable intent and its storage dependencies to the
    /// approval. Workers receive facts; they never reconstruct authority from
    /// filesystem job files. Source addresses do not imply source-byte custody.
    pub fn admit_image_import(
        &mut self,
        operation_id: OperationId,
        input: ImageImportInput,
        approval: Approval,
    ) -> Result<ImageImportRecord> {
        let request_digest = input.request_digest(&operation_id)?;
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("image import approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = image_import(&tx, &operation_id)? {
            return if old.request_digest == request_digest
                && image_import_input(&tx, &operation_id)?.as_ref() == Some(&input)
            {
                Ok(old)
            } else {
                Err(Error::Conflict("image import operation identity conflict"))
            };
        }
        host_operation_identity_available(&tx, &operation_id)?;
        let (dependency_image, dependency_snapshot) = match &input {
            ImageImportInput::Native {
                manifest_digest, ..
            } => (
                image_state(&tx, manifest_digest)?
                    .filter(|(_, retired, _)| !retired)
                    .map(|_| manifest_digest.clone()),
                None,
            ),
            ImageImportInput::Oci { recipe, .. } => {
                require_image(&tx, &recipe.boot_image_digest)?;
                (Some(recipe.boot_image_digest.clone()), None)
            }
            ImageImportInput::PublishSnapshot {
                snapshot: expected,
                allow_sensitive,
            } => {
                let retained = snapshot_record(&tx, &expected.request.id)?
                    .ok_or(Error::Missing("image snapshot does not exist"))?;
                if retained != **expected || retained.phase != SnapshotPhase::Ready {
                    return Err(Error::Conflict(
                        "image publication requires the exact ready snapshot",
                    ));
                }
                if retained.sensitive && !allow_sensitive {
                    return Err(Error::Conflict(
                        "sensitive snapshot publication needs explicit authorization",
                    ));
                }
                require_image(&tx, &retained.image_digest)?;
                (Some(retained.image_digest), Some(retained.request.id))
            }
        };
        capacity(&tx, "image_imports", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let value = ImageImportRecord {
            operation_id,
            request_digest,
            phase: ImageImportPhase::Admitted,
            image: None,
        };
        tx.execute(
            "INSERT INTO image_imports VALUES (?1,?2,?3,?4,?5,?6,NULL,NULL,0)",
            params![
                value.operation_id.as_str(),
                value.request_digest.as_str(),
                encode(&input)?,
                dependency_image.as_ref().map(Digest::as_str),
                dependency_snapshot.as_ref().map(SnapshotId::as_str),
                encode(&value.phase)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Cancel before candidate adoption. Prepared candidates have crossed the
    /// catalog's publication boundary and finish through publication/release.
    /// Client disconnect and worker failure never imply this explicit intent.
    pub fn cancel_image_import(
        &mut self,
        operation: &OperationId,
        expected_request: &Digest,
    ) -> Result<ImageImportRecord> {
        let tx = self.db.connection.transaction()?;
        let old = image_import(&tx, operation)?
            .ok_or(Error::Missing("image import operation is missing"))?;
        if old.request_digest != *expected_request {
            return Err(Error::Conflict(
                "image cancellation request binding changed",
            ));
        }
        match old.phase {
            ImageImportPhase::Cancelling | ImageImportPhase::Cancelled => return Ok(old),
            ImageImportPhase::Prepared | ImageImportPhase::Published => {
                return Err(Error::Conflict(
                    "image candidate was already adopted for publication",
                ));
            }
            ImageImportPhase::Admitted => {}
        }
        tx.execute(
            "UPDATE image_imports SET phase=?2 WHERE operation=?1",
            params![operation.as_str(), encode(&ImageImportPhase::Cancelling)?],
        )?;
        tx.commit()?;
        Ok(ImageImportRecord {
            phase: ImageImportPhase::Cancelling,
            ..old
        })
    }

    /// Called only after the cancellation effect retains original worker and
    /// materializer custody through this transaction's commit.
    pub fn complete_image_cancellation(
        &mut self,
        operation: &OperationId,
        expected_request: &Digest,
    ) -> Result<ImageImportRecord> {
        let tx = self.db.connection.transaction()?;
        let old = image_import(&tx, operation)?
            .ok_or(Error::Missing("image cancellation operation is missing"))?;
        if old.request_digest != *expected_request {
            return Err(Error::Conflict(
                "image cancellation request binding changed",
            ));
        }
        if old.phase == ImageImportPhase::Cancelled {
            return Ok(old);
        }
        if old.phase != ImageImportPhase::Cancelling {
            return Err(Error::Conflict("image cancellation was not admitted"));
        }
        tx.execute(
            "UPDATE image_imports SET phase=?2,dependency_image=NULL,dependency_snapshot=NULL WHERE operation=?1",
            params![operation.as_str(), encode(&ImageImportPhase::Cancelled)?],
        )?;
        tx.commit()?;
        Ok(ImageImportRecord {
            phase: ImageImportPhase::Cancelled,
            ..old
        })
    }

    /// Reserve and bind a private materialization before shared publication.
    /// A candidate is not yet an image from which a machine can be created.
    /// Only this catalog owner may adopt it; builders own bytes, not authority.
    pub fn prepare_image_import(
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
        if old.phase != ImageImportPhase::Admitted {
            return if old.image.as_ref() == Some(&image) {
                Ok(old)
            } else {
                Err(Error::Conflict(
                    "image import already bound another candidate",
                ))
            };
        }
        let existing = image_state(&tx, &image.digest)?;
        if let Some((existing, retired, cleanup_pending)) = &existing {
            if existing != &image {
                return Err(Error::Conflict(
                    "image digest is bound to different metadata",
                ));
            }
            if *retired && *cleanup_pending {
                return Err(Error::Conflict(
                    "retired image cleanup must finish before re-import",
                ));
            }
        }
        let (identities, bytes) = image_reservations(&tx, &image)?;
        if identities > self.limits.identities.get() || bytes > self.limits.image_bytes.get() {
            return Err(Error::Capacity("image candidate reservation exhausted"));
        }
        tx.execute(
            "UPDATE image_imports SET phase=?2,candidate=?3 WHERE operation=?1",
            params![
                operation_id.as_str(),
                encode(&ImageImportPhase::Prepared)?,
                encode(&image)?
            ],
        )?;
        tx.commit()?;
        Ok(ImageImportRecord {
            operation_id: operation_id.clone(),
            request_digest: request_digest.clone(),
            phase: ImageImportPhase::Prepared,
            image: Some(image),
        })
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
        if &old.request_digest != request_digest || old.image.as_ref() != Some(&image) {
            return Err(Error::Conflict(
                "image publication differs from its reserved candidate",
            ));
        }
        if old.phase == ImageImportPhase::Published {
            return Ok(old);
        }
        if old.phase != ImageImportPhase::Prepared {
            return Err(Error::Conflict(
                "image publication has no prepared reservation",
            ));
        }
        let existing = image_state(&tx, &image.digest)?;
        if let Some((previous, _, cleanup_pending)) = &existing
            && (previous != &image || *cleanup_pending)
        {
            return Err(Error::Conflict(
                "image publication conflicts with existing ownership",
            ));
        }
        if existing.is_some() {
            tx.execute(
                "UPDATE images SET retired=0 WHERE digest=?1",
                [image.digest.as_str()],
            )?;
        } else {
            tx.execute(
                "INSERT INTO images VALUES (?1,?2,0)",
                params![image.digest.as_str(), encode(&image)?],
            )?;
        }
        tx.execute(
            "UPDATE image_imports SET phase=?2,candidate=NULL,image=?3,candidate_cleanup_pending=1 WHERE operation=?1",
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

    /// Publication transferred byte ownership to the immutable image store.
    /// Reclaiming the private copy is a separately recoverable storage effect.
    pub fn pending_image_candidate_cleanup(
        &self,
        after: Option<&OperationId>,
        limit: Counter,
    ) -> Result<Vec<ImageImportRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity(
                "image candidate cleanup page limit must be in 1..=256",
            ));
        }
        let mut statement = self.db.connection.prepare(
            "SELECT operation FROM image_imports WHERE candidate_cleanup_pending=1 AND operation>?1 ORDER BY operation LIMIT ?2",
        )?;
        let operations = statement
            .query_map(
                params![after.map_or("", OperationId::as_str), limit.get()],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        control_page(operations.into_iter().map(|operation| {
            image_import(&self.db.connection, &operation.try_into()?)?
                .ok_or(Error::Corrupt("image candidate cleanup disappeared"))
        }))
    }

    pub fn complete_image_candidate_cleanup(
        &mut self,
        operation: &OperationId,
        request_digest: &Digest,
    ) -> Result<()> {
        let tx = self.db.connection.transaction()?;
        let record = image_import(&tx, operation)?.ok_or(Error::Missing(
            "image candidate cleanup operation is missing",
        ))?;
        if record.request_digest != *request_digest || record.phase != ImageImportPhase::Published {
            return Err(Error::Conflict(
                "image candidate ownership has not transferred",
            ));
        }
        tx.execute(
            "UPDATE image_imports SET candidate_cleanup_pending=0 WHERE operation=?1",
            [operation.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn image_import_input(&self, operation: &OperationId) -> Result<Option<ImageImportInput>> {
        image_import_input(&self.db.connection, operation)
    }

    pub fn pending_image_imports(
        &self,
        after: Option<&OperationId>,
        limit: Counter,
    ) -> Result<Vec<ImageImportRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity(
                "image import page limit must be in 1..=256",
            ));
        }
        let mut statement = self.db.connection.prepare(
            "SELECT operation FROM image_imports WHERE json_extract(phase,'$') NOT IN ('published','cancelled') AND operation>?1 ORDER BY operation LIMIT ?2")?;
        let operations = statement
            .query_map(
                params![after.map_or("", OperationId::as_str), limit.get()],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        control_page(operations.into_iter().map(|operation| {
            image_import(&self.db.connection, &operation.try_into()?)?
                .ok_or(Error::Corrupt("pending image import disappeared"))
        }))
    }

    pub fn image(&self, digest: &Digest) -> Result<Option<ImageRecord>> {
        Ok(image_state(&self.db.connection, digest)?
            .filter(|(_, retired, _)| !retired)
            .map(|(image, _, _)| image))
    }

    pub fn images(&self, after: Option<&Digest>, limit: Counter) -> Result<Vec<ImageRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("image page limit must be in 1..=256"));
        }
        let mut statement = self.db.connection.prepare(
            "SELECT value FROM images WHERE retired=0 AND digest>?1 ORDER BY digest ASC LIMIT ?2",
        )?;
        let mut rows = statement.query(params![after.map_or("", Digest::as_str), limit.get()])?;
        let mut page = ControlPage::default();
        while let Some(row) = rows.next()? {
            if !page.push(decode::<ImageRecord>(&row.get::<_, String>(0)?)?)? {
                break;
            }
        }
        Ok(page.into_values())
    }

    pub fn release_image(
        &mut self,
        operation_id: OperationId,
        image_digest: Digest,
        approval: Approval,
    ) -> Result<ImageReleaseRecord> {
        let request_digest = digest(
            Domain::Image,
            &("sandsurf-release-image-v1", &operation_id, &image_digest),
        )?;
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("image release approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = image_release(&tx, &operation_id)? {
            return if old.image_digest == image_digest && old.request_digest == request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict("image release operation identity conflict"))
            };
        }
        host_operation_identity_available(&tx, &operation_id)?;
        let (_, retired, _) =
            image_state(&tx, &image_digest)?.ok_or(Error::Missing("image does not exist"))?;
        if retired {
            return Err(Error::Conflict("image is already retired"));
        }
        let machine_references: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM machines WHERE image=?1 AND released=0)",
            [image_digest.as_str()],
            |row| row.get(0),
        )?;
        if machine_references {
            return Err(Error::Conflict("active machines pin this image"));
        }
        let snapshot_references: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshots WHERE json_extract(value,'$.imageDigest')=?1 AND json_extract(value,'$.phase') IS NOT 'released')",
            [image_digest.as_str()],
            |row| row.get(0),
        )?;
        if snapshot_references {
            return Err(Error::Conflict("retained snapshots pin this image"));
        }
        let import_references: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM image_imports WHERE json_extract(phase,'$') NOT IN ('published','cancelled') AND (dependency_image=?1 OR json_extract(candidate,'$.digest')=?1))",
            [image_digest.as_str()], |row| row.get(0))?;
        if import_references {
            return Err(Error::Conflict(
                "pending image materialization pins this image",
            ));
        }
        capacity(&tx, "image_releases", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let value = ImageReleaseRecord {
            operation_id,
            image_digest,
            request_digest,
            cleanup_pending: true,
        };
        tx.execute(
            "INSERT INTO image_releases VALUES (?1,?2,?3,1)",
            params![
                value.operation_id.as_str(),
                value.image_digest.as_str(),
                value.request_digest.as_str()
            ],
        )?;
        tx.execute(
            "UPDATE images SET retired=1 WHERE digest=?1",
            [value.image_digest.as_str()],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn complete_image_release(
        &mut self,
        operation_id: &OperationId,
        request_digest: &Digest,
    ) -> Result<ImageReleaseRecord> {
        let tx = self.db.connection.transaction()?;
        let mut value = image_release(&tx, operation_id)?
            .ok_or(Error::Missing("image release operation does not exist"))?;
        if &value.request_digest != request_digest {
            return Err(Error::Conflict("image release request digest changed"));
        }
        tx.execute(
            "UPDATE image_releases SET cleanup_pending=0 WHERE operation=?1",
            [operation_id.as_str()],
        )?;
        tx.commit()?;
        value.cleanup_pending = false;
        Ok(value)
    }

    pub fn pending_image_releases(
        &self,
        after: Option<&OperationId>,
        limit: Counter,
    ) -> Result<Vec<ImageReleaseRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity(
                "image cleanup page limit must be in 1..=256",
            ));
        }
        let mut statement = self.db.connection.prepare(
            "SELECT operation,image,request_digest,cleanup_pending FROM image_releases WHERE cleanup_pending=1 AND operation>?1 ORDER BY operation LIMIT ?2",
        )?;
        statement
            .query_map(
                params![after.map_or("", OperationId::as_str), limit.get()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                },
            )?
            .map(|row| {
                let (operation, image, request, cleanup_pending) = row?;
                Ok(ImageReleaseRecord {
                    operation_id: operation.try_into()?,
                    image_digest: image.try_into()?,
                    request_digest: request.try_into()?,
                    cleanup_pending,
                })
            })
            .collect()
    }

    pub fn snapshot(&self, id: &SnapshotId) -> Result<Option<Snapshot>> {
        snapshot_record(&self.db.connection, id)
    }

    /// Retirement closes admission before any filesystem deletion. Historical
    /// snapshot/lineage identities remain readable; only physical dependencies
    /// pin bytes. A completed independent fork does not pin its source forever.
    pub fn release_snapshot(
        &mut self,
        operation_id: OperationId,
        snapshot_id: SnapshotId,
        approval: Approval,
    ) -> Result<SnapshotReleaseRecord> {
        let request_digest = digest(
            Domain::Snapshot,
            &("sandsurf-release-snapshot-v1", &operation_id, &snapshot_id),
        )?;
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("snapshot release approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = snapshot_release(&tx, &operation_id)? {
            return if old.snapshot_id == snapshot_id && old.request_digest == request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict(
                    "snapshot release operation identity conflict",
                ))
            };
        }
        host_operation_identity_available(&tx, &operation_id)?;
        let mut snapshot =
            snapshot_record(&tx, &snapshot_id)?.ok_or(Error::Missing("snapshot does not exist"))?;
        if matches!(
            snapshot.phase,
            SnapshotPhase::Retiring | SnapshotPhase::Released
        ) {
            return Err(Error::Conflict("snapshot already has a retirement owner"));
        }
        for query in [
            "SELECT EXISTS(SELECT 1 FROM forks f JOIN machines m ON f.machine=m.id WHERE f.snapshot=?1 AND m.released=0 AND json_extract(f.value,'$.materializedDisk') IS NULL)",
            "SELECT EXISTS(SELECT 1 FROM rollbacks WHERE json_extract(value,'$.snapshotId')=?1 AND json_extract(value,'$.phase') IS NOT 'applied')",
            "SELECT EXISTS(SELECT 1 FROM image_imports WHERE dependency_snapshot=?1 AND json_extract(phase,'$') NOT IN ('published','cancelled'))",
        ] {
            if tx.query_row(query, [snapshot_id.as_str()], |row| row.get::<_, bool>(0))? {
                return Err(Error::Conflict("pending host operation pins this snapshot"));
            }
        }
        if tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM ({SUSPENSION_INPUTS}) WHERE snapshot=?1)"),
            [snapshot_id.as_str()],
            |row| row.get::<_, bool>(0),
        )? {
            // A newer accepted revision is not proof that a lost native
            // suspension response was NotApplied. Keep its possible input
            // until a later native lifecycle is actually completed.
            return Err(Error::Conflict(
                "pending or applied suspension pins this snapshot",
            ));
        }
        capacity(&tx, "snapshot_releases", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let record = SnapshotReleaseRecord {
            operation_id,
            machine_id: snapshot.request.machine_id.clone(),
            snapshot_id,
            request_digest,
            cleanup_pending: true,
        };
        snapshot.phase = SnapshotPhase::Retiring;
        tx.execute(
            "INSERT INTO snapshot_releases VALUES (?1,?2,?3)",
            params![
                record.operation_id.as_str(),
                record.snapshot_id.as_str(),
                encode(&record)?
            ],
        )?;
        tx.execute(
            "UPDATE snapshots SET value=?2 WHERE id=?1",
            params![snapshot.request.id.as_str(), encode(&snapshot)?],
        )?;
        tx.commit()?;
        Ok(record)
    }

    /// Called by the catalog owner only after the detached storage task has
    /// durably removed the complete owned payload closure.
    pub fn complete_snapshot_release(
        &mut self,
        operation: &OperationId,
        request_digest: &Digest,
    ) -> Result<SnapshotReleaseRecord> {
        let tx = self.db.connection.transaction()?;
        let mut record = snapshot_release(&tx, operation)?
            .ok_or(Error::Missing("snapshot release is missing"))?;
        if record.request_digest != *request_digest {
            return Err(Error::Conflict("snapshot release request changed"));
        }
        let mut snapshot = snapshot_record(&tx, &record.snapshot_id)?
            .ok_or(Error::Corrupt("retired snapshot disappeared"))?;
        if !matches!(
            snapshot.phase,
            SnapshotPhase::Retiring | SnapshotPhase::Released
        ) {
            return Err(Error::Corrupt("snapshot retirement phase changed"));
        }
        record.cleanup_pending = false;
        snapshot.phase = SnapshotPhase::Released;
        tx.execute(
            "UPDATE snapshot_releases SET value=?2 WHERE operation=?1",
            params![operation.as_str(), encode(&record)?],
        )?;
        tx.execute(
            "UPDATE snapshots SET value=?2 WHERE id=?1",
            params![record.snapshot_id.as_str(), encode(&snapshot)?],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn pending_snapshot_releases(
        &self,
        after: Option<&OperationId>,
        limit: Counter,
    ) -> Result<Vec<SnapshotReleaseRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity(
                "snapshot cleanup page limit must be in 1..=256",
            ));
        }
        let mut statement = self.db.connection.prepare("SELECT operation FROM snapshot_releases WHERE json_extract(value,'$.cleanupPending')=1 AND operation>?1 ORDER BY operation LIMIT ?2")?;
        let operations = statement
            .query_map(
                params![after.map_or("", OperationId::as_str), limit.get()],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        control_page(operations.into_iter().map(|operation| {
            snapshot_release(&self.db.connection, &operation.try_into()?)?
                .ok_or(Error::Corrupt("pending snapshot retirement disappeared"))
        }))
    }

    pub fn suspension(&self, machine: &MachineId) -> Result<Option<SuspensionRecord>> {
        let operation: Option<String> = self.db.connection.query_row(
            &format!("SELECT lifecycle FROM ({SUSPENSION_INPUTS}) WHERE machine=?1 AND completed IS NOT NULL"),
            [machine.as_str()], |row| row.get(0),
        ).optional()?;
        let Some(operation) = operation else {
            return Ok(None);
        };
        let lifecycle = intent(&self.db.connection, &operation.try_into()?)?
            .ok_or(Error::Corrupt("suspension lifecycle disappeared"))?;
        let snapshot = suspension_capture(&self.db.connection, &lifecycle)?;
        if snapshot.phase != SnapshotPhase::Ready {
            return Err(Error::Corrupt(
                "active suspension lost its retained capture",
            ));
        }
        Ok(Some(SuspensionRecord {
            machine_id: machine.clone(),
            lifecycle_operation_id: lifecycle.operation_id,
            snapshot_id: snapshot.request.id,
            manifest_digest: snapshot
                .manifest_digest
                .ok_or(Error::Corrupt("suspension manifest disappeared"))?,
        }))
    }

    pub fn snapshots(&self, after: Option<&SnapshotId>, limit: Counter) -> Result<Vec<Snapshot>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("snapshot page limit must be in 1..=256"));
        }
        let mut statement = self
            .db
            .connection
            .prepare("SELECT id FROM snapshots WHERE id>?1 ORDER BY id LIMIT ?2")?;
        let rows = statement.query_map(
            params![after.map_or("", SnapshotId::as_str), limit.get()],
            |row| row.get::<_, String>(0),
        )?;
        let mut page = ControlPage::default();
        for row in rows {
            let id: SnapshotId = row?.try_into()?;
            if !page.push(
                snapshot_record(&self.db.connection, &id)?.ok_or(Error::Corrupt(
                    "listed snapshot disappeared from the catalog",
                ))?,
            )? {
                break;
            }
        }
        Ok(page.into_values())
    }

    /// Recovery candidates, not all historical snapshots. The partial index
    /// bounds work independently of the size of retained immutable history.
    pub fn capturing_disk_snapshots(
        &self,
        after: Option<&SnapshotId>,
        limit: Counter,
    ) -> Result<Vec<Snapshot>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("snapshot page limit must be in 1..=256"));
        }
        let mut statement = self.db.connection.prepare(
            "SELECT value FROM snapshots WHERE id>?1 AND json_extract(value,'$.phase')='capturing' AND json_extract(value,'$.request.kind')='disk' ORDER BY id LIMIT ?2",
        )?;
        let mut rows =
            statement.query(params![after.map_or("", SnapshotId::as_str), limit.get()])?;
        let mut page = ControlPage::default();
        while let Some(row) = rows.next()? {
            if !page.push(decode::<Snapshot>(&row.get::<_, String>(0)?)?)? {
                break;
            }
        }
        Ok(page.into_values())
    }

    pub fn admit_snapshot(
        &mut self,
        request: SnapshotRequest,
        approval: Approval,
    ) -> Result<Snapshot> {
        let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request))?;
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("snapshot approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = snapshot_record(&tx, &request.id)? {
            return if old.request_digest == request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict("snapshot identity conflict"))
            };
        }
        host_operation_identity_available(&tx, &request.operation_id)?;
        require_revision(&tx, &request.machine_id, request.expected_revision)?;
        if let Some(parent) = request.parent.as_ref() {
            let parent = snapshot_record(&tx, parent)?
                .ok_or(Error::Missing("parent snapshot is missing"))?;
            if parent.phase != SnapshotPhase::Ready {
                return Err(Error::Conflict("parent snapshot is not ready"));
            }
        }
        let machine = machine_record(&tx, &request.machine_id)?
            .ok_or(Error::Missing("snapshot machine is missing"))?;
        reserve_snapshot_capacity(
            &tx,
            &request.machine_id,
            &machine.runtime_configuration.resources,
            request.kind,
        )?;
        capacity(&tx, "snapshots", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let full = request.kind == SnapshotKind::Full;
        let value = Snapshot {
            request,
            request_digest,
            phase: SnapshotPhase::Admitted,
            image_digest: machine.image_digest,
            system_disk_bytes: machine.runtime_configuration.resources.disk_bytes,
            resources: machine.runtime_configuration.resources,
            consistency: None,
            system_disk_digest: None,
            manifest_digest: None,
            // Reconnect credentials and process memory make a full capture
            // protected even when no defaults secret has been delivered.
            sensitive: machine.known_sensitive || full,
            full: None,
        };
        tx.execute(
            "INSERT INTO snapshots VALUES (?1,?2,?3,?4)",
            params![
                value.request.id.as_str(),
                value.request.operation_id.as_str(),
                value.request.machine_id.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Admit the full snapshot implied by an already committed suspend
    /// intent. This is a host-owned suboperation of that lifecycle authority,
    /// not a second application approval or a synthetic snapshot grant.
    pub fn admit_suspension_snapshot(
        &mut self,
        request: SnapshotRequest,
        lifecycle_operation: &OperationId,
    ) -> Result<Snapshot> {
        if request.kind != SnapshotKind::Full || request.parent.is_some() {
            return Err(Error::Conflict("suspension requires a root full snapshot"));
        }
        let request_digest = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &request))?;
        let tx = self.db.connection.transaction()?;
        if let Some(old) = snapshot_record(&tx, &request.id)? {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT lifecycle FROM suspension_captures WHERE snapshot=?1",
                    [request.id.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            return if old.request_digest == request_digest
                && owner.as_deref() == Some(lifecycle_operation.as_str())
            {
                Ok(old)
            } else {
                Err(Error::Conflict("suspension snapshot identity conflict"))
            };
        }
        let lifecycle = intent(&tx, lifecycle_operation)?
            .ok_or(Error::Missing("suspend lifecycle intent is missing"))?;
        if lifecycle.machine_id != request.machine_id
            || lifecycle.desired != DesiredState::Suspended
            || lifecycle.completion.is_some()
            || request.expected_revision.next()? != lifecycle.revision
        {
            return Err(Error::Conflict(
                "suspension snapshot does not match its lifecycle intent",
            ));
        }
        host_operation_identity_available(&tx, &request.operation_id)?;
        let machine = machine_record(&tx, &request.machine_id)?
            .ok_or(Error::Missing("suspension machine is missing"))?;
        if machine.configuration_revision != lifecycle.revision {
            return Err(Error::Conflict(
                "suspension lifecycle is no longer the current host intent",
            ));
        }
        reserve_snapshot_capacity(
            &tx,
            &request.machine_id,
            &machine.runtime_configuration.resources,
            request.kind,
        )?;
        capacity(&tx, "snapshots", self.limits.operations)?;
        let value = Snapshot {
            request,
            request_digest,
            phase: SnapshotPhase::Admitted,
            image_digest: machine.image_digest,
            system_disk_bytes: machine.runtime_configuration.resources.disk_bytes,
            resources: machine.runtime_configuration.resources,
            consistency: None,
            system_disk_digest: None,
            manifest_digest: None,
            sensitive: true,
            full: None,
        };
        tx.execute(
            "INSERT INTO snapshots VALUES (?1,?2,?3,?4)",
            params![
                value.request.id.as_str(),
                value.request.operation_id.as_str(),
                value.request.machine_id.as_str(),
                encode(&value)?
            ],
        )?;
        tx.execute(
            "INSERT INTO suspension_captures VALUES (?1,?2)",
            params![value.request.id.as_str(), lifecycle_operation.as_str()],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn begin_snapshot(&mut self, id: &SnapshotId, request_digest: &Digest) -> Result<Snapshot> {
        let mut value = snapshot_record(&self.db.connection, id)?
            .ok_or(Error::Missing("snapshot is missing"))?;
        if value.request_digest != *request_digest {
            return Err(Error::Conflict("snapshot request digest mismatch"));
        }
        if value.phase == SnapshotPhase::Ready {
            return Ok(value);
        }
        if !matches!(
            value.phase,
            SnapshotPhase::Admitted | SnapshotPhase::Capturing
        ) {
            return Err(Error::Conflict("retired snapshot cannot resume capture"));
        }
        value.phase = SnapshotPhase::Capturing;
        self.db.connection.execute(
            "UPDATE snapshots SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        Ok(value)
    }

    pub fn complete_snapshot(
        &mut self,
        id: &SnapshotId,
        request_digest: &Digest,
        disk_digest: Digest,
        manifest_digest: Digest,
        consistency: SnapshotConsistency,
    ) -> Result<Snapshot> {
        self.complete_snapshot_inner(
            id,
            request_digest,
            disk_digest,
            manifest_digest,
            consistency,
            None,
        )
    }

    pub fn complete_full_snapshot(
        &mut self,
        id: &SnapshotId,
        request_digest: &Digest,
        disk_digest: Digest,
        manifest_digest: Digest,
        consistency: SnapshotConsistency,
        full: FullSnapshotMetadata,
    ) -> Result<Snapshot> {
        self.complete_snapshot_inner(
            id,
            request_digest,
            disk_digest,
            manifest_digest,
            consistency,
            Some(full),
        )
    }

    fn complete_snapshot_inner(
        &mut self,
        id: &SnapshotId,
        request_digest: &Digest,
        disk_digest: Digest,
        manifest_digest: Digest,
        consistency: SnapshotConsistency,
        full: Option<FullSnapshotMetadata>,
    ) -> Result<Snapshot> {
        let mut value = snapshot_record(&self.db.connection, id)?
            .ok_or(Error::Missing("snapshot is missing"))?;
        if value.request_digest != *request_digest {
            return Err(Error::Conflict("snapshot request digest mismatch"));
        }
        if (value.request.kind == SnapshotKind::Full) != full.is_some() {
            return Err(Error::Conflict(
                "snapshot kind does not match its completion material",
            ));
        }
        if value.phase == SnapshotPhase::Ready {
            return if value.system_disk_digest.as_ref() == Some(&disk_digest)
                && value.manifest_digest.as_ref() == Some(&manifest_digest)
                && value.consistency == Some(consistency)
                && value.full == full
            {
                Ok(value)
            } else {
                Err(Error::Conflict("snapshot result identity conflict"))
            };
        }
        if value.phase != SnapshotPhase::Capturing {
            return Err(Error::Conflict("snapshot capture has not begun"));
        }
        value.phase = SnapshotPhase::Ready;
        value.system_disk_digest = Some(disk_digest);
        value.manifest_digest = Some(manifest_digest);
        value.consistency = Some(consistency);
        value.full = full;
        self.db.connection.execute(
            "UPDATE snapshots SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        Ok(value)
    }

    pub fn authority_binding(&self) -> &AuthorityBinding {
        self.authority.binding()
    }

    pub fn machine(&self, id: &MachineId) -> Result<Option<MachineRecord>> {
        machine_record(&self.db.connection, id)
    }

    /// Stable identity pagination. The bounded result is an observation of the
    /// host catalog, not an ownership token or a cache of machine state.
    pub fn machines(
        &self,
        after: Option<&MachineId>,
        limit: Counter,
    ) -> Result<Vec<MachineRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("machine page limit must be in 1..=256"));
        }
        let after = after.map_or("", MachineId::as_str);
        let mut statement = self
            .db
            .connection
            .prepare("SELECT id FROM machines WHERE id>?1 ORDER BY id ASC LIMIT ?2")?;
        let identities = statement
            .query_map(params![after, limit.get()], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        control_page(identities.into_iter().map(|id| {
            let id: MachineId = id.try_into()?;
            machine_record(&self.db.connection, &id)?.ok_or(Error::Corrupt(
                "listed machine disappeared from the host transaction view",
            ))
        }))
    }

    /// Machines whose storage reservation still has an owner. Retirement
    /// recovery remains eligible until actual deletion is committed; released
    /// historical identities do not slow lifecycle reconciliation.
    pub fn active_machines(
        &self,
        after: Option<&MachineId>,
        limit: Counter,
    ) -> Result<Vec<MachineRecord>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("machine page limit must be in 1..=256"));
        }
        let mut statement = self
            .db
            .connection
            .prepare("SELECT id FROM machines WHERE released=0 AND id>?1 ORDER BY id LIMIT ?2")?;
        let identities = statement
            .query_map(
                params![after.map_or("", MachineId::as_str), limit.get()],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        control_page(identities.into_iter().map(|id| {
            let id: MachineId = id.try_into()?;
            machine_record(&self.db.connection, &id)?.ok_or(Error::Corrupt(
                "active machine disappeared from the host transaction view",
            ))
        }))
    }

    pub fn create_machine(
        &mut self,
        admission: MachineAdmission,
        approval: Approval,
    ) -> Result<LifecycleIntent> {
        let MachineAdmission {
            id,
            image,
            resources,
            defaults,
            mut image_defaults,
            lifetime,
            operation,
        } = admission;
        resources.validate()?;
        defaults.validate()?;
        lifetime.validate()?;
        let request = digest(
            Domain::Machine,
            &(&id, &image, &resources, &defaults, &lifetime, &operation),
        )?;
        if request != approval.request_digest {
            return Err(Error::Conflict(
                "creation approval does not bind the exact request",
            ));
        }
        image_defaults.environment.extend(defaults.environment);
        if defaults.user.is_some() {
            image_defaults.user = defaults.user;
        }
        if defaults.working_directory.is_some() {
            image_defaults.working_directory = defaults.working_directory;
        }
        image_defaults.validate()?;
        let tx = self.db.connection.transaction()?;
        if let Some(old) = intent(&tx, &operation)? {
            if old.request_digest == request {
                return Ok(old);
            }
            return Err(Error::Conflict(
                "operation identity already bound to another request",
            ));
        }
        host_operation_identity_available(&tx, &operation)?;
        capacity(&tx, "machines", self.limits.identities)?;
        capacity(&tx, "intents", self.limits.operations)?;
        let (image_record, retired, _) = image_state(&tx, &image)?
            .ok_or(Error::Missing("machine image has not been admitted"))?;
        if retired {
            return Err(Error::Conflict("machine image is retired"));
        }
        let sensitive = image_record.sensitive;
        reserve_compute(&tx, None, &resources, &self.limits)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let runtime_configuration = initial_runtime_configuration(&resources)?;
        let activity = current_unix_millis()?;
        tx.execute(
            "INSERT INTO machines(id,image,configuration,defaults,lifetime,activity,sensitive,revision) VALUES (?1,?2,?3,?4,?5,?6,?7,1)",
            params![
                id.as_str(),
                image.as_str(),
                encode(&runtime_configuration)?,
                encode(&image_defaults)?,
                encode(&lifetime)?,
                activity.get(),
                sensitive
            ],
        )?;
        let value = LifecycleIntent {
            machine_id: id,
            operation_id: operation,
            desired: DesiredState::Running,
            revision: Counter::ONE,
            request_digest: request,
            completion: None,
        };
        save_intent(&tx, &value)?;
        validate_machine_metadata(&tx, &value.machine_id)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn create_machine_from_snapshot(
        &mut self,
        id: MachineId,
        snapshot_id: &SnapshotId,
        resources: Resources,
        lifetime: MachineLifetime,
        operation: OperationId,
        approval: Approval,
    ) -> Result<LifecycleIntent> {
        resources.validate()?;
        lifetime.validate()?;
        let request = digest(
            Domain::Snapshot,
            &(
                "sandsurf-filesystem-fork-v1",
                snapshot_id,
                &id,
                &resources,
                &lifetime,
                &operation,
            ),
        )?;
        if request != approval.request_digest {
            return Err(Error::Conflict("fork approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = intent(&tx, &operation)? {
            return if old.request_digest == request {
                Ok(old)
            } else {
                Err(Error::Conflict("fork operation identity conflict"))
            };
        }
        host_operation_identity_available(&tx, &operation)?;
        let snapshot =
            snapshot_record(&tx, snapshot_id)?.ok_or(Error::Missing("fork snapshot is missing"))?;
        if snapshot.phase != SnapshotPhase::Ready
            || snapshot.request.kind != SnapshotKind::Disk
            || resources.disk_bytes != snapshot.system_disk_bytes
        {
            return Err(Error::Conflict(
                "fork requires a ready filesystem snapshot with matching disk geometry",
            ));
        }
        capacity(&tx, "machines", self.limits.identities)?;
        capacity(&tx, "intents", self.limits.operations)?;
        reserve_compute(&tx, None, &resources, &self.limits)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let configuration = initial_runtime_configuration(&resources)?;
        let source_defaults: String = tx.query_row(
            "SELECT defaults FROM machines WHERE id=?1",
            [snapshot.request.machine_id.as_str()],
            |row| row.get(0),
        )?;
        let activity = current_unix_millis()?;
        tx.execute(
            "INSERT INTO machines(id,image,configuration,defaults,lifetime,activity,sensitive,revision) VALUES (?1,?2,?3,?4,?5,?6,?7,1)",
            params![
                id.as_str(),
                snapshot.image_digest.as_str(),
                encode(&configuration)?,
                source_defaults,
                encode(&lifetime)?,
                activity.get(),
                snapshot.sensitive
            ],
        )?;
        let fork = ForkRecord {
            machine_id: id.clone(),
            operation_id: operation.clone(),
            snapshot_id: snapshot_id.clone(),
            request_digest: request.clone(),
            materialized_disk: None,
        };
        let value = LifecycleIntent {
            machine_id: id,
            operation_id: operation,
            desired: DesiredState::Running,
            revision: Counter::ONE,
            request_digest: request,
            completion: None,
        };
        save_intent(&tx, &value)?;
        tx.execute(
            "INSERT INTO forks VALUES (?1,?2,?3,?4)",
            params![
                fork.machine_id.as_str(),
                fork.operation_id.as_str(),
                fork.snapshot_id.as_str(),
                encode(&fork)?,
            ],
        )?;
        validate_machine_metadata(&tx, &value.machine_id)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn fork(&self, machine: &MachineId) -> Result<Option<ForkRecord>> {
        fork_record(&self.db.connection, machine)
    }

    /// Actual verified disk bytes, not worker receipt presence, establish
    /// materialization. This record persists after Linux modifies those bytes;
    /// reopening a machine must never reapply its creation customization.
    pub fn complete_fork_materialization(
        &mut self,
        machine: &MachineId,
        operation: &OperationId,
        request_digest: &Digest,
        disk: Digest,
    ) -> Result<ForkRecord> {
        let tx = self.db.connection.transaction()?;
        let mut fork = fork_record(&tx, machine)?
            .ok_or(Error::Missing("machine fork admission is missing"))?;
        if fork.operation_id != *operation || fork.request_digest != *request_digest {
            return Err(Error::Conflict("fork materialization admission changed"));
        }
        if let Some(old) = &fork.materialized_disk {
            return if old == &disk {
                Ok(fork)
            } else {
                Err(Error::Conflict("fork materialization completion changed"))
            };
        }
        fork.materialized_disk = Some(disk);
        tx.execute(
            "UPDATE forks SET value=?2 WHERE machine=?1",
            params![machine.as_str(), encode(&fork)?],
        )?;
        tx.commit()?;
        Ok(fork)
    }

    pub fn admit_rollback(
        &mut self,
        machine: &MachineId,
        snapshot_id: &SnapshotId,
        operation_id: OperationId,
        expected_revision: Counter,
        approval: Approval,
    ) -> Result<RollbackRecord> {
        let request_digest = digest(
            Domain::Snapshot,
            &(
                "sandsurf-filesystem-rollback-v1",
                machine,
                snapshot_id,
                &operation_id,
                expected_revision,
            ),
        )?;
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("rollback approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(raw) = tx
            .query_row(
                "SELECT value FROM rollbacks WHERE operation=?1",
                [operation_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: RollbackRecord = decode(&raw)?;
            return if old.request_digest == request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict("rollback operation identity conflict"))
            };
        }
        host_operation_identity_available(&tx, &operation_id)?;
        require_revision(&tx, machine, expected_revision)?;
        if pending_rollback_record(&tx, machine)?.is_some() {
            return Err(Error::Conflict("another disk replacement is pending"));
        }
        let source = snapshot_record(&tx, snapshot_id)?
            .ok_or(Error::Missing("rollback snapshot is missing"))?;
        let target =
            machine_record(&tx, machine)?.ok_or(Error::Missing("rollback machine is missing"))?;
        if source.phase != SnapshotPhase::Ready
            || source.request.kind != SnapshotKind::Disk
            || source.image_digest != target.image_digest
            || source.system_disk_bytes != target.runtime_configuration.resources.disk_bytes
        {
            return Err(Error::Conflict(
                "rollback snapshot is incompatible with the target Machine",
            ));
        }
        // Classification precedes disk replacement. Interrupted replacement cannot
        // make potentially disclosed bytes public, and clean rollback never clears it.
        if source.sensitive {
            tx.execute(
                "UPDATE machines SET sensitive=1 WHERE id=?1",
                [machine.as_str()],
            )?;
        }
        capacity(&tx, "rollbacks", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let value = RollbackRecord {
            operation_id,
            machine_id: machine.clone(),
            snapshot_id: snapshot_id.clone(),
            expected_revision,
            request_digest,
            phase: RollbackPhase::Admitted,
            evidence_digest: None,
        };
        tx.execute(
            "INSERT INTO rollbacks VALUES (?1,?2,?3)",
            params![
                value.operation_id.as_str(),
                value.machine_id.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// The admitted replacement, not a cached storage observation, fences new
    /// boot authority until its exact verified disk publication is committed.
    pub fn pending_rollback(&self, machine: &MachineId) -> Result<Option<RollbackRecord>> {
        pending_rollback_record(&self.db.connection, machine)
    }

    pub fn complete_rollback(
        &mut self,
        operation_id: &OperationId,
        request_digest: &Digest,
        evidence_digest: Digest,
    ) -> Result<RollbackRecord> {
        let raw: String = self.db.connection.query_row(
            "SELECT value FROM rollbacks WHERE operation=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )?;
        let mut value: RollbackRecord = decode(&raw)?;
        if value.request_digest != *request_digest {
            return Err(Error::Conflict("rollback request digest mismatch"));
        }
        if value.phase == RollbackPhase::Applied {
            return if value.evidence_digest.as_ref() == Some(&evidence_digest) {
                Ok(value)
            } else {
                Err(Error::Conflict("rollback evidence identity conflict"))
            };
        }
        value.phase = RollbackPhase::Applied;
        value.evidence_digest = Some(evidence_digest);
        self.db.connection.execute(
            "UPDATE rollbacks SET value=?2 WHERE operation=?1",
            params![operation_id.as_str(), encode(&value)?],
        )?;
        Ok(value)
    }

    pub fn request_lifecycle(
        &mut self,
        machine: &MachineId,
        operation: OperationId,
        expected: Counter,
        desired: DesiredState,
        approval: Approval,
    ) -> Result<LifecycleIntent> {
        let request = digest(Domain::Operation, &(machine, &operation, expected, desired))?;
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
        host_operation_identity_available(&tx, &operation)?;
        require_revision(&tx, machine, expected)?;
        // A newer, explicitly authorized intent supersedes prior intent. An
        // incomplete earlier operation stays incomplete in immutable history;
        // it cannot hold machine termination hostage or be redispatched later.
        capacity(&tx, "intents", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let revision = expected.next()?;
        let value = LifecycleIntent {
            machine_id: machine.clone(),
            operation_id: operation,
            desired,
            revision,
            request_digest: request,
            completion: None,
        };
        tx.execute(
            "UPDATE machines SET revision=?2 WHERE id=?1",
            params![machine.as_str(), revision.get()],
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
        let machine = machine_record(&self.db.connection, &intent.machine_id)?
            .ok_or(Error::Missing("lifecycle machine is missing"))?;
        if intent.desired == DesiredState::Running
            && self.pending_rollback(&intent.machine_id)?.is_some()
        {
            return Err(Error::Conflict("disk replacement has not completed"));
        }
        if intent.desired == DesiredState::Running
            && self
                .fork(&intent.machine_id)?
                .is_some_and(|fork| fork.materialized_disk.is_none())
        {
            return Err(Error::Conflict(
                "fork disk materialization has not completed",
            ));
        }
        if machine.configuration_revision != intent.revision {
            return Err(Error::Conflict(
                "lifecycle intent is no longer the current configuration revision",
            ));
        }
        self.authority.authorize_lifecycle(LifecycleCommand {
            machine_id: intent.machine_id,
            operation_id: intent.operation_id,
            desired: intent.desired,
            revision: intent.revision,
            request_digest: intent.request_digest,
            configuration: machine.runtime_configuration,
        })
    }

    /// Authorize installation of the host-owned configuration revision without
    /// manufacturing a lifecycle intent. The guardian records the applied
    /// revision as an observation; this catalog remains the only grant writer.
    pub fn authorize_configuration(
        &self,
        machine: &MachineId,
        revision: Counter,
    ) -> Result<AuthorizedConfiguration> {
        require_revision(&self.db.connection, machine, revision)?;
        let configuration = self
            .machine(machine)?
            .ok_or(Error::Missing("machine is missing"))?
            .runtime_configuration;
        configuration.validate()?;
        let operation_id: OperationId = format!("configuration-{}", revision.get()).try_into()?;
        let request_digest = digest(
            Domain::Authority,
            &(
                "sandsurf-apply-configuration-v1",
                machine,
                revision,
                &configuration,
            ),
        )?;
        self.authority
            .authorize_configuration(ConfigurationCommand {
                machine_id: machine.clone(),
                operation_id,
                revision,
                request_digest,
                configuration,
            })
    }

    /// Replace the host-owned runtime configuration and advance its revision
    /// atomically. A guardian receives the signed result but never owns a
    /// separately mutable grant/configuration set.
    pub fn set_runtime_configuration(
        &mut self,
        machine: &MachineId,
        operation: &OperationId,
        expected: Counter,
        configuration: RuntimeConfiguration,
        request: Digest,
        approval: Approval,
    ) -> Result<HostConfigurationOperation> {
        configuration.validate()?;
        if request != approval.request_digest {
            return Err(Error::Conflict("runtime configuration approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(raw) = tx
            .query_row(
                "SELECT value FROM configuration_operations WHERE id=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: HostConfigurationOperation = decode(&raw)?;
            return if old.machine_id == *machine && old.request_digest == request {
                Ok(old)
            } else {
                Err(Error::Conflict("configuration operation identity conflict"))
            };
        }
        host_operation_identity_available(&tx, operation)?;
        require_revision(&tx, machine, expected)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let revision = expected.next()?;
        let previous: String = tx.query_row(
            "SELECT configuration FROM machines WHERE id=?1",
            [machine.as_str()],
            |row| row.get(0),
        )?;
        if decode::<RuntimeConfiguration>(&previous)?.resources != configuration.resources {
            return Err(Error::Conflict(
                "network configuration cannot change resource authority",
            ));
        }
        tx.execute(
            "UPDATE machines SET configuration=?2,revision=?3 WHERE id=?1",
            params![machine.as_str(), encode(&configuration)?, revision.get()],
        )?;
        validate_machine_metadata(&tx, machine)?;
        let value = HostConfigurationOperation {
            operation_id: operation.clone(),
            machine_id: machine.clone(),
            request_digest: request,
            revision,
            configuration,
        };
        capacity(&tx, "configuration_operations", self.limits.operations)?;
        tx.execute(
            "INSERT INTO configuration_operations VALUES (?1,?2,?3,?4)",
            params![
                operation.as_str(),
                machine.as_str(),
                value.request_digest.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Admit the host-owned envelope after the service verifies native applicability.
    pub fn update_resources(
        &mut self,
        machine: &MachineId,
        operation: &OperationId,
        expected: Counter,
        resources: Resources,
        approval: Approval,
    ) -> Result<HostConfigurationOperation> {
        resources.validate()?;
        let request = digest(
            Domain::Authority,
            &(
                "sandsurf-machine-resources-v1",
                machine,
                operation,
                expected,
                &resources,
            ),
        )?;
        if approval.request_digest != request {
            return Err(Error::Conflict("resource update approval mismatch"));
        }
        if let Some(raw) = self
            .db
            .connection
            .query_row(
                "SELECT value FROM configuration_operations WHERE id=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            let old: HostConfigurationOperation = decode(&raw)?;
            return if old.machine_id == *machine && old.request_digest == request {
                Ok(old)
            } else {
                Err(Error::Conflict("configuration operation identity conflict"))
            };
        }
        let tx = self.db.connection.transaction()?;
        host_operation_identity_available(&tx, operation)?;
        require_revision(&tx, machine, expected)?;
        reserve_compute(&tx, Some(machine), &resources, &self.limits)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let encoded: String = tx.query_row(
            "SELECT configuration FROM machines WHERE id=?1",
            [machine.as_str()],
            |row| row.get(0),
        )?;
        let mut configuration: RuntimeConfiguration = decode(&encoded)?;
        if resources.disk_bytes != configuration.resources.disk_bytes
            && pending_rollback_record(&tx, machine)?.is_some()
        {
            return Err(Error::Conflict(
                "pending disk replacement fixes disk geometry",
            ));
        }
        if snapshot_capacity_held(&tx, machine)? > resources.snapshot_bytes.get() {
            return Err(Error::Capacity(
                "resource reduction excludes retained snapshot reservations",
            ));
        }
        configuration.resources = resources.clone();
        let revision = expected.next()?;
        tx.execute(
            "UPDATE machines SET configuration=?2,revision=?3 WHERE id=?1",
            params![machine.as_str(), encode(&configuration)?, revision.get()],
        )?;
        validate_machine_metadata(&tx, machine)?;
        let value = HostConfigurationOperation {
            operation_id: operation.clone(),
            machine_id: machine.clone(),
            request_digest: request,
            revision,
            configuration,
        };
        capacity(&tx, "configuration_operations", self.limits.operations)?;
        tx.execute(
            "INSERT INTO configuration_operations VALUES (?1,?2,?3,?4)",
            params![
                operation.as_str(),
                machine.as_str(),
                value.request_digest.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
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
            || operation.command.machine_id != observation.machine_id
            || observation.cause
                != (ObservationCause::Lifecycle {
                    operation_id: operation.command.operation_id.clone(),
                })
            || operation.command.revision != observation.applied_revision
            || !observation.state.satisfies(operation.command.desired)
            || reference.machine_id != observation.machine_id
            || reference.generation != observation.generation
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
        let ObservationCause::Lifecycle { operation_id } = &observation.cause else {
            return Err(Error::Conflict(
                "only lifecycle evidence can complete host intent",
            ));
        };
        let mut value =
            intent(&tx, operation_id)?.ok_or(Error::Missing("lifecycle intent is missing"))?;
        if value.machine_id != observation.machine_id
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
        if value.desired == DesiredState::Suspended {
            let snapshot = suspension_capture(&tx, &value)?;
            if snapshot.phase != SnapshotPhase::Ready
                && tx.query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM ({SUSPENSION_INPUTS}) WHERE lifecycle=?1)"
                    ),
                    [value.operation_id.as_str()],
                    |row| row.get::<_, bool>(0),
                )?
            {
                return Err(Error::Conflict(
                    "live suspension requires retained capture bytes",
                ));
            }
        }
        value.completion = Some(reference);
        tx.execute(
            "UPDATE intents SET value=?2 WHERE id=?1",
            params![value.operation_id.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Host storage commits this only after native destruction and durable
    /// disk deletion. Output, artifacts, and snapshots have separate owners.
    pub fn release_retired_storage(&mut self, machine: &MachineId) -> Result<()> {
        let tx = self.db.connection.transaction()?;
        let record = machine_record(&tx, machine)?.ok_or(Error::Missing("machine is missing"))?;
        if record.latest_intent.desired != DesiredState::Destroyed
            || record.latest_intent.completion.is_none()
        {
            return Err(Error::Conflict(
                "storage release requires confirmed native destruction",
            ));
        }
        tx.execute(
            "UPDATE machines SET released=1 WHERE id=?1",
            [machine.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn revision(&self, machine: &MachineId) -> Result<Counter> {
        revision(&self.db.connection, machine)
    }

    /// Record host-observed application activity monotonically. This is an
    /// input to an admitted idle policy, never machine-state evidence.
    pub fn observe_activity(&mut self, machine: &MachineId, at: Counter) -> Result<()> {
        let changed = self.db.connection.execute(
            "UPDATE machines SET activity=max(activity,?2) WHERE id=?1 AND released=0",
            params![machine.as_str(), at.get()],
        )?;
        if changed != 1 {
            return Err(Error::Missing("active machine is missing"));
        }
        Ok(())
    }

    /// Check a host revision without manufacturing a second authority record.
    pub fn require_revision(&self, machine: &MachineId, expected: Counter) -> Result<()> {
        require_revision(&self.db.connection, machine, expected)
    }

    /// Host intent gates new client work without inventing command grants or
    /// using configuration revisions as byte-stream transaction counters.
    pub fn require_guest_access(&self, machine: &MachineId) -> Result<()> {
        let record = self
            .machine(machine)?
            .ok_or(Error::Missing("computer identity is missing"))?;
        if record.latest_intent.desired != DesiredState::Running {
            return Err(Error::Conflict(
                "host lifecycle intent does not admit guest work",
            ));
        }
        Ok(())
    }

    pub fn authorize_output_loss(
        &mut self,
        machine: &MachineId,
        process: &ExecutionId,
        receipt: &Digest,
        output: &OutputBoundary,
        approval: Approval,
    ) -> Result<AuthorizedLoss> {
        let binding = digest(
            Domain::Release,
            &(machine, process, receipt, output, "loss"),
        )?;
        if approval.request_digest != binding {
            return Err(Error::Conflict(
                "loss approval must bind the machine and complete evidence scope",
            ));
        }
        let tx = self.db.connection.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM machines WHERE id=?1)",
            [machine.as_str()],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::Missing(
                "loss decision has no host-owned machine identity",
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
            machine.clone(),
            process.clone(),
            receipt.clone(),
            output.clone(),
            approval.id,
            approval.request_digest,
        )
    }

    /// Convert guardian/guest counters into host-owned monotonic consumption.
    /// Live gauges remain observations and may fall; consumed counters do not.
    pub fn observe_usage(
        &mut self,
        machine: &MachineId,
        generation: Counter,
        raw: ResourceUsage,
    ) -> Result<ResourceUsage> {
        let tx = self.db.connection.transaction()?;
        let old = tx
            .query_row(
                "SELECT generation,raw,cumulative FROM usage_observations WHERE machine=?1",
                [machine.as_str()],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let cumulative = if let Some((old_generation, old_raw, old_cumulative)) = old {
            let old_generation: Counter = old_generation.try_into()?;
            if generation < old_generation {
                return Err(Error::Conflict("resource usage generation moved backwards"));
            }
            let old_raw: ResourceUsage = decode(&old_raw)?;
            let mut value: ResourceUsage = decode(&old_cumulative)?;
            let same_host_counter = raw.host_counter_epoch.is_some()
                && raw.host_counter_epoch == old_raw.host_counter_epoch;
            let same_counter = same_host_counter
                || (raw.host_counter_epoch.is_none() && generation == old_generation);
            if same_host_counter
                && let (Some(current), Some(previous)) = (&raw.cpu_ledgers, &old_raw.cpu_ledgers)
                && [
                    (current.native_micros, previous.native_micros),
                    (current.partition_micros, previous.partition_micros),
                    (
                        current.partition_hypervisor_micros,
                        previous.partition_hypervisor_micros,
                    ),
                ]
                .iter()
                .any(|(current, previous)| {
                    matches!((current, previous),
                    (Some(current), Some(previous)) if current < previous)
                })
            {
                return Err(Error::Conflict(
                    "native CPU ledger rewound within one owner epoch",
                ));
            }
            if same_counter
                && [
                    (raw.network_rx_bytes, old_raw.network_rx_bytes),
                    (raw.network_tx_bytes, old_raw.network_tx_bytes),
                    (raw.network_connections, old_raw.network_connections),
                ]
                .iter()
                .any(|(current, previous)| current < previous)
            {
                return Err(Error::Conflict(
                    "resource usage rewound within one machine generation",
                ));
            }
            if same_counter && [
                (raw.cpu_micros, old_raw.cpu_micros),
                (raw.io_read_bytes, old_raw.io_read_bytes),
                (raw.io_write_bytes, old_raw.io_write_bytes),
            ].iter().any(|(current, previous)| matches!((current, previous), (Some(current), Some(previous)) if current < previous)) {
                return Err(Error::Conflict("native counters rewound within one generation"));
            }
            let previous_cpu = if same_host_counter
                || (raw.host_counter_epoch.is_none() && generation == old_generation)
            {
                old_raw.cpu_micros
            } else {
                Some(Counter::ZERO)
            };
            let previous_read = if same_host_counter
                || (raw.host_counter_epoch.is_none() && generation == old_generation)
            {
                old_raw.io_read_bytes
            } else {
                Some(Counter::ZERO)
            };
            let previous_write = if same_host_counter
                || (raw.host_counter_epoch.is_none() && generation == old_generation)
            {
                old_raw.io_write_bytes
            } else {
                Some(Counter::ZERO)
            };
            value.cpu_micros =
                add_optional_observed(value.cpu_micros, raw.cpu_micros, previous_cpu)?;
            value.io_read_bytes =
                add_optional_observed(value.io_read_bytes, raw.io_read_bytes, previous_read)?;
            value.io_write_bytes =
                add_optional_observed(value.io_write_bytes, raw.io_write_bytes, previous_write)?;
            value.network_rx_bytes = add_observed(
                value.network_rx_bytes,
                raw.network_rx_bytes,
                if same_counter {
                    old_raw.network_rx_bytes
                } else {
                    Counter::ZERO
                },
            )?;
            value.network_tx_bytes = add_observed(
                value.network_tx_bytes,
                raw.network_tx_bytes,
                if same_counter {
                    old_raw.network_tx_bytes
                } else {
                    Counter::ZERO
                },
            )?;
            value.network_connections = add_observed(
                value.network_connections,
                raw.network_connections,
                if same_counter {
                    old_raw.network_connections
                } else {
                    Counter::ZERO
                },
            )?;
            value.memory_current = raw.memory_current;
            // These disjointly labelled observations retain their native
            // epoch. They are not another total or an additive consumption.
            value.cpu_ledgers = raw.cpu_ledgers.clone();
            value.memory_peak = value.memory_peak.max(raw.memory_peak);
            value.disk_logical_bytes = raw.disk_logical_bytes;
            value.disk_allocated_bytes = raw.disk_allocated_bytes;
            value.output_retained_bytes = raw.output_retained_bytes;
            value.executions_current = raw.executions_current;
            value.channels_current = raw.channels_current;
            value.inflight_requests_current = raw.inflight_requests_current;
            value.provenance = raw.provenance.clone();
            value.host_counter_epoch = raw.host_counter_epoch.clone();
            value.complete = value.complete && raw.complete;
            value.source = format!("host-catalog-cumulative({})", raw.source);
            value.observed_unix_millis = raw.observed_unix_millis;
            value
        } else {
            let mut value = raw.clone();
            value.source = format!("host-catalog-cumulative({})", raw.source);
            value
        };
        tx.execute(
            "INSERT INTO usage_observations VALUES (?1,?2,?3,?4) ON CONFLICT(machine) DO UPDATE SET generation=excluded.generation,raw=excluded.raw,cumulative=excluded.cumulative",
            params![
                machine.as_str(),
                generation.get(),
                encode(&raw)?,
                encode(&cumulative)?
            ],
        )?;
        tx.commit()?;
        Ok(cumulative)
    }

    /// Usage IDs survive rollback. Repeated delivery cannot double-charge.
    pub fn account(
        &mut self,
        id: &OperationId,
        machine: &MachineId,
        cpu: Counter,
        network: Counter,
    ) -> Result<()> {
        let identity = digest(Domain::Operation, &(machine, cpu, network))?;
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
                machine.as_str(),
                identity.as_str(),
                cpu.get(),
                network.get()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn usage(&self, machine: &MachineId) -> Result<(Counter, Counter)> {
        let (cpu, network): (u64, u64) = self.db.connection.query_row(
            "SELECT coalesce(sum(cpu),0),coalesce(sum(network),0) FROM usage WHERE machine=?1",
            [machine.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((cpu.try_into()?, network.try_into()?))
    }
}

fn add_observed(total: Counter, current: Counter, previous: Counter) -> Result<Counter> {
    let delta = if current >= previous {
        current.get() - previous.get()
    } else {
        current.get()
    };
    Ok(total.checked_add(delta)?)
}

fn add_optional_observed(
    total: Option<Counter>,
    current: Option<Counter>,
    previous: Option<Counter>,
) -> Result<Option<Counter>> {
    match (total, current, previous) {
        (Some(total), Some(current), Some(previous)) => {
            Ok(Some(add_observed(total, current, previous)?))
        }
        _ => Ok(None),
    }
}

// Defaults and configuration have separate storage columns, but their combined
// authority metadata must fit one control observation. Reserve space for later
// bounded lifecycle receipts, native observations and the authenticated envelope.
// Validate before admission commits, not while a recovery sweep tries to read it.
fn validate_machine_metadata(db: &rusqlite::Connection, machine: &MachineId) -> Result<()> {
    let record = machine_record(db, machine)?.ok_or(Error::Missing("machine is missing"))?;
    let mut page = ControlPage::with_envelope_bytes(32 * 1024)?;
    page.push(record).map_err(|_| {
        Error::Capacity("combined machine authority metadata exceeds control bound")
    })?;
    Ok(())
}

fn machine_record(db: &rusqlite::Connection, machine: &MachineId) -> Result<Option<MachineRecord>> {
    let row = db
        .query_row(
            "SELECT image,configuration,defaults,lifetime,activity,revision,released,sensitive FROM machines WHERE id=?1",
            [machine.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, bool>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        image,
        configuration,
        defaults,
        lifetime,
        activity,
        revision,
        released,
        known_sensitive,
    )) = row
    else {
        return Ok(None);
    };
    let latest: String = db.query_row(
        "SELECT value FROM intents WHERE machine=?1 ORDER BY rowid DESC LIMIT 1",
        [machine.as_str()],
        |row| row.get(0),
    )?;
    let reservation = match released {
        0 => ReservationState::Held,
        1 => ReservationState::Released,
        _ => return Err(Error::Corrupt("machine reservation flag is invalid")),
    };
    let configuration: RuntimeConfiguration = decode(&configuration)?;
    Ok(Some(MachineRecord {
        id: machine.clone(),
        image_digest: image.try_into()?,
        runtime_configuration: configuration,
        execution_defaults: decode(&defaults)?,
        lifetime: decode(&lifetime)?,
        last_activity_unix_millis: activity.try_into()?,
        configuration_revision: revision.try_into()?,
        reservation,
        known_sensitive,
        latest_intent: decode(&latest)?,
    }))
}

fn fork_record(db: &rusqlite::Connection, machine: &MachineId) -> Result<Option<ForkRecord>> {
    db.query_row(
        "SELECT value FROM forks WHERE machine=?1",
        [machine.as_str()],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| decode(&value))
    .transpose()
}

fn suspension_capture(db: &rusqlite::Connection, lifecycle: &LifecycleIntent) -> Result<Snapshot> {
    let id: String = db
        .query_row(
            "SELECT snapshot FROM suspension_captures WHERE lifecycle=?1",
            [lifecycle.operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(Error::Missing("suspension has no admitted capture"))?;
    let snapshot = snapshot_record(db, &id.try_into()?)?
        .ok_or(Error::Corrupt("suspension capture disappeared"))?;
    if lifecycle.desired != DesiredState::Suspended
        || snapshot.request.machine_id != lifecycle.machine_id
        || snapshot.request.expected_revision.next()? != lifecycle.revision
        || snapshot.request.kind != SnapshotKind::Full
        || !matches!(
            snapshot.phase,
            SnapshotPhase::Ready | SnapshotPhase::Retiring | SnapshotPhase::Released
        )
        || snapshot.full.is_none()
        || snapshot.manifest_digest.is_none()
    {
        return Err(Error::Conflict(
            "suspension requires its exact published full capture",
        ));
    }
    Ok(snapshot)
}

fn snapshot_record(db: &rusqlite::Connection, id: &SnapshotId) -> Result<Option<Snapshot>> {
    let raw = db
        .query_row(
            "SELECT value FROM snapshots WHERE id=?1",
            [id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    raw.map(|raw| {
        let value: Snapshot = decode(&raw)?;
        let expected = digest(Domain::Snapshot, &("sandsurf-snapshot-v1", &value.request))?;
        let empty = value.consistency.is_none()
            && value.system_disk_digest.is_none()
            && value.manifest_digest.is_none()
            && value.full.is_none();
        let published = value.consistency.is_some()
            && value.system_disk_digest.is_some()
            && value.manifest_digest.is_some()
            && (value.request.kind == SnapshotKind::Full) == value.full.is_some();
        let valid_capture = match value.phase {
            SnapshotPhase::Admitted | SnapshotPhase::Capturing => empty,
            SnapshotPhase::Ready => published,
            SnapshotPhase::Retiring | SnapshotPhase::Released => empty || published,
        };
        if value.request.id != *id || value.request_digest != expected || !valid_capture {
            return Err(Error::Corrupt("snapshot record is inconsistent"));
        }
        Ok(value)
    })
    .transpose()
}

fn reserve_compute(
    db: &rusqlite::Connection,
    excluding: Option<&MachineId>,
    requested: &Resources,
    limits: &CatalogLimits,
) -> Result<()> {
    let mut cpu = requested.cpu_quota_micros;
    let mut memory = requested.host_memory_bytes()?;
    let mut statement =
        db.prepare("SELECT configuration FROM machines WHERE released=0 AND id<>?1")?;
    for row in statement.query_map([excluding.map_or("", MachineId::as_str)], |row| {
        row.get::<_, String>(0)
    })? {
        let resources = decode::<RuntimeConfiguration>(&row?)?.resources;
        cpu = cpu.checked_add(resources.cpu_quota_micros.get())?;
        memory = memory.checked_add(resources.host_memory_bytes()?.get())?;
    }
    if cpu > limits.cpu_quota_micros || memory > limits.host_memory_bytes {
        return Err(Error::Capacity("host compute reservations exhausted"));
    }
    // Destruction releases compute only. The mounted machine volume remains
    // exclusive and independently retains its archives and snapshot bytes;
    // this admission decision neither reclaims it nor spends host-volume bytes.
    Ok(())
}

fn snapshot_charge(resources: &Resources, kind: SnapshotKind) -> Result<u64> {
    let mut bytes = resources.disk_bytes.get();
    if kind == SnapshotKind::Full {
        bytes = bytes
            .checked_add(
                resources
                    .memory_mib
                    .get()
                    .checked_mul(1024 * 1024)
                    .ok_or(Error::Capacity("snapshot RAM reservation overflow"))?,
            )
            .ok_or(Error::Capacity("snapshot reservation overflow"))?;
    }
    bytes
        .checked_add(64 * 1024 * 1024)
        .and_then(|value| value.checked_mul(2))
        .ok_or(Error::Capacity(
            "snapshot staging/publication reservation overflow",
        ))
}

fn snapshot_capacity_held(db: &rusqlite::Connection, machine: &MachineId) -> Result<u64> {
    let mut statement = db.prepare("SELECT value FROM snapshots WHERE machine=?1 AND json_extract(value,'$.phase') IS NOT 'released'")?;
    let mut total = 0_u64;
    for row in statement.query_map([machine.as_str()], |row| row.get::<_, String>(0))? {
        let record: Snapshot = decode(&row?)?;
        // Interrupted captures and published bytes retain capacity until the
        // storage owner confirms actual deletion; VM destruction is irrelevant.
        total = total
            .checked_add(snapshot_charge(&record.resources, record.request.kind)?)
            .ok_or(Error::Capacity("retained snapshot capacity overflow"))?;
    }
    Ok(total)
}

fn reserve_snapshot_capacity(
    db: &rusqlite::Connection,
    machine: &MachineId,
    resources: &Resources,
    kind: SnapshotKind,
) -> Result<()> {
    let total = snapshot_capacity_held(db, machine)?
        .checked_add(snapshot_charge(resources, kind)?)
        .ok_or(Error::Capacity("snapshot reservation overflow"))?;
    if total > resources.snapshot_bytes.get() {
        return Err(Error::Capacity(
            "snapshot physical storage budget exhausted",
        ));
    }
    Ok(())
}

fn secret_version_revoked(
    db: &rusqlite::Connection,
    machine: &MachineId,
    secret: &SecretVersion,
) -> Result<bool> {
    Ok(secret_revocation_operation(db, machine, secret)?.is_some())
}

fn secret_revocation_operation(
    db: &rusqlite::Connection,
    machine: &MachineId,
    secret: &SecretVersion,
) -> Result<Option<OperationId>> {
    let row: Option<(String, String)> = db
        .query_row(
            SECRET_REVOCATION_OBSERVATION,
            params![
                machine.as_str(),
                secret.id.as_str(),
                secret.version.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(operation, value)| {
        let record: SecretRevocationRecord = decode(&value)?;
        if record.operation_id.as_str() != operation
            || record.machine_id != *machine
            || record.secret.id != secret.id
            || record.secret.version != secret.version
        {
            return Err(Error::Corrupt(
                "secret revocation authority binding changed",
            ));
        }
        Ok(record.operation_id)
    })
    .transpose()
}

fn observe_secret_delivery(
    db: &rusqlite::Connection,
    record: StoredSecretDelivery,
) -> Result<SecretDeliveryRecord> {
    let revocation_operation =
        secret_revocation_operation(db, &record.machine_id, &record.delivery.secret)?;
    Ok(SecretDeliveryRecord {
        operation_id: record.operation_id,
        machine_id: record.machine_id,
        request_digest: record.request_digest,
        delivery: record.delivery,
        disclosure: record.disclosure,
        revoked: revocation_operation.is_some(),
        revocation_operation,
    })
}

fn initial_runtime_configuration(resources: &Resources) -> Result<RuntimeConfiguration> {
    Ok(RuntimeConfiguration {
        network: NetworkPolicy::default(),
        exposures: Vec::new(),
        resources: resources.clone(),
    })
}

fn revision(db: &rusqlite::Connection, machine: &MachineId) -> Result<Counter> {
    let record =
        machine_record(db, machine)?.ok_or(Error::Missing("machine identity is missing"))?;
    if record.reservation == ReservationState::Released
        || (record.latest_intent.desired == DesiredState::Destroyed
            && record.latest_intent.completion.is_some())
    {
        return Err(Error::Missing("machine identity is retired"));
    }
    Ok(record.configuration_revision)
}
fn require_revision(
    db: &rusqlite::Connection,
    machine: &MachineId,
    expected: Counter,
) -> Result<()> {
    if revision(db, machine)? != expected {
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
fn pending_rollback_record(
    db: &rusqlite::Connection,
    machine: &MachineId,
) -> Result<Option<RollbackRecord>> {
    let mut statement = db.prepare(
        "SELECT value FROM rollbacks WHERE machine=?1 AND json_extract(value,'$.phase') IS NOT 'applied' LIMIT 2",
    )?;
    let values = statement
        .query_map([machine.as_str()], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    match values.as_slice() {
        [] => Ok(None),
        [value] => {
            let record: RollbackRecord = decode(value)?;
            if record.machine_id != *machine || record.phase != RollbackPhase::Admitted {
                return Err(Error::Corrupt(
                    "pending disk replacement binding is invalid",
                ));
            }
            Ok(Some(record))
        }
        _ => Err(Error::Corrupt(
            "machine has competing pending disk replacements",
        )),
    }
}

fn host_operation_identity_available(
    db: &rusqlite::Connection,
    operation: &OperationId,
) -> Result<()> {
    let used: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM intents WHERE id=?1) OR EXISTS(SELECT 1 FROM configuration_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM transfer_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM image_imports WHERE operation=?1) OR EXISTS(SELECT 1 FROM image_releases WHERE operation=?1) OR EXISTS(SELECT 1 FROM secret_puts WHERE operation=?1) OR EXISTS(SELECT 1 FROM secret_deliveries WHERE operation=?1) OR EXISTS(SELECT 1 FROM secret_revocations WHERE operation=?1) OR EXISTS(SELECT 1 FROM snapshots WHERE operation=?1) OR EXISTS(SELECT 1 FROM snapshot_releases WHERE operation=?1) OR EXISTS(SELECT 1 FROM rollbacks WHERE operation=?1)",
        [operation.as_str()],
        |row| row.get(0),
    )?;
    if used {
        Err(Error::Conflict(
            "host operation identity already belongs to another operation",
        ))
    } else {
        Ok(())
    }
}

fn current_unix_millis() -> Result<Counter> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Conflict("host wall clock is before the Unix generation"))?
        .as_millis();
    let millis = u64::try_from(millis)
        .map_err(|_| Error::Capacity("host wall clock exceeds the counter range"))?;
    millis.try_into().map_err(Error::from)
}

fn image_record(db: &rusqlite::Connection, digest: &Digest) -> Result<Option<ImageRecord>> {
    Ok(image_state(db, digest)?.map(|(image, _, _)| image))
}

fn image_state(
    db: &rusqlite::Connection,
    digest: &Digest,
) -> Result<Option<(ImageRecord, bool, bool)>> {
    db.query_row(
        "SELECT value,retired,EXISTS(SELECT 1 FROM image_releases r WHERE r.image=images.digest AND r.cleanup_pending=1) FROM images WHERE digest=?1",
        [digest.as_str()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, bool>(2)?,
            ))
        },
    )
    .optional()?
    .map(|(value, retired, cleanup)| Ok((decode(&value)?, retired, cleanup)))
    .transpose()
}

const IMAGE_RESERVATION_IDENTITIES: &str = "SELECT (SELECT count(*) FROM images)+(SELECT count(*) FROM (SELECT json_extract(candidate,'$.digest') FROM image_imports i WHERE json_extract(phase,'$')='prepared' AND NOT EXISTS(SELECT 1 FROM images WHERE digest=json_extract(i.candidate,'$.digest')) GROUP BY json_extract(candidate,'$.digest')))+CASE WHEN EXISTS(SELECT 1 FROM images WHERE digest=?1) OR EXISTS(SELECT 1 FROM image_imports WHERE json_extract(phase,'$')='prepared' AND json_extract(candidate,'$.digest')=?1) THEN 0 ELSE 1 END";
const IMAGE_RESERVATION_STORAGE: &str = "SELECT value FROM images WHERE retired=0 OR EXISTS(SELECT 1 FROM image_releases r WHERE r.image=images.digest AND r.cleanup_pending=1) UNION ALL SELECT candidate FROM image_imports i WHERE json_extract(phase,'$')='prepared' AND NOT EXISTS(SELECT 1 FROM images WHERE digest=json_extract(i.candidate,'$.digest') AND (retired=0 OR EXISTS(SELECT 1 FROM image_releases r WHERE r.image=images.digest AND r.cleanup_pending=1))) GROUP BY json_extract(candidate,'$.digest')";

/// Derive admission from canonical rows without materializing the entire
/// image catalog in the API owner's bounded heap. The expression index groups
/// candidates by immutable identity; an already retained image is charged once.
fn image_reservations(db: &rusqlite::Connection, incoming: &ImageRecord) -> Result<(u64, u64)> {
    let previous: Option<String> = db.query_row(
        "SELECT candidate FROM image_imports WHERE json_extract(phase,'$')='prepared' AND json_extract(candidate,'$.digest')=?1 LIMIT 1",
        [incoming.digest.as_str()], |row| row.get(0),
    ).optional()?;
    if previous
        .map(|value| decode::<ImageRecord>(&value))
        .transpose()?
        .as_ref()
        .is_some_and(|previous| previous != incoming)
    {
        return Err(Error::Conflict("image candidate metadata changed"));
    }
    let identities: u64 = db.query_row(
        IMAGE_RESERVATION_IDENTITIES,
        [incoming.digest.as_str()],
        |row| row.get(0),
    )?;
    // Retirement gates attachments immediately, but its bytes stay reserved
    // until exact artifact cleanup completes. Prepared candidates against that
    // same identity cannot be admitted until cleanup completes either.
    let mut statement = db.prepare(IMAGE_RESERVATION_STORAGE)?;
    let mut rows = statement.query([])?;
    let mut total = 0_u64;
    let mut includes_incoming = false;
    while let Some(row) = rows.next()? {
        let image: ImageRecord = decode(&row.get::<_, String>(0)?)?;
        if image.digest == incoming.digest {
            if image != *incoming {
                return Err(Error::Corrupt(
                    "image reservations disagree about immutable metadata",
                ));
            }
            includes_incoming = true;
        }
        total = total
            .checked_add(image.storage_bytes.get())
            .ok_or(Error::Capacity("image storage reservation overflow"))?;
    }
    if !includes_incoming {
        total = total
            .checked_add(incoming.storage_bytes.get())
            .ok_or(Error::Capacity("image storage reservation overflow"))?;
    }
    Ok((identities, total))
}

fn image_release(
    db: &rusqlite::Connection,
    operation: &OperationId,
) -> Result<Option<ImageReleaseRecord>> {
    db.query_row(
        "SELECT image,request_digest,cleanup_pending FROM image_releases WHERE operation=?1",
        [operation.as_str()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
            ))
        },
    )
    .optional()?
    .map(|(image, request, cleanup_pending)| {
        Ok(ImageReleaseRecord {
            operation_id: operation.clone(),
            image_digest: image.try_into()?,
            request_digest: request.try_into()?,
            cleanup_pending,
        })
    })
    .transpose()
}

fn snapshot_release(
    db: &rusqlite::Connection,
    operation: &OperationId,
) -> Result<Option<SnapshotReleaseRecord>> {
    db.query_row(
        "SELECT snapshot,value FROM snapshot_releases WHERE operation=?1",
        [operation.as_str()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .optional()?
    .map(|(id, value)| {
        let record: SnapshotReleaseRecord = decode(&value)?;
        let snapshot = snapshot_record(db, &record.snapshot_id)?
            .ok_or(Error::Corrupt("snapshot retirement lost its payload owner"))?;
        if record.operation_id != *operation
            || record.snapshot_id.as_str() != id
            || record.machine_id != snapshot.request.machine_id
            || record.request_digest
                != digest(
                    Domain::Snapshot,
                    &(
                        "sandsurf-release-snapshot-v1",
                        operation,
                        &record.snapshot_id,
                    ),
                )?
            || snapshot.phase
                != if record.cleanup_pending {
                    SnapshotPhase::Retiring
                } else {
                    SnapshotPhase::Released
                }
        {
            return Err(Error::Corrupt("snapshot retirement binding changed"));
        }
        Ok(record)
    })
    .transpose()
}

fn require_image(db: &rusqlite::Connection, image: &Digest) -> Result<()> {
    if image_state(db, image)?.is_none_or(|(_, retired, _)| retired) {
        return Err(Error::Missing("image build dependency is not admitted"));
    }
    Ok(())
}

fn image_import_input(
    db: &rusqlite::Connection,
    operation: &OperationId,
) -> Result<Option<ImageImportInput>> {
    let input: Option<(String, String)> = db
        .query_row(
            "SELECT input,request_digest FROM image_imports WHERE operation=?1",
            [operation.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    input
        .map(|(input, request)| decode_image_input(operation, &request, &input))
        .transpose()
}

fn decode_image_input(
    operation: &OperationId,
    request: &str,
    input: &str,
) -> Result<ImageImportInput> {
    let input: ImageImportInput = decode(input)?;
    if input.request_digest(operation)?.as_str() != request {
        return Err(Error::Corrupt("image input and approved request disagree"));
    }
    Ok(input)
}

fn image_import(
    db: &rusqlite::Connection,
    operation: &OperationId,
) -> Result<Option<ImageImportRecord>> {
    struct ImportRow {
        request_digest: String,
        phase: String,
        candidate: Option<String>,
        published: Option<String>,
        input: String,
    }
    let row = db
        .query_row(
            "SELECT request_digest,phase,candidate,image,input FROM image_imports WHERE operation=?1",
            [operation.as_str()],
            |row| Ok(ImportRow { request_digest: row.get(0)?, phase: row.get(1)?, candidate: row.get(2)?, published: row.get(3)?, input: row.get(4)? }),
        )
        .optional()?;
    row.map(
        |ImportRow {
             request_digest,
             phase,
             candidate,
             published,
             input,
         }| {
            decode_image_input(operation, &request_digest, &input)?;
            let phase: ImageImportPhase = decode(&phase)?;
            if match phase {
                ImageImportPhase::Admitted
                | ImageImportPhase::Cancelling
                | ImageImportPhase::Cancelled => candidate.is_some() || published.is_some(),
                ImageImportPhase::Prepared => candidate.is_none() || published.is_some(),
                ImageImportPhase::Published => candidate.is_some() || published.is_none(),
            } {
                return Err(Error::Corrupt("image import phase and result disagree"));
            }
            let image = published
                .map(|digest| {
                    image_record(db, &Digest::try_from(digest)?)?
                        .ok_or(Error::Corrupt("published image import has no image record"))
                })
                .transpose()?;
            let image = image.or(candidate.map(|value| decode(&value)).transpose()?);
            Ok(ImageImportRecord {
                operation_id: operation.clone(),
                request_digest: request_digest.try_into()?,
                phase,
                image,
            })
        },
    )
    .transpose()
}
fn control_page<T: Serialize>(rows: impl IntoIterator<Item = Result<T>>) -> Result<Vec<T>> {
    let mut page = ControlPage::default();
    for row in rows {
        if !page.push(row?)? {
            break;
        }
    }
    Ok(page.into_values())
}

fn save_intent(db: &rusqlite::Connection, value: &LifecycleIntent) -> Result<()> {
    db.execute(
        "INSERT INTO intents VALUES (?1,?2,?3,?4)",
        params![
            value.operation_id.as_str(),
            value.machine_id.as_str(),
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

#[cfg(test)]
mod admission_query_tests {
    use super::*;

    #[test]
    fn actual_admission_queries_stream_indexed_identities_without_temporary_catalogs() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        for query in [IMAGE_RESERVATION_IDENTITIES, IMAGE_RESERVATION_STORAGE] {
            let mut statement = db.prepare(&format!("EXPLAIN QUERY PLAN {query}")).unwrap();
            let parameters = vec!["a".repeat(64); statement.parameter_count()];
            let mut rows = statement
                .query(rusqlite::params_from_iter(parameters.iter()))
                .unwrap();
            let mut indexed = false;
            while let Some(row) = rows.next().unwrap() {
                let detail: String = row.get(3).unwrap();
                assert!(!detail.contains("USE TEMP B-TREE"), "{detail}");
                indexed |= detail.contains("prepared_image_target");
            }
            assert!(
                indexed,
                "prepared identity accounting lost its expression index"
            );
        }
    }

    #[test]
    fn secret_decisions_and_bounded_cleanup_use_their_exact_version_indexes() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        for (query, index) in [
            (SECRET_CLEANUP_SELECTION, "secret_delivery_version"),
            (SECRET_REVOCATION_OBSERVATION, "secret_revocation_version"),
        ] {
            let mut statement = db.prepare(&format!("EXPLAIN QUERY PLAN {query}")).unwrap();
            let mut rows = statement
                .query(["machine", "credential", "opaque-version"])
                .unwrap();
            let mut indexed = false;
            while let Some(row) = rows.next().unwrap() {
                let detail: String = row.get(3).unwrap();
                assert!(!detail.contains("USE TEMP B-TREE"), "{detail}");
                assert!(!detail.starts_with("SCAN secret_"), "{detail}");
                indexed |= detail.contains(index);
            }
            assert!(
                indexed,
                "secret admission lost its indexed audience/version boundary"
            );
        }
    }
}
