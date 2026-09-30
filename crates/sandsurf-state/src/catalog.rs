use crate::{Error, Result, authority::HostAuthority, database::Database, decode, encode};
use rusqlite::{OptionalExtension, params};
use sandsurf_protocol::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE configuration(id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, limits TEXT NOT NULL, authority TEXT NOT NULL) STRICT;
CREATE TABLE machines(id TEXT PRIMARY KEY, image TEXT NOT NULL, configuration TEXT NOT NULL, defaults TEXT NOT NULL, lifetime TEXT NOT NULL, activity INTEGER NOT NULL, revision INTEGER NOT NULL, sensitive INTEGER NOT NULL CHECK(sensitive IN (0,1)), released INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE intents(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE configuration_operations(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE transfer_operations(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE usage(id TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), digest TEXT NOT NULL, cpu INTEGER NOT NULL, network INTEGER NOT NULL) STRICT;
CREATE TABLE approvals(id TEXT PRIMARY KEY, digest TEXT NOT NULL) STRICT;
CREATE TABLE image_imports(operation TEXT PRIMARY KEY, request_digest TEXT NOT NULL, phase TEXT NOT NULL, image TEXT) STRICT;
CREATE TABLE images(digest TEXT PRIMARY KEY, value TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0, cleanup_pending INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE image_releases(operation TEXT PRIMARY KEY, image TEXT NOT NULL REFERENCES images(digest), request_digest TEXT NOT NULL, cleanup_pending INTEGER NOT NULL) STRICT;
CREATE TABLE secret_deliveries(operation TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE secret_revocations(operation TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE secret_puts(operation TEXT PRIMARY KEY, request_digest TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE snapshots(id TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL, machine TEXT NOT NULL REFERENCES machines(id), value TEXT NOT NULL) STRICT;
CREATE TABLE rollbacks(operation TEXT PRIMARY KEY, machine TEXT NOT NULL REFERENCES machines(id), value TEXT NOT NULL) STRICT;
CREATE TABLE usage_observations(machine TEXT PRIMARY KEY REFERENCES machines(id), generation INTEGER NOT NULL, raw TEXT NOT NULL, cumulative TEXT NOT NULL) STRICT;
CREATE TABLE suspensions(machine TEXT PRIMARY KEY REFERENCES machines(id), value TEXT NOT NULL) STRICT;
";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogLimits {
    pub identities: Counter,
    pub operations: Counter,
    pub usage_records: Counter,
    pub image_bytes: Counter,
    pub resources: Resources,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
        limits.resources.validate()?;
        if [
            limits.identities,
            limits.operations,
            limits.usage_records,
            limits.image_bytes,
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
        if let Some(value) = db
            .query_row(
                "SELECT value FROM secret_deliveries WHERE operation=?1",
                [operation.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            result.push(HostOperationRecord::SecretDelivery(decode(&value)?));
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
        record: SecretDeliveryRecord,
        expected_revision: Counter,
        approval: Approval,
    ) -> Result<SecretDeliveryRecord> {
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
            let old: SecretDeliveryRecord = decode(&encoded)?;
            if old.request_digest == record.request_digest {
                return Ok(old);
            }
            return Err(Error::Conflict(
                "secret delivery operation identity conflict",
            ));
        }
        host_operation_identity_available(&tx, &record.operation_id)?;
        require_revision(&tx, &record.machine_id, expected_revision)?;
        if record.revoked
            || record.revocation_operation.is_some()
            || record.disclosure != SecretDisclosure::NotSent
            || secret_version_revoked(&tx, &record.machine_id, &record.delivery.secret)?
        {
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
        Ok(record)
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
        let mut record: SecretDeliveryRecord = decode(&raw)?;
        if record.disclosure != SecretDisclosure::NotSent
            || record.revoked
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
        Ok(record)
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
        let mut record: SecretDeliveryRecord = decode(&raw)?;
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
        Ok(record)
    }

    pub fn secret_version_revoked(
        &self,
        machine: &MachineId,
        secret: &SecretVersion,
    ) -> Result<bool> {
        secret_version_revoked(&self.db.connection, machine, secret)
    }

    pub fn secret_deliveries(&self, machine: &MachineId) -> Result<Vec<SecretDeliveryRecord>> {
        let mut statement = self
            .db
            .connection
            .prepare("SELECT value FROM secret_deliveries WHERE machine=?1 ORDER BY rowid ASC")?;
        statement
            .query_map([machine.as_str()], |row| row.get::<_, String>(0))?
            .map(|value| decode(&value?))
            .collect()
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
        let mut statement = tx.prepare(
            "SELECT operation,value FROM secret_deliveries WHERE machine=?1 ORDER BY rowid ASC",
        )?;
        let encoded = statement
            .query_map([request.machine_id.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut deliveries = Vec::new();
        let mut updates = Vec::new();
        for (delivery_operation, value) in encoded {
            let mut record: SecretDeliveryRecord = decode(&value)?;
            if !record.revoked
                && record.delivery.secret == request.secret
                && record
                    .revocation_operation
                    .as_ref()
                    .is_none_or(|value| value == &request.operation_id)
            {
                record.revocation_operation = Some(request.operation_id.clone());
                record.revoked = true;
                deliveries.push(record.delivery.clone());
                updates.push((delivery_operation, encode(&record)?));
            }
        }
        if deliveries.len() > 1024 {
            return Err(Error::Capacity(
                "secret revocation delivery set is oversized",
            ));
        }
        capacity(&tx, "secret_revocations", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let record = SecretRevocationRecord {
            operation_id: request.operation_id,
            machine_id: request.machine_id,
            request_digest: request.request_digest,
            secret: request.secret,
            deliveries,
            terminate_recipients: request.terminate_recipients,
            guest_cleanup_report: None,
        };
        for (delivery_operation, value) in updates {
            tx.execute(
                "UPDATE secret_deliveries SET value=?2 WHERE operation=?1",
                params![delivery_operation, value],
            )?;
        }
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

    pub fn secret_revocations(&self, machine: &MachineId) -> Result<Vec<SecretRevocationRecord>> {
        let mut statement = self
            .db
            .connection
            .prepare("SELECT value FROM secret_revocations WHERE machine=?1 ORDER BY rowid ASC")?;
        statement
            .query_map([machine.as_str()], |row| row.get::<_, String>(0))?
            .map(|value| decode(&value?))
            .collect()
    }

    /// Admit an image command before any source is read or builder is run.
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
        host_operation_identity_available(&tx, &operation_id)?;
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
        } else {
            capacity(&tx, "images", self.limits.identities)?;
        }
        if existing.as_ref().is_none_or(|(_, retired, _)| *retired) {
            let mut reserved = image_storage_bytes(&tx)?;
            reserved = reserved
                .checked_add(image.storage_bytes.get())
                .ok_or(Error::Capacity("image storage reservation overflow"))?;
            if reserved > self.limits.image_bytes.get() {
                return Err(Error::Capacity("image storage reservation exhausted"));
            }
        }
        if existing.is_some() {
            tx.execute(
                "UPDATE images SET retired=0,cleanup_pending=0 WHERE digest=?1",
                [image.digest.as_str()],
            )?;
        } else {
            tx.execute(
                "INSERT INTO images VALUES (?1,?2,0,0)",
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
        statement
            .query_map(
                params![after.map_or("", Digest::as_str), limit.get()],
                |row| row.get::<_, String>(0),
            )?
            .map(|value| decode(&value?))
            .collect()
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
        let mut statement = tx.prepare("SELECT value FROM snapshots")?;
        let snapshots = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for snapshot in snapshots {
            if decode::<Snapshot>(&snapshot)?.image_digest == image_digest {
                return Err(Error::Conflict("retained snapshots pin this image"));
            }
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
            "UPDATE images SET retired=1,cleanup_pending=1 WHERE digest=?1",
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
        tx.execute(
            "UPDATE images SET cleanup_pending=0 WHERE digest=?1",
            [value.image_digest.as_str()],
        )?;
        tx.commit()?;
        value.cleanup_pending = false;
        Ok(value)
    }

    pub fn pending_image_releases(&self) -> Result<Vec<ImageReleaseRecord>> {
        let mut statement = self.db.connection.prepare(
            "SELECT operation,image,request_digest,cleanup_pending FROM image_releases WHERE cleanup_pending=1 ORDER BY operation",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            })?
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

    pub fn suspension(&self, machine: &MachineId) -> Result<Option<SuspensionRecord>> {
        self.db
            .connection
            .query_row(
                "SELECT value FROM suspensions WHERE machine=?1",
                [machine.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| decode(&value))
            .transpose()
    }

    pub fn record_suspension(
        &mut self,
        machine: &MachineId,
        lifecycle_operation: &OperationId,
        snapshot_id: &SnapshotId,
        manifest_digest: &Digest,
    ) -> Result<SuspensionRecord> {
        let tx = self.db.connection.transaction()?;
        let snapshot = snapshot_record(&tx, snapshot_id)?
            .ok_or(Error::Missing("suspension snapshot is missing"))?;
        let lifecycle = intent(&tx, lifecycle_operation)?
            .ok_or(Error::Missing("suspension lifecycle intent is missing"))?;
        if snapshot.request.machine_id != *machine
            || snapshot.request.kind != SnapshotKind::Full
            || snapshot.phase != SnapshotPhase::Ready
            || snapshot.manifest_digest.as_ref() != Some(manifest_digest)
            || snapshot.full.is_none()
            || lifecycle.machine_id != *machine
            || lifecycle.desired != DesiredState::Suspended
            || lifecycle.completion.is_none()
        {
            return Err(Error::Conflict(
                "suspension association lacks snapshot or lifecycle completion",
            ));
        }
        let value = SuspensionRecord {
            machine_id: machine.clone(),
            lifecycle_operation_id: lifecycle_operation.clone(),
            snapshot_id: snapshot_id.clone(),
            manifest_digest: manifest_digest.clone(),
        };
        if let Some(old) = tx
            .query_row(
                "SELECT value FROM suspensions WHERE machine=?1",
                [machine.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|encoded| decode::<SuspensionRecord>(&encoded))
            .transpose()?
        {
            return if old == value {
                Ok(old)
            } else {
                Err(Error::Conflict(
                    "machine is already bound to another suspension snapshot",
                ))
            };
        }
        tx.execute(
            "INSERT INTO suspensions VALUES (?1,?2)",
            params![machine.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn clear_suspension(
        &mut self,
        machine: &MachineId,
        snapshot_id: &SnapshotId,
    ) -> Result<()> {
        let tx = self.db.connection.transaction()?;
        let value = tx
            .query_row(
                "SELECT value FROM suspensions WHERE machine=?1",
                [machine.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|encoded| decode::<SuspensionRecord>(&encoded))
            .transpose()?
            .ok_or(Error::Missing("suspension association is missing"))?;
        if value.snapshot_id != *snapshot_id {
            return Err(Error::Conflict("suspension snapshot identity changed"));
        }
        tx.execute(
            "DELETE FROM suspensions WHERE machine=?1",
            [machine.as_str()],
        )?;
        tx.commit()?;
        Ok(())
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
        let mut values = Vec::new();
        for row in rows {
            let id: SnapshotId = row?.try_into()?;
            values.push(
                snapshot_record(&self.db.connection, &id)?.ok_or(Error::Corrupt(
                    "listed snapshot disappeared from the catalog",
                ))?,
            );
        }
        Ok(values)
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
            return if old.request_digest == request_digest {
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
        identities
            .into_iter()
            .map(|id| {
                let id: MachineId = id.try_into()?;
                machine_record(&self.db.connection, &id)?.ok_or(Error::Corrupt(
                    "listed machine disappeared from the host transaction view",
                ))
            })
            .collect()
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
        let image_state = image_state(&tx, &image)?;
        if image_state.as_ref().is_some_and(|(_, retired, _)| *retired) {
            return Err(Error::Conflict("machine image is retired"));
        }
        let sensitive = image_state.is_some_and(|(image, _, _)| image.sensitive);
        let mut total = resources.clone();
        {
            let mut statement =
                tx.prepare("SELECT configuration FROM machines WHERE released=0")?;
            let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
            for row in rows {
                total = total.checked_add(&decode::<RuntimeConfiguration>(&row?)?.resources)?;
            }
        }
        if !total.within(&self.limits.resources) {
            return Err(Error::Capacity("host resource reservations exhausted"));
        }
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
        let mut total = resources.clone();
        let mut statement = tx.prepare("SELECT configuration FROM machines WHERE released=0")?;
        for row in statement.query_map([], |row| row.get::<_, String>(0))? {
            total = total.checked_add(&decode::<RuntimeConfiguration>(&row?)?.resources)?;
        }
        drop(statement);
        if !total.within(&self.limits.resources) {
            return Err(Error::Capacity("host resource reservations exhausted"));
        }
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
        let value = LifecycleIntent {
            machine_id: id,
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
                "sandsurf-apply-configuration-v2",
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
        let mut total = resources.clone();
        {
            let mut statement =
                tx.prepare("SELECT configuration FROM machines WHERE released=0 AND id<>?1")?;
            for row in statement.query_map([machine.as_str()], |row| row.get::<_, String>(0))? {
                total = total.checked_add(&decode::<RuntimeConfiguration>(&row?)?.resources)?;
            }
        }
        if !total.within(&self.limits.resources) {
            return Err(Error::Capacity("host resource reservations exhausted"));
        }
        record_approval(&tx, &approval, self.limits.operations)?;
        let encoded: String = tx.query_row(
            "SELECT configuration FROM machines WHERE id=?1",
            [machine.as_str()],
            |row| row.get(0),
        )?;
        let mut configuration: RuntimeConfiguration = decode(&encoded)?;
        configuration.resources = resources.clone();
        let revision = expected.next()?;
        tx.execute(
            "UPDATE machines SET configuration=?2,revision=?3 WHERE id=?1",
            params![machine.as_str(), encode(&configuration)?, revision.get()],
        )?;
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
            if generation == old_generation
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
            if generation == old_generation && [
                (raw.cpu_micros, old_raw.cpu_micros),
                (raw.io_read_bytes, old_raw.io_read_bytes),
                (raw.io_write_bytes, old_raw.io_write_bytes),
            ].iter().any(|(current, previous)| matches!((current, previous), (Some(current), Some(previous)) if current < previous)) {
                return Err(Error::Conflict("native counters rewound within one generation"));
            }
            let previous_cpu = if generation == old_generation {
                old_raw.cpu_micros
            } else {
                Some(Counter::ZERO)
            };
            let previous_read = if generation == old_generation {
                old_raw.io_read_bytes
            } else {
                Some(Counter::ZERO)
            };
            let previous_write = if generation == old_generation {
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
                old_raw.network_rx_bytes,
            )?;
            value.network_tx_bytes = add_observed(
                value.network_tx_bytes,
                raw.network_tx_bytes,
                old_raw.network_tx_bytes,
            )?;
            value.network_connections = add_observed(
                value.network_connections,
                raw.network_connections,
                old_raw.network_connections,
            )?;
            value.memory_current = raw.memory_current;
            value.memory_peak = value.memory_peak.max(raw.memory_peak);
            value.disk_logical_bytes = raw.disk_logical_bytes;
            value.disk_allocated_bytes = raw.disk_allocated_bytes;
            value.output_retained_bytes = raw.output_retained_bytes;
            value.executions_current = raw.executions_current;
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
        if value.request.id != *id
            || value.request_digest != expected
            || (value.phase == SnapshotPhase::Ready)
                != (value.consistency.is_some()
                    && value.system_disk_digest.is_some()
                    && value.manifest_digest.is_some())
        {
            return Err(Error::Corrupt("snapshot record is inconsistent"));
        }
        Ok(value)
    })
    .transpose()
}

fn secret_version_revoked(
    db: &rusqlite::Connection,
    machine: &MachineId,
    secret: &SecretVersion,
) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM secret_revocations WHERE machine=?1 AND json_extract(value,'$.secret.id')=?2 AND json_extract(value,'$.secret.version')=?3)",
        params![machine.as_str(), secret.id.as_str(), secret.version.as_str()], |row| row.get(0))?)
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
fn host_operation_identity_available(
    db: &rusqlite::Connection,
    operation: &OperationId,
) -> Result<()> {
    let used: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM intents WHERE id=?1) OR EXISTS(SELECT 1 FROM configuration_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM transfer_operations WHERE id=?1) OR EXISTS(SELECT 1 FROM image_imports WHERE operation=?1) OR EXISTS(SELECT 1 FROM image_releases WHERE operation=?1) OR EXISTS(SELECT 1 FROM secret_puts WHERE operation=?1) OR EXISTS(SELECT 1 FROM secret_deliveries WHERE operation=?1) OR EXISTS(SELECT 1 FROM secret_revocations WHERE operation=?1) OR EXISTS(SELECT 1 FROM snapshots WHERE operation=?1) OR EXISTS(SELECT 1 FROM rollbacks WHERE operation=?1)",
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
        "SELECT value,retired,cleanup_pending FROM images WHERE digest=?1",
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

fn image_storage_bytes(db: &rusqlite::Connection) -> Result<u64> {
    // Retirement gates new attachments immediately, but its storage remains
    // reserved until exact artifact cleanup is durably complete.
    let mut statement =
        db.prepare("SELECT value FROM images WHERE retired=0 OR cleanup_pending=1")?;
    let values = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut total = 0_u64;
    for value in values {
        total = total
            .checked_add(decode::<ImageRecord>(&value)?.storage_bytes.get())
            .ok_or(Error::Capacity("image storage reservation overflow"))?;
    }
    Ok(total)
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
