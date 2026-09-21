use crate::{Error, Result, authority::HostAuthority, database::Database, decode, encode};
use rusqlite::{OptionalExtension, params};
use sandsurf_protocol::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE configuration(id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, limits TEXT NOT NULL, authority TEXT NOT NULL) STRICT;
CREATE TABLE sandboxes(id TEXT PRIMARY KEY, image TEXT NOT NULL, resources TEXT NOT NULL, configuration TEXT NOT NULL, revision INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE intents(id TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), request TEXT NOT NULL, value TEXT NOT NULL) STRICT;
CREATE TABLE grants(id TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), value TEXT NOT NULL) STRICT;
CREATE TABLE usage(id TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), digest TEXT NOT NULL, cpu INTEGER NOT NULL, network INTEGER NOT NULL) STRICT;
CREATE TABLE approvals(id TEXT PRIMARY KEY, digest TEXT NOT NULL) STRICT;
CREATE TABLE image_imports(operation TEXT PRIMARY KEY, request_digest TEXT NOT NULL, phase TEXT NOT NULL, image TEXT) STRICT;
CREATE TABLE images(digest TEXT PRIMARY KEY, value TEXT NOT NULL, retired INTEGER NOT NULL DEFAULT 0, cleanup_pending INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE image_releases(operation TEXT PRIMARY KEY, image TEXT NOT NULL REFERENCES images(digest), request_digest TEXT NOT NULL, cleanup_pending INTEGER NOT NULL) STRICT;
CREATE TABLE secret_deliveries(operation TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), request_digest TEXT NOT NULL, value TEXT NOT NULL, applied INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE secret_revocations(operation TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), request_digest TEXT NOT NULL, value TEXT NOT NULL, enforced INTEGER NOT NULL DEFAULT 0) STRICT;
CREATE TABLE checkpoints(id TEXT PRIMARY KEY, operation TEXT UNIQUE NOT NULL, sandbox TEXT NOT NULL REFERENCES sandboxes(id), value TEXT NOT NULL) STRICT;
CREATE TABLE rollbacks(operation TEXT PRIMARY KEY, sandbox TEXT NOT NULL REFERENCES sandboxes(id), value TEXT NOT NULL) STRICT;
CREATE TABLE usage_observations(sandbox TEXT PRIMARY KEY REFERENCES sandboxes(id), epoch INTEGER NOT NULL, raw TEXT NOT NULL, cumulative TEXT NOT NULL) STRICT;
CREATE TABLE suspensions(sandbox TEXT PRIMARY KEY REFERENCES sandboxes(id), value TEXT NOT NULL) STRICT;
";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogLimits {
    pub identities: Counter,
    pub operations: Counter,
    pub grants: Counter,
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
    pub sandbox_id: SandboxId,
    pub request_digest: Digest,
    pub delivery: SecretDelivery,
    pub applied: bool,
    pub revocation_operation: Option<OperationId>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretRevocationRecord {
    pub operation_id: OperationId,
    pub sandbox_id: SandboxId,
    pub request_digest: Digest,
    pub secret: SecretVersion,
    pub deliveries: Vec<SecretDelivery>,
    pub terminate_recipients: bool,
    pub evidence: Option<SecretRevocationEvidence>,
}

#[derive(Debug, Clone)]
pub struct SecretRevocationAdmission {
    pub sandbox_id: SandboxId,
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
pub struct SandboxRecord {
    pub id: SandboxId,
    pub image_digest: Digest,
    pub resources: Resources,
    pub runtime_configuration: RuntimeConfiguration,
    pub configuration_revision: Counter,
    pub reservation: ReservationState,
    pub latest_intent: LifecycleIntent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuspensionRecord {
    pub sandbox_id: SandboxId,
    pub lifecycle_operation_id: OperationId,
    pub checkpoint_id: CheckpointId,
    pub manifest_digest: Digest,
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

    pub fn record_host_approval(&mut self, approval: Approval) -> Result<()> {
        let tx = self.db.connection.transaction()?;
        record_approval(&tx, &approval, self.limits.operations)?;
        tx.commit()?;
        Ok(())
    }

    pub fn admit_secret_delivery(
        &mut self,
        record: SecretDeliveryRecord,
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
        record_approval(&tx, &approval, self.limits.operations)?;
        tx.execute(
            "INSERT INTO secret_deliveries(operation,sandbox,request_digest,value) VALUES (?1,?2,?3,?4)",
            params![
                record.operation_id.as_str(),
                record.sandbox_id.as_str(),
                record.request_digest.as_str(),
                encode(&record)?
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn complete_secret_delivery(
        &mut self,
        operation: &OperationId,
        request_digest: &Digest,
    ) -> Result<SecretDeliveryRecord> {
        let tx = self.db.connection.transaction()?;
        let encoded: String = tx
            .query_row(
                "SELECT value FROM secret_deliveries WHERE operation=?1 AND request_digest=?2",
                params![operation.as_str(), request_digest.as_str()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::Missing("secret delivery operation is missing"))?;
        let mut record: SecretDeliveryRecord = decode(&encoded)?;
        if !record.applied {
            record.applied = true;
            tx.execute(
                "UPDATE secret_deliveries SET value=?2,applied=1 WHERE operation=?1",
                params![operation.as_str(), encode(&record)?],
            )?;
        }
        tx.commit()?;
        Ok(record)
    }

    pub fn secret_deliveries(&self, sandbox: &SandboxId) -> Result<Vec<SecretDeliveryRecord>> {
        let mut statement = self
            .db
            .connection
            .prepare("SELECT value FROM secret_deliveries WHERE sandbox=?1 ORDER BY rowid ASC")?;
        statement
            .query_map([sandbox.as_str()], |row| row.get::<_, String>(0))?
            .map(|value| decode(&value?))
            .collect()
    }

    pub fn active_secret_deliveries(
        &self,
        sandbox: &SandboxId,
    ) -> Result<Vec<SecretDeliveryRecord>> {
        Ok(self
            .secret_deliveries(sandbox)?
            .into_iter()
            .filter(|record| {
                record.applied && record.revocation_operation.is_none() && !record.revoked
            })
            .collect())
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
        require_revision(&tx, &request.sandbox_id, request.expected_revision)?;
        let mut statement = tx.prepare(
            "SELECT operation,value FROM secret_deliveries WHERE sandbox=?1 ORDER BY rowid ASC",
        )?;
        let encoded = statement
            .query_map([request.sandbox_id.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut deliveries = Vec::new();
        let mut updates = Vec::new();
        for (delivery_operation, value) in encoded {
            let mut record: SecretDeliveryRecord = decode(&value)?;
            if record.applied
                && !record.revoked
                && record.delivery.secret == request.secret
                && record
                    .revocation_operation
                    .as_ref()
                    .is_none_or(|value| value == &request.operation_id)
            {
                record.revocation_operation = Some(request.operation_id.clone());
                deliveries.push(record.delivery.clone());
                updates.push((delivery_operation, encode(&record)?));
            }
        }
        if deliveries.is_empty() {
            return Err(Error::Missing("active secret delivery is missing"));
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
            sandbox_id: request.sandbox_id,
            request_digest: request.request_digest,
            secret: request.secret,
            deliveries,
            terminate_recipients: request.terminate_recipients,
            evidence: None,
        };
        for (delivery_operation, value) in updates {
            tx.execute(
                "UPDATE secret_deliveries SET value=?2 WHERE operation=?1",
                params![delivery_operation, value],
            )?;
        }
        tx.execute(
            "INSERT INTO secret_revocations(operation,sandbox,request_digest,value) VALUES (?1,?2,?3,?4)",
            params![
                record.operation_id.as_str(),
                record.sandbox_id.as_str(),
                record.request_digest.as_str(),
                encode(&record)?
            ],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn complete_secret_revocation(
        &mut self,
        operation_id: &OperationId,
        request_digest: &Digest,
        evidence: SecretRevocationEvidence,
    ) -> Result<SecretRevocationRecord> {
        if !evidence.enforcement_complete {
            return Err(Error::Conflict(
                "secret revocation enforcement is incomplete",
            ));
        }
        let tx = self.db.connection.transaction()?;
        let encoded: String = tx
            .query_row(
                "SELECT value FROM secret_revocations WHERE operation=?1 AND request_digest=?2",
                params![operation_id.as_str(), request_digest.as_str()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(Error::Missing("secret revocation operation is missing"))?;
        let mut record: SecretRevocationRecord = decode(&encoded)?;
        if let Some(committed) = record.evidence.as_ref() {
            if committed != &evidence {
                return Err(Error::Conflict("secret revocation evidence changed"));
            }
            return Ok(record);
        }
        record.evidence = Some(evidence);
        for delivery in &record.deliveries {
            let mut statement = tx.prepare(
                "SELECT operation,value FROM secret_deliveries WHERE sandbox=?1 ORDER BY rowid ASC",
            )?;
            let values = statement
                .query_map([record.sandbox_id.as_str()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            drop(statement);
            for (delivery_operation, value) in values {
                let mut delivery_record: SecretDeliveryRecord = decode(&value)?;
                if &delivery_record.delivery == delivery
                    && delivery_record.revocation_operation.as_ref() == Some(operation_id)
                {
                    delivery_record.revoked = true;
                    tx.execute(
                        "UPDATE secret_deliveries SET value=?2 WHERE operation=?1",
                        params![delivery_operation, encode(&delivery_record)?],
                    )?;
                }
            }
        }
        tx.execute(
            "UPDATE secret_revocations SET value=?2,enforced=1 WHERE operation=?1",
            params![operation_id.as_str(), encode(&record)?],
        )?;
        tx.commit()?;
        Ok(record)
    }

    pub fn secret_revocations(&self, sandbox: &SandboxId) -> Result<Vec<SecretRevocationRecord>> {
        let mut statement = self
            .db
            .connection
            .prepare("SELECT value FROM secret_revocations WHERE sandbox=?1 ORDER BY rowid ASC")?;
        statement
            .query_map([sandbox.as_str()], |row| row.get::<_, String>(0))?
            .map(|value| decode(&value?))
            .collect()
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
        let (_, retired, _) =
            image_state(&tx, &image_digest)?.ok_or(Error::Missing("image does not exist"))?;
        if retired {
            return Err(Error::Conflict("image is already retired"));
        }
        let sandbox_references: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sandboxes WHERE image=?1 AND released=0)",
            [image_digest.as_str()],
            |row| row.get(0),
        )?;
        if sandbox_references {
            return Err(Error::Conflict("active sandboxes pin this image"));
        }
        let mut statement = tx.prepare("SELECT value FROM checkpoints")?;
        let checkpoints = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for checkpoint in checkpoints {
            if decode::<Checkpoint>(&checkpoint)?.image_digest == image_digest {
                return Err(Error::Conflict("retained checkpoints pin this image"));
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

    pub fn checkpoint(&self, id: &CheckpointId) -> Result<Option<Checkpoint>> {
        checkpoint_record(&self.db.connection, id)
    }

    pub fn suspension(&self, sandbox: &SandboxId) -> Result<Option<SuspensionRecord>> {
        self.db
            .connection
            .query_row(
                "SELECT value FROM suspensions WHERE sandbox=?1",
                [sandbox.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| decode(&value))
            .transpose()
    }

    pub fn record_suspension(
        &mut self,
        sandbox: &SandboxId,
        lifecycle_operation: &OperationId,
        checkpoint_id: &CheckpointId,
        manifest_digest: &Digest,
    ) -> Result<SuspensionRecord> {
        let tx = self.db.connection.transaction()?;
        let checkpoint = checkpoint_record(&tx, checkpoint_id)?
            .ok_or(Error::Missing("suspension checkpoint is missing"))?;
        let lifecycle = intent(&tx, lifecycle_operation)?
            .ok_or(Error::Missing("suspension lifecycle intent is missing"))?;
        if checkpoint.request.sandbox_id != *sandbox
            || checkpoint.request.kind != CheckpointKind::Full
            || checkpoint.phase != CheckpointPhase::Ready
            || checkpoint.manifest_digest.as_ref() != Some(manifest_digest)
            || checkpoint.full.is_none()
            || lifecycle.sandbox_id != *sandbox
            || lifecycle.desired != DesiredState::Suspended
            || lifecycle.completion.is_none()
        {
            return Err(Error::Conflict(
                "suspension association lacks checkpoint or lifecycle completion",
            ));
        }
        let value = SuspensionRecord {
            sandbox_id: sandbox.clone(),
            lifecycle_operation_id: lifecycle_operation.clone(),
            checkpoint_id: checkpoint_id.clone(),
            manifest_digest: manifest_digest.clone(),
        };
        if let Some(old) = tx
            .query_row(
                "SELECT value FROM suspensions WHERE sandbox=?1",
                [sandbox.as_str()],
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
                    "sandbox is already bound to another suspension checkpoint",
                ))
            };
        }
        tx.execute(
            "INSERT INTO suspensions VALUES (?1,?2)",
            params![sandbox.as_str(), encode(&value)?],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn clear_suspension(
        &mut self,
        sandbox: &SandboxId,
        checkpoint_id: &CheckpointId,
    ) -> Result<()> {
        let tx = self.db.connection.transaction()?;
        let value = tx
            .query_row(
                "SELECT value FROM suspensions WHERE sandbox=?1",
                [sandbox.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|encoded| decode::<SuspensionRecord>(&encoded))
            .transpose()?
            .ok_or(Error::Missing("suspension association is missing"))?;
        if value.checkpoint_id != *checkpoint_id {
            return Err(Error::Conflict("suspension checkpoint identity changed"));
        }
        tx.execute(
            "DELETE FROM suspensions WHERE sandbox=?1",
            [sandbox.as_str()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn checkpoints(
        &self,
        after: Option<&CheckpointId>,
        limit: Counter,
    ) -> Result<Vec<Checkpoint>> {
        if limit == Counter::ZERO || limit.get() > 256 {
            return Err(Error::Capacity("checkpoint page limit must be in 1..=256"));
        }
        let mut statement = self
            .db
            .connection
            .prepare("SELECT id FROM checkpoints WHERE id>?1 ORDER BY id LIMIT ?2")?;
        let rows = statement.query_map(
            params![after.map_or("", CheckpointId::as_str), limit.get()],
            |row| row.get::<_, String>(0),
        )?;
        let mut values = Vec::new();
        for row in rows {
            let id: CheckpointId = row?.try_into()?;
            values.push(
                checkpoint_record(&self.db.connection, &id)?.ok_or(Error::Corrupt(
                    "listed checkpoint disappeared from the catalog",
                ))?,
            );
        }
        Ok(values)
    }

    pub fn admit_checkpoint(
        &mut self,
        request: CheckpointRequest,
        approval: Approval,
    ) -> Result<Checkpoint> {
        let request_digest = digest(Domain::Checkpoint, &("sandsurf-checkpoint-v1", &request))?;
        if approval.request_digest != request_digest {
            return Err(Error::Conflict("checkpoint approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        if let Some(old) = checkpoint_record(&tx, &request.id)? {
            return if old.request_digest == request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict("checkpoint identity conflict"))
            };
        }
        let operation_used: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE operation=?1 UNION ALL SELECT 1 FROM intents WHERE id=?1 UNION ALL SELECT 1 FROM rollbacks WHERE operation=?1)",
            [request.operation_id.as_str()],
            |row| row.get(0),
        )?;
        if operation_used {
            return Err(Error::Conflict("checkpoint operation identity conflict"));
        }
        require_revision(&tx, &request.sandbox_id, request.expected_revision)?;
        if let Some(parent) = request.parent.as_ref() {
            let parent = checkpoint_record(&tx, parent)?
                .ok_or(Error::Missing("parent checkpoint is missing"))?;
            if parent.phase != CheckpointPhase::Ready {
                return Err(Error::Conflict("parent checkpoint is not ready"));
            }
        }
        let sandbox = sandbox_record(&tx, &request.sandbox_id)?
            .ok_or(Error::Missing("checkpoint sandbox is missing"))?;
        let sensitive: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM secret_deliveries WHERE sandbox=?1 AND applied=1)",
            [request.sandbox_id.as_str()],
            |row| row.get(0),
        )?;
        capacity(&tx, "checkpoints", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let full = request.kind == CheckpointKind::Full;
        let value = Checkpoint {
            request,
            request_digest,
            phase: CheckpointPhase::Admitted,
            image_digest: sandbox.image_digest,
            workload_disk_bytes: sandbox.resources.disk_bytes,
            resources: sandbox.resources,
            consistency: None,
            workload_disk_digest: None,
            manifest_digest: None,
            // Reconnect credentials and process memory make a full capture
            // protected even when no workload secret has been delivered.
            sensitive: sensitive || full,
            full: None,
        };
        tx.execute(
            "INSERT INTO checkpoints VALUES (?1,?2,?3,?4)",
            params![
                value.request.id.as_str(),
                value.request.operation_id.as_str(),
                value.request.sandbox_id.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    /// Admit the full checkpoint implied by an already committed suspend
    /// intent. This is a host-owned suboperation of that lifecycle authority,
    /// not a second application approval or a synthetic checkpoint grant.
    pub fn admit_suspension_checkpoint(
        &mut self,
        request: CheckpointRequest,
        lifecycle_operation: &OperationId,
    ) -> Result<Checkpoint> {
        if request.kind != CheckpointKind::Full || request.parent.is_some() {
            return Err(Error::Conflict(
                "suspension requires a root full checkpoint",
            ));
        }
        let request_digest = digest(Domain::Checkpoint, &("sandsurf-checkpoint-v1", &request))?;
        let tx = self.db.connection.transaction()?;
        if let Some(old) = checkpoint_record(&tx, &request.id)? {
            return if old.request_digest == request_digest {
                Ok(old)
            } else {
                Err(Error::Conflict("suspension checkpoint identity conflict"))
            };
        }
        let lifecycle = intent(&tx, lifecycle_operation)?
            .ok_or(Error::Missing("suspend lifecycle intent is missing"))?;
        if lifecycle.sandbox_id != request.sandbox_id
            || lifecycle.desired != DesiredState::Suspended
            || lifecycle.completion.is_some()
            || request.expected_revision.next()? != lifecycle.revision
        {
            return Err(Error::Conflict(
                "suspension checkpoint does not match its lifecycle intent",
            ));
        }
        let operation_used: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE operation=?1 UNION ALL SELECT 1 FROM intents WHERE id=?1 UNION ALL SELECT 1 FROM rollbacks WHERE operation=?1)",
            [request.operation_id.as_str()],
            |row| row.get(0),
        )?;
        if operation_used {
            return Err(Error::Conflict(
                "suspension checkpoint operation identity conflict",
            ));
        }
        let sandbox = sandbox_record(&tx, &request.sandbox_id)?
            .ok_or(Error::Missing("suspension sandbox is missing"))?;
        if sandbox.configuration_revision != lifecycle.revision {
            return Err(Error::Conflict(
                "suspension lifecycle is no longer the current host intent",
            ));
        }
        capacity(&tx, "checkpoints", self.limits.operations)?;
        let value = Checkpoint {
            request,
            request_digest,
            phase: CheckpointPhase::Admitted,
            image_digest: sandbox.image_digest,
            workload_disk_bytes: sandbox.resources.disk_bytes,
            resources: sandbox.resources,
            consistency: None,
            workload_disk_digest: None,
            manifest_digest: None,
            sensitive: true,
            full: None,
        };
        tx.execute(
            "INSERT INTO checkpoints VALUES (?1,?2,?3,?4)",
            params![
                value.request.id.as_str(),
                value.request.operation_id.as_str(),
                value.request.sandbox_id.as_str(),
                encode(&value)?
            ],
        )?;
        tx.commit()?;
        Ok(value)
    }

    pub fn begin_checkpoint(
        &mut self,
        id: &CheckpointId,
        request_digest: &Digest,
    ) -> Result<Checkpoint> {
        let mut value = checkpoint_record(&self.db.connection, id)?
            .ok_or(Error::Missing("checkpoint is missing"))?;
        if value.request_digest != *request_digest {
            return Err(Error::Conflict("checkpoint request digest mismatch"));
        }
        if value.phase == CheckpointPhase::Ready {
            return Ok(value);
        }
        value.phase = CheckpointPhase::Capturing;
        self.db.connection.execute(
            "UPDATE checkpoints SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        Ok(value)
    }

    pub fn complete_checkpoint(
        &mut self,
        id: &CheckpointId,
        request_digest: &Digest,
        disk_digest: Digest,
        manifest_digest: Digest,
        consistency: CheckpointConsistency,
    ) -> Result<Checkpoint> {
        self.complete_checkpoint_inner(
            id,
            request_digest,
            disk_digest,
            manifest_digest,
            consistency,
            None,
        )
    }

    pub fn complete_full_checkpoint(
        &mut self,
        id: &CheckpointId,
        request_digest: &Digest,
        disk_digest: Digest,
        manifest_digest: Digest,
        consistency: CheckpointConsistency,
        full: FullCheckpointMetadata,
    ) -> Result<Checkpoint> {
        self.complete_checkpoint_inner(
            id,
            request_digest,
            disk_digest,
            manifest_digest,
            consistency,
            Some(full),
        )
    }

    fn complete_checkpoint_inner(
        &mut self,
        id: &CheckpointId,
        request_digest: &Digest,
        disk_digest: Digest,
        manifest_digest: Digest,
        consistency: CheckpointConsistency,
        full: Option<FullCheckpointMetadata>,
    ) -> Result<Checkpoint> {
        let mut value = checkpoint_record(&self.db.connection, id)?
            .ok_or(Error::Missing("checkpoint is missing"))?;
        if value.request_digest != *request_digest {
            return Err(Error::Conflict("checkpoint request digest mismatch"));
        }
        if (value.request.kind == CheckpointKind::Full) != full.is_some() {
            return Err(Error::Conflict(
                "checkpoint kind does not match its completion material",
            ));
        }
        if value.phase == CheckpointPhase::Ready {
            return if value.workload_disk_digest.as_ref() == Some(&disk_digest)
                && value.manifest_digest.as_ref() == Some(&manifest_digest)
                && value.consistency == Some(consistency)
                && value.full == full
            {
                Ok(value)
            } else {
                Err(Error::Conflict("checkpoint result identity conflict"))
            };
        }
        if value.phase != CheckpointPhase::Capturing {
            return Err(Error::Conflict("checkpoint capture has not begun"));
        }
        value.phase = CheckpointPhase::Ready;
        value.workload_disk_digest = Some(disk_digest);
        value.manifest_digest = Some(manifest_digest);
        value.consistency = Some(consistency);
        value.full = full;
        self.db.connection.execute(
            "UPDATE checkpoints SET value=?2 WHERE id=?1",
            params![id.as_str(), encode(&value)?],
        )?;
        Ok(value)
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
        if image_state(&tx, &image)?.is_some_and(|(_, retired, _)| retired) {
            return Err(Error::Conflict("sandbox image is retired"));
        }
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
        let runtime_configuration = initial_runtime_configuration(&resources)?;
        tx.execute(
            "INSERT INTO sandboxes(id,image,resources,configuration,revision) VALUES (?1,?2,?3,?4,1)",
            params![
                id.as_str(),
                image.as_str(),
                encode(&resources)?,
                encode(&runtime_configuration)?
            ],
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

    pub fn create_sandbox_from_checkpoint(
        &mut self,
        id: SandboxId,
        checkpoint_id: &CheckpointId,
        resources: Resources,
        operation: OperationId,
        approval: Approval,
    ) -> Result<LifecycleIntent> {
        resources.validate()?;
        let request = digest(
            Domain::Checkpoint,
            &(
                "sandsurf-filesystem-fork-v1",
                checkpoint_id,
                &id,
                &resources,
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
        let checkpoint = checkpoint_record(&tx, checkpoint_id)?
            .ok_or(Error::Missing("fork checkpoint is missing"))?;
        if checkpoint.phase != CheckpointPhase::Ready
            || checkpoint.request.kind != CheckpointKind::Filesystem
            || resources.disk_bytes != checkpoint.workload_disk_bytes
        {
            return Err(Error::Conflict(
                "fork requires a ready filesystem checkpoint with matching disk geometry",
            ));
        }
        capacity(&tx, "sandboxes", self.limits.identities)?;
        capacity(&tx, "intents", self.limits.operations)?;
        let mut total = resources.clone();
        let mut statement = tx.prepare("SELECT resources FROM sandboxes WHERE released=0")?;
        for row in statement.query_map([], |row| row.get::<_, String>(0))? {
            total = total.checked_add(&decode::<Resources>(&row?)?)?;
        }
        drop(statement);
        if !total.within(&self.limits.resources) {
            return Err(Error::Capacity("host resource reservations exhausted"));
        }
        record_approval(&tx, &approval, self.limits.operations)?;
        let configuration = initial_runtime_configuration(&resources)?;
        tx.execute(
            "INSERT INTO sandboxes(id,image,resources,configuration,revision) VALUES (?1,?2,?3,?4,1)",
            params![
                id.as_str(),
                checkpoint.image_digest.as_str(),
                encode(&resources)?,
                encode(&configuration)?
            ],
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

    pub fn admit_rollback(
        &mut self,
        sandbox: &SandboxId,
        checkpoint_id: &CheckpointId,
        operation_id: OperationId,
        expected_revision: Counter,
        approval: Approval,
    ) -> Result<RollbackRecord> {
        let request_digest = digest(
            Domain::Checkpoint,
            &(
                "sandsurf-filesystem-rollback-v1",
                sandbox,
                checkpoint_id,
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
        require_revision(&tx, sandbox, expected_revision)?;
        let source = checkpoint_record(&tx, checkpoint_id)?
            .ok_or(Error::Missing("rollback checkpoint is missing"))?;
        let target =
            sandbox_record(&tx, sandbox)?.ok_or(Error::Missing("rollback sandbox is missing"))?;
        if source.phase != CheckpointPhase::Ready
            || source.request.kind != CheckpointKind::Filesystem
            || source.image_digest != target.image_digest
            || source.workload_disk_bytes != target.resources.disk_bytes
        {
            return Err(Error::Conflict(
                "rollback checkpoint is incompatible with the target Sandbox",
            ));
        }
        capacity(&tx, "rollbacks", self.limits.operations)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let value = RollbackRecord {
            operation_id,
            sandbox_id: sandbox.clone(),
            checkpoint_id: checkpoint_id.clone(),
            expected_revision,
            request_digest,
            phase: RollbackPhase::Admitted,
            evidence_digest: None,
        };
        tx.execute(
            "INSERT INTO rollbacks VALUES (?1,?2,?3)",
            params![
                value.operation_id.as_str(),
                value.sandbox_id.as_str(),
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
        let sandbox = sandbox_record(&self.db.connection, &intent.sandbox_id)?
            .ok_or(Error::Missing("lifecycle sandbox is missing"))?;
        if sandbox.configuration_revision != intent.revision {
            return Err(Error::Conflict(
                "lifecycle intent is no longer the current configuration revision",
            ));
        }
        self.authority.authorize_lifecycle(LifecycleCommand {
            sandbox_id: intent.sandbox_id,
            operation_id: intent.operation_id,
            desired: intent.desired,
            revision: intent.revision,
            request_digest: intent.request_digest,
            configuration: sandbox.runtime_configuration,
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
        let configuration = self
            .sandbox(sandbox)?
            .ok_or(Error::Missing("sandbox is missing"))?
            .runtime_configuration;
        configuration.validate()?;
        let operation_id: OperationId = format!("configuration-{}", revision.get()).try_into()?;
        let request_digest = digest(
            Domain::Grant,
            &(
                "sandsurf-apply-configuration-v2",
                sandbox,
                revision,
                &configuration,
            ),
        )?;
        self.authority
            .authorize_configuration(ConfigurationCommand {
                sandbox_id: sandbox.clone(),
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
        sandbox: &SandboxId,
        operation: &OperationId,
        expected: Counter,
        configuration: RuntimeConfiguration,
        approval: Approval,
    ) -> Result<Counter> {
        configuration.validate()?;
        let request = digest(
            Domain::Grant,
            &(
                "sandsurf-runtime-configuration-v1",
                sandbox,
                operation,
                expected,
                &configuration,
            ),
        )?;
        if request != approval.request_digest {
            return Err(Error::Conflict("runtime configuration approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        require_revision(&tx, sandbox, expected)?;
        record_approval(&tx, &approval, self.limits.operations)?;
        let revision = expected.next()?;
        tx.execute(
            "UPDATE sandboxes SET configuration=?2,revision=?3 WHERE id=?1",
            params![sandbox.as_str(), encode(&configuration)?, revision.get()],
        )?;
        tx.commit()?;
        Ok(revision)
    }

    /// Increase live-qualified reservations and workload cgroup ceilings. VM
    /// RAM/vCPU topology remains a boot-time shape and cannot be changed here.
    pub fn update_live_resources(
        &mut self,
        sandbox: &SandboxId,
        operation: &OperationId,
        expected: Counter,
        resources: Resources,
        live: LiveResourceLimits,
        approval: Approval,
    ) -> Result<Counter> {
        resources.validate()?;
        live.validate()?;
        let old = self
            .sandbox(sandbox)?
            .ok_or(Error::Missing("sandbox is missing"))?;
        let memory_bytes = resources
            .memory_mib
            .get()
            .checked_mul(1024 * 1024)
            .ok_or(Error::Capacity("memory reservation overflow"))?;
        if resources.vcpus != old.resources.vcpus
            || resources.memory_mib != old.resources.memory_mib
            || resources.disk_bytes < old.resources.disk_bytes
            || resources.output_bytes < old.resources.output_bytes
            || resources.processes < old.resources.processes
            || live.workload_memory_bytes.get() > memory_bytes
            || live.workload_processes > resources.processes
        {
            return Err(Error::Conflict(
                "live update changes boot shape, shrinks a reservation, or exceeds its envelope",
            ));
        }
        let request = digest(
            Domain::Grant,
            &(
                "sandsurf-live-resources-v1",
                sandbox,
                operation,
                expected,
                &resources,
                &live,
            ),
        )?;
        if approval.request_digest != request {
            return Err(Error::Conflict("resource update approval mismatch"));
        }
        let tx = self.db.connection.transaction()?;
        require_revision(&tx, sandbox, expected)?;
        let mut total = resources.clone();
        {
            let mut statement =
                tx.prepare("SELECT resources FROM sandboxes WHERE released=0 AND id<>?1")?;
            for row in statement.query_map([sandbox.as_str()], |row| row.get::<_, String>(0))? {
                total = total.checked_add(&decode::<Resources>(&row?)?)?;
            }
        }
        if !total.within(&self.limits.resources) {
            return Err(Error::Capacity("host resource reservations exhausted"));
        }
        record_approval(&tx, &approval, self.limits.operations)?;
        let encoded: String = tx.query_row(
            "SELECT configuration FROM sandboxes WHERE id=?1",
            [sandbox.as_str()],
            |row| row.get(0),
        )?;
        let mut configuration: RuntimeConfiguration = decode(&encoded)?;
        configuration.resources = live;
        let revision = expected.next()?;
        tx.execute(
            "UPDATE sandboxes SET resources=?2,configuration=?3,revision=?4 WHERE id=?1",
            params![
                sandbox.as_str(),
                encode(&resources)?,
                encode(&configuration)?,
                revision.get()
            ],
        )?;
        tx.commit()?;
        Ok(revision)
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

    /// Convert guardian/guest counters into host-owned monotonic consumption.
    /// Live gauges remain observations and may fall; consumed counters do not.
    pub fn observe_usage(
        &mut self,
        sandbox: &SandboxId,
        epoch: Counter,
        raw: ResourceUsage,
    ) -> Result<ResourceUsage> {
        let tx = self.db.connection.transaction()?;
        let old = tx
            .query_row(
                "SELECT epoch,raw,cumulative FROM usage_observations WHERE sandbox=?1",
                [sandbox.as_str()],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let cumulative = if let Some((old_epoch, old_raw, old_cumulative)) = old {
            let old_epoch: Counter = old_epoch.try_into()?;
            if epoch < old_epoch {
                return Err(Error::Conflict("resource usage epoch moved backwards"));
            }
            let old_raw: ResourceUsage = decode(&old_raw)?;
            let mut value: ResourceUsage = decode(&old_cumulative)?;
            if epoch == old_epoch
                && [
                    (raw.cpu_micros, old_raw.cpu_micros),
                    (raw.io_read_bytes, old_raw.io_read_bytes),
                    (raw.io_write_bytes, old_raw.io_write_bytes),
                    (raw.network_rx_bytes, old_raw.network_rx_bytes),
                    (raw.network_tx_bytes, old_raw.network_tx_bytes),
                    (raw.network_connections, old_raw.network_connections),
                ]
                .iter()
                .any(|(current, previous)| current < previous)
            {
                return Err(Error::Conflict(
                    "resource usage rewound within one machine epoch",
                ));
            }
            value.cpu_micros = add_observed(value.cpu_micros, raw.cpu_micros, old_raw.cpu_micros)?;
            value.io_read_bytes = add_observed(
                value.io_read_bytes,
                raw.io_read_bytes,
                old_raw.io_read_bytes,
            )?;
            value.io_write_bytes = add_observed(
                value.io_write_bytes,
                raw.io_write_bytes,
                old_raw.io_write_bytes,
            )?;
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
            value.processes_current = raw.processes_current;
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
            "INSERT INTO usage_observations VALUES (?1,?2,?3,?4) ON CONFLICT(sandbox) DO UPDATE SET epoch=excluded.epoch,raw=excluded.raw,cumulative=excluded.cumulative",
            params![
                sandbox.as_str(),
                epoch.get(),
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

fn add_observed(total: Counter, current: Counter, previous: Counter) -> Result<Counter> {
    let delta = if current >= previous {
        current.get() - previous.get()
    } else {
        current.get()
    };
    Ok(total.checked_add(delta)?)
}

fn sandbox_record(db: &rusqlite::Connection, sandbox: &SandboxId) -> Result<Option<SandboxRecord>> {
    let row = db
        .query_row(
            "SELECT image,resources,configuration,revision,released FROM sandboxes WHERE id=?1",
            [sandbox.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((image, resources, configuration, revision, released)) = row else {
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
        runtime_configuration: decode(&configuration)?,
        configuration_revision: revision.try_into()?,
        reservation,
        latest_intent: decode(&latest)?,
    }))
}

fn checkpoint_record(db: &rusqlite::Connection, id: &CheckpointId) -> Result<Option<Checkpoint>> {
    let raw = db
        .query_row(
            "SELECT value FROM checkpoints WHERE id=?1",
            [id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    raw.map(|raw| {
        let value: Checkpoint = decode(&raw)?;
        let expected = digest(
            Domain::Checkpoint,
            &("sandsurf-checkpoint-v1", &value.request),
        )?;
        if value.request.id != *id
            || value.request_digest != expected
            || (value.phase == CheckpointPhase::Ready)
                != (value.consistency.is_some()
                    && value.workload_disk_digest.is_some()
                    && value.manifest_digest.is_some())
        {
            return Err(Error::Corrupt("checkpoint record is inconsistent"));
        }
        Ok(value)
    })
    .transpose()
}

fn initial_runtime_configuration(resources: &Resources) -> Result<RuntimeConfiguration> {
    let memory = resources
        .memory_mib
        .get()
        .checked_mul(1024 * 1024)
        .ok_or(Error::Capacity("workload memory envelope overflow"))?;
    Ok(RuntimeConfiguration {
        network: NetworkPolicy::default(),
        exposures: Vec::new(),
        resources: LiveResourceLimits {
            workload_memory_bytes: Counter::try_from(memory)?,
            workload_processes: resources.processes,
            cpu_max: None,
        },
    })
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
