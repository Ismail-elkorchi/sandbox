//! Creation-input package provenance. This is an inventory of the assembled
//! seed, not an attestation of the administrator-controlled running computer.
use crate::{Architecture, ImageError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DistributionInventory {
    Alpine {
        database_digest: String,
        packages: Vec<DistributionPackage>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DistributionPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub origin: String,
    /// Preserve the distribution declaration, including non-SPDX/custom names;
    /// never silently convert it into a different grant or license choice.
    pub license: String,
    pub build_commit: String,
    /// APK's installed-record checksum, not a whole-archive SHA-256 claim.
    pub package_checksum: String,
}

impl DistributionInventory {
    pub fn validate(&self, architecture: Architecture) -> Result<(), ImageError> {
        let Self::Alpine {
            database_digest,
            packages,
        } = self;
        super::validate_digest(database_digest)?;
        if packages.is_empty() || packages.len() > 512 {
            return Err(invalid("distribution package count exceeds bound"));
        }
        let mut previous: Option<&str> = None;
        for value in packages {
            value.validate(architecture)?;
            if previous.is_some_and(|old| old >= value.name.as_str()) {
                return Err(invalid("distribution packages must be unique and sorted"));
            }
            previous = Some(&value.name);
        }
        Ok(())
    }
}
impl DistributionPackage {
    fn validate(&self, architecture: Architecture) -> Result<(), ImageError> {
        let name = |value: &str| {
            !value.is_empty()
                && value.len() <= 128
                && value.as_bytes()[0].is_ascii_alphanumeric()
                && value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+_.-".contains(&b))
        };
        let arch = match architecture {
            Architecture::X64 => "x86_64",
            Architecture::Arm64 => "aarch64",
        };
        if !name(&self.name)
            || !name(&self.origin)
            || self.version.is_empty()
            || self.version.len() > 128
            || !self.version.as_bytes()[0].is_ascii_digit()
            || !self
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+_.:~-".contains(&b))
            || (self.architecture != arch && self.architecture != "noarch")
            || self.license.is_empty()
            || self.license.len() > 1024
            || self.license.chars().any(char::is_control)
            || self.build_commit.len() != 40
            || !self
                .build_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !self.package_checksum.starts_with("Q1")
            || self.package_checksum.len() != 30
            || !self.package_checksum[2..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return Err(invalid("distribution package provenance is malformed"));
        }
        Ok(())
    }
}
fn invalid(value: &str) -> ImageError {
    ImageError::Invalid(value.into())
}

/// The caller obtains these bytes from the completed offline seed, through the
/// isolated disk reader. Do not reconstruct package versions from filenames or
/// repository indexes: neither describes what the image actually installed.
pub fn alpine_inventory(
    bytes: &[u8],
    architecture: Architecture,
) -> Result<DistributionInventory, ImageError> {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid("installed package database exceeds bound"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid("installed package database is not UTF-8"))?;
    if !text.ends_with("\n\n") || text.contains('\0') || text.contains('\r') {
        return Err(invalid("installed package database is incomplete"));
    }
    let mut packages = Vec::new();
    let mut names = BTreeSet::new();
    for block in text.trim_end_matches('\n').split("\n\n") {
        let mut fields = BTreeMap::new();
        // File records reuse letters (including L for an installed link).
        // Only the package header before the first F record is provenance.
        for line in block.lines().take_while(|line| !line.starts_with("F:")) {
            if line.len() > 65536 {
                return Err(invalid("installed package record exceeds bound"));
            }
            if let Some((key, value)) = line.split_once(':')
                && ["P", "V", "A", "o", "L", "c", "C"].contains(&key)
                && fields.insert(key, value).is_some()
            {
                return Err(invalid("duplicate installed package provenance field"));
            }
        }
        let field = |key| {
            fields
                .get(key)
                .map(|v| (*v).to_owned())
                .ok_or_else(|| invalid("missing installed package provenance field"))
        };
        let value = DistributionPackage {
            name: field("P")?,
            version: field("V")?,
            architecture: field("A")?,
            origin: field("o")?,
            license: field("L")?,
            build_commit: field("c")?,
            package_checksum: field("C")?,
        };
        value.validate(architecture)?;
        if !names.insert(value.name.clone()) || packages.len() == 512 {
            return Err(invalid("installed package identity/count conflict"));
        }
        packages.push(value);
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    let value = DistributionInventory::Alpine {
        database_digest: super::hex_sha256(bytes),
        packages,
    };
    value.validate(architecture)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(name: &str) -> String {
        format!(
            "C:Q1{}\nP:{name}\nV:1.0-r0\nA:x86_64\no:origin\nL:custom ISC\nc:{}\nF:usr/lib\nR:link\nL:not-package-license\n\n",
            "A".repeat(27) + "=",
            "a".repeat(40)
        )
    }
    #[test]
    fn package_headers_not_file_entries_own_the_image_inventory() {
        let bytes = record("second") + &record("first");
        let value = alpine_inventory(bytes.as_bytes(), Architecture::X64).unwrap();
        let DistributionInventory::Alpine { packages, .. } = value;
        assert_eq!(packages[0].name, "first");
        assert_eq!(packages[0].origin, "origin");
        assert_eq!(packages[0].license, "custom ISC");
        assert_eq!(packages[1].name, "second");
    }
    #[test]
    fn inventory_rejects_missing_duplicate_truncated_and_wrong_architecture_metadata() {
        let valid = record("example");
        for bytes in [
            valid.trim_end().to_owned(),
            valid.replace("o:origin\n", ""),
            valid.replace("P:example", "P:example\nP:second"),
            valid.clone() + &valid,
            valid.replace("A:x86_64", "A:aarch64"),
            valid.replace("o:origin", "o:../origin"),
            valid.replace(&"a".repeat(40), &"x".repeat(40)),
            valid.replace("L:custom ISC", "L:"),
        ] {
            assert!(alpine_inventory(bytes.as_bytes(), Architecture::X64).is_err());
        }
        assert!(alpine_inventory(&vec![b'x'; 4 * 1024 * 1024 + 1], Architecture::X64).is_err());
    }
}
