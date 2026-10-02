//! Distribution carries gzip disk blobs; the host's immutable image store
//! carries materialized VM disks. Both bind the exact same manifest and decoded
//! artifact digests. Neither representation is a compatibility reader.
use crate::{ImageError, ImageTrust, MAX_IMAGE_ARTIFACT_BYTES, VerifiedImage};
use std::collections::BTreeSet;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

/// Decode only after manifest authorization. No installation hook writes to an
/// npm package. A bounded worker publishes the private host-owned VM image.
pub fn install(
    store: &Path,
    manifest_path: &Path,
    trust: ImageTrust<'_>,
) -> Result<VerifiedImage, ImageError> {
    let (manifest, digest, bytes) = crate::read_manifest(manifest_path, trust)?;
    let owner = crate::ImageStage::acquire(store, &digest)?;
    let destination = store.join(&digest);
    if destination.exists() {
        return crate::verify_image(
            &destination.join("manifest.json"),
            ImageTrust::Pinned {
                manifest_digest: &digest,
            },
        );
    }
    let source = manifest_path
        .parent()
        .ok_or_else(|| ImageError::Invalid("distribution has no owner".into()))?;
    let stage = owner.path.clone();
    sandsurf_native::local::create_private_directory(&stage)?;
    let result = (|| {
        let mut directories = BTreeSet::new();
        let mut record = sandsurf_native::local::create_private_file(&stage.join("manifest.json"))?;
        record.write_all(&bytes)?;
        sandsurf_native::storage::sync_file(&record)?;
        // Publication transfers the whole directory. Windows readers/writers
        // intentionally deny DELETE sharing; drain this writer before rename.
        drop(record);
        let mut artifacts = vec![(&manifest.boot_bundle.kernel.path, false)];
        if let Some(initramfs) = &manifest.boot_bundle.initramfs {
            artifacts.push((&initramfs.path, false));
        }
        artifacts.push((&manifest.system.rootfs.path, true));
        for (relative, compressed) in artifacts {
            let target = stage.join(relative);
            let mut directory = stage.clone();
            if let Some(parent) = Path::new(relative).parent() {
                for part in parent.components() {
                    directory.push(part);
                    sandsurf_native::local::ensure_private_directory(&directory)?;
                    directories.insert(directory.clone());
                }
            }
            let input_name = if compressed {
                format!("{relative}.gz")
            } else {
                relative.clone()
            };
            let input_path = crate::resolve_beneath(source, &input_name)?;
            let input = crate::open_regular_bounded(
                &input_path,
                MAX_IMAGE_ARTIFACT_BYTES,
                "distribution source",
            )?;
            let mut output = sandsurf_native::local::create_private_file(&target)?;
            if compressed {
                decode(input, &mut output, MAX_IMAGE_ARTIFACT_BYTES)?;
            } else if io::copy(&mut input.take(MAX_IMAGE_ARTIFACT_BYTES + 1), &mut output)?
                > MAX_IMAGE_ARTIFACT_BYTES
            {
                return Err(ImageError::Invalid(
                    "distribution source grew beyond its bound".into(),
                ));
            }
            sandsurf_native::storage::sync_file(&output)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400))?;
            }
        }
        for directory in directories.iter().rev() {
            sandsurf_native::storage::sync_directory(directory)?;
        }
        let published = crate::publish_image_stage(store, &stage, &digest)?;
        crate::verify_image(
            &published.join("manifest.json"),
            ImageTrust::Pinned {
                manifest_digest: &digest,
            },
        )
    })();
    if stage.exists() {
        std::fs::remove_dir_all(&stage)?;
    }
    result
}

fn decode(input: impl Read, output: &mut impl Write, maximum: u64) -> Result<(), ImageError> {
    let mut decoder = flate2::bufread::GzDecoder::new(BufReader::with_capacity(64 * 1024, input));
    if io::copy(&mut decoder.by_ref().take(maximum + 1), output)? > maximum {
        return Err(ImageError::Invalid(
            "decoded disk exceeds image capacity bound".into(),
        ));
    }
    if decoder.into_inner().read(&mut [0_u8; 1])? != 0 {
        return Err(ImageError::Invalid(
            "disk transport contains trailing bytes or additional gzip members".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }
    #[test]
    fn decoder_bounds_expansion_and_rejects_truncation_and_second_members() {
        let compressed = gzip(&[1_u8; 128 * 1024]);
        let mut output = Vec::new();
        decode(&compressed[..], &mut output, 128 * 1024).unwrap();
        assert_eq!(output, vec![1; 128 * 1024]);
        assert!(decode(&compressed[..], &mut Vec::new(), 32).is_err());
        assert!(
            decode(
                &compressed[..compressed.len() - 2],
                &mut Vec::new(),
                128 * 1024
            )
            .is_err()
        );
        let mut multiple = compressed.clone();
        multiple.extend_from_slice(&gzip(b"other"));
        assert!(decode(&multiple[..], &mut Vec::new(), 128 * 1024).is_err());
    }
}
