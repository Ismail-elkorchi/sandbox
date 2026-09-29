use sandsurf_image::ext4::finalize_journaled_seed;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let image = PathBuf::from(arguments.next().ok_or("missing journaled ext4 image")?);
    if arguments.next().is_some() {
        return Err("unexpected ext4 finalizer argument".into());
    }
    finalize_journaled_seed(&image)?;
    Ok(())
}
