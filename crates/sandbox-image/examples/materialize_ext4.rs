use sandbox_image::ext4::materialize_tar;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let archive = PathBuf::from(arguments.next().ok_or("missing canonical tar path")?);
    let output = PathBuf::from(arguments.next().ok_or("missing ext4 output path")?);
    let bytes = arguments
        .next()
        .ok_or("missing ext4 byte count")?
        .into_string()
        .map_err(|_| "ext4 byte count is not UTF-8")?
        .parse::<u64>()?;
    if arguments.next().is_some() {
        return Err("unexpected ext4 builder argument".into());
    }
    println!("{}", materialize_tar(&archive, &output, bytes)?);
    Ok(())
}
