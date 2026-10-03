//! Shared kernel-test sealing input; this is not a machine image or a product
//! runtime. The production caller seals its complete verified QEMU closure.
pub fn seal(
    parent: &std::path::Path,
    executable: &std::path::Path,
) -> std::sync::Arc<sandsurf_native::windows_vmm::Isolation> {
    let input = sandsurf_native::windows_vmm::boot_input(executable).unwrap();
    sandsurf_native::windows_vmm::Isolation::create(
        parent,
        "sandsurf-qemu-x64.exe",
        &[(std::path::Path::new("sandsurf-qemu-x64.exe"), &input)],
        &input,
        None,
    )
    .unwrap()
}
