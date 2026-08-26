#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(values) = serde_json::from_slice::<Vec<String>>(data)
        && let Some((executable, arguments)) = values.split_first()
    {
        let _ = sandbox_launcher_windows::encode_windows_command_line(executable, arguments);
    }
});
