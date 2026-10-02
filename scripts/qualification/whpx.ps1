# Query WHPX and release an empty partition handle. Never enable features,
# install services, or boot a guest. This does not qualify the QEMU runtime.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SandsurfWhpxProbe {
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("WinHvPlatform.dll", ExactSpelling = true)]
    private static extern int WHvGetCapability(uint code, out ulong value, uint bytes, out uint written);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("WinHvPlatform.dll", ExactSpelling = true)]
    private static extern int WHvCreatePartition(out IntPtr partition);
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("WinHvPlatform.dll", ExactSpelling = true)]
    private static extern int WHvDeletePartition(IntPtr partition);

    public static bool Present() {
        ulong value; uint written;
        // WHvCapabilityCodeHypervisorPresent = 0, BOOL member of the union.
        int result = WHvGetCapability(0, out value, 8, out written);
        return result >= 0 && written >= 4 && written <= 8 && (value & 0xffffffff) == 1;
    }
    public static bool Handle() {
        IntPtr partition;
        int result = WHvCreatePartition(out partition);
        if (result < 0 || partition == IntPtr.Zero) return false;
        return WHvDeletePartition(partition) >= 0;
    }
}
'@
$checks = [System.Collections.Generic.List[object]]::new()
try {
    $checks.Add(@{ id = 'whpx-hypervisor-present'; passed = [SandsurfWhpxProbe]::Present() })
    $checks.Add(@{ id = 'whpx-native-handle-release'; passed = [SandsurfWhpxProbe]::Handle() })
} catch {
    $checks.Add(@{ id = 'whpx-api'; passed = $false; error = $_.Exception.GetType().Name })
}
@{ engine = 'qemu-whpx'; checks = $checks.ToArray() } | ConvertTo-Json -Depth 6 -Compress
