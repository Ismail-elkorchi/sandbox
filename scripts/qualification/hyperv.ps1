# Read-only prerequisites. Never enable features, register services, or create a VM.
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class SandsurfHcsProbe {
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("computecore.dll", ExactSpelling = true)]
    private static extern IntPtr HcsCreateOperation(IntPtr context, IntPtr callback);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("computecore.dll", ExactSpelling = true)]
    private static extern void HcsCloseOperation(IntPtr operation);

    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [DllImport("computecore.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int HcsGetServiceProperties(string query, out IntPtr result);

    public static bool Operation() {
        var operation = HcsCreateOperation(IntPtr.Zero, IntPtr.Zero);
        if (operation == IntPtr.Zero) return false;
        HcsCloseOperation(operation);
        return true;
    }

    public static int ServiceProperties() {
        IntPtr result = IntPtr.Zero;
        try {
            return HcsGetServiceProperties("{\"PropertyTypes\":[\"Basic\"]}", out result);
        } finally {
            if (result != IntPtr.Zero) Marshal.FreeCoTaskMem(result);
        }
    }
}
'@

$checks = [System.Collections.Generic.List[object]]::new()
try {
    $system = Get-CimInstance Win32_ComputerSystem
    $checks.Add(@{ id = 'hypervisor-present'; passed = [bool]$system.HypervisorPresent })
} catch {
    $checks.Add(@{ id = 'hypervisor-present'; passed = $false; error = $_.Exception.GetType().Name })
}
foreach ($name in @('vmms', 'vmcompute')) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    $checks.Add(@{ id = "service-$name-running"; passed = ($null -ne $service -and $service.Status -eq 'Running') })
}
try {
    $checks.Add(@{ id = 'hcs-operation-handle'; passed = [SandsurfHcsProbe]::Operation() })
    $result = [SandsurfHcsProbe]::ServiceProperties()
    $checks.Add(@{ id = 'hcs-service-query'; passed = ($result -ge 0); hresult = $result })
} catch {
    $checks.Add(@{ id = 'hcs-api'; passed = $false; error = $_.Exception.GetType().Name })
}
@{ engine = 'hyper-v'; checks = $checks.ToArray() } | ConvertTo-Json -Depth 6 -Compress
