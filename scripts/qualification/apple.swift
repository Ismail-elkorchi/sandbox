// Source-built, ad-hoc-entitled prerequisite probe, not a release-signed VM owner.
import Foundation
import Virtualization

let report: [String: Any] = [
    "engine": "apple-virtualization",
    "checks": [[
        "id": "virtualization-framework-supported",
        "passed": VZVirtualMachine.isSupported,
    ]],
]
let bytes = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys])
FileHandle.standardOutput.write(bytes)
FileHandle.standardOutput.write(Data([10]))
