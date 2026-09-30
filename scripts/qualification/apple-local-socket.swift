import Foundation
import Darwin

@main
private enum NativeControlContracts {
    static func main() throws {
        precondition(CommandLine.arguments.count == 2)
        let fixture = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let request = try JSONDecoder().decode(Request.self, from: fixture)
        precondition(request.kind == "create" && request.machineId == "box")
        precondition(request.kernel == "/kernel" && request.initialRamdisk == nil)
        precondition(request.commandLine == "root=/dev/vda" && request.disks?.first?.readOnly == true)
        precondition(request.memoryBytes == 536870912 && request.vcpus == 2)
        precondition(request.controlSocket == "/private/tmp/control.sock")
        precondition(request.hostConnectPorts == [10789] && request.guestListenPorts == [12080])
        var unknown = try JSONSerialization.jsonObject(with: fixture) as! [String: Any]
        unknown["unrecognized"] = true
        let invalid = try JSONSerialization.data(withJSONObject: unknown)
        precondition((try? JSONDecoder().decode(Request.self, from: invalid)) == nil)

        let files = FileManager.default
        let originalDirectory = files.currentDirectoryPath
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("sandsurf-swift-\(UUID().uuidString)-\(String(repeating: "x", count: 120))")
        try files.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? files.removeItem(at: root) }
        let path = root.appendingPathComponent("control.sock").path
        precondition(path.utf8.count >= MemoryLayout.size(ofValue: sockaddr_un().sun_path))
        let listener = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        precondition(listener >= 0)
        defer { Darwin.close(listener) }
        let bound = relativeUnixSocket(path) { address, length in
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, length) }
            }
        }
        precondition(bound == 0 && Darwin.listen(listener, 16) == 0)
        guard let client = connectUnix(path) else { fatalError("descriptor-relative guest relay failed") }
        defer { Darwin.close(client) }
        let peer = Darwin.accept(listener, nil, nil)
        precondition(peer >= 0)
        defer { Darwin.close(peer) }
        var sent: UInt8 = 0xf8
        var received: UInt8 = 0
        precondition(Darwin.write(client, &sent, 1) == 1)
        precondition(Darwin.read(peer, &received, 1) == 1 && sent == received)
        precondition(relativeUnixSocket("relative.sock") { _, _ in fatalError("relative path accepted") } == nil)
        precondition(relativeUnixSocket(root.appendingPathComponent(String(repeating: "x", count: 120)).path) { _, _ in fatalError("oversized basename accepted") } == nil)
        DispatchQueue.concurrentPerform(iterations: 32) { _ in
            precondition(relativeUnixSocket(path) { _, _ in Darwin.access("control.sock", F_OK) } == 0)
            precondition(FileManager.default.currentDirectoryPath == originalDirectory)
        }
        precondition(files.currentDirectoryPath == originalDirectory)
        print("Apple native-owner wire and descriptor-relative socket contracts passed; no VM qualification implied")
    }
}
