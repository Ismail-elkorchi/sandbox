import Foundation
import Virtualization

private let maxMessageBytes = 1024 * 1024
private let vmQueue = DispatchQueue(label: "org.sandsurf.virtual-machine")

private struct Disk: Decodable {
    let path: String
    let readOnly: Bool
}

private struct Request: Decodable {
    let kind: String
    let sandboxId: String?
    let kernel: String?
    let initialRamdisk: String?
    let commandLine: String?
    let disks: [Disk]?
    let memoryBytes: UInt64?
    let vcpus: Int?
}

private struct Response: Encodable {
    let kind: String
    let state: String
}

private enum OwnerError: Error {
    case invalidInvocation
    case invalidFrame
    case invalidRequest
    case unsupported
    case unexpectedState
}

private final class MachineOwner {
    private var machine: VZVirtualMachine?

    func handle(_ request: Request) throws -> Response {
        switch request.kind {
        case "create":
            guard machine == nil,
                  let kernel = request.kernel,
                  let commandLine = request.commandLine,
                  let disks = request.disks,
                  let memoryBytes = request.memoryBytes,
                  let vcpus = request.vcpus,
                  request.sandboxId != nil else {
                throw OwnerError.invalidRequest
            }
            guard VZVirtualMachine.isSupported else {
                return Response(kind: "not-applied", state: "stopped")
            }
            let configuration = VZVirtualMachineConfiguration()
            let bootLoader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: kernel))
            bootLoader.commandLine = commandLine
            if let initialRamdisk = request.initialRamdisk {
                bootLoader.initialRamdiskURL = URL(fileURLWithPath: initialRamdisk)
            }
            configuration.bootLoader = bootLoader
            configuration.cpuCount = vcpus
            configuration.memorySize = memoryBytes
            configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
            configuration.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
            configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
            configuration.networkDevices = []
            configuration.storageDevices = try disks.map { disk in
                let attachment = try VZDiskImageStorageDeviceAttachment(
                    url: URL(fileURLWithPath: disk.path),
                    readOnly: disk.readOnly
                )
                return VZVirtioBlockDeviceConfiguration(attachment: attachment)
            }
            try configuration.validate()
            let value = VZVirtualMachine(configuration: configuration, queue: vmQueue)
            machine = value
            try awaitResult { completion in value.start(completionHandler: completion) }
            guard value.state == .running else { throw OwnerError.unexpectedState }
            return Response(kind: "observed", state: "running")
        case "pause":
            guard let machine else { return Response(kind: "not-applied", state: "stopped") }
            guard machine.canPause else { return Response(kind: "not-applied", state: stateName(machine.state)) }
            try awaitResult { completion in machine.pause(completionHandler: completion) }
            guard machine.state == .paused else { throw OwnerError.unexpectedState }
            return Response(kind: "observed", state: "paused")
        case "resume":
            guard let machine else { return Response(kind: "not-applied", state: "stopped") }
            guard machine.canResume else { return Response(kind: "not-applied", state: stateName(machine.state)) }
            try awaitResult { completion in machine.resume(completionHandler: completion) }
            guard machine.state == .running else { throw OwnerError.unexpectedState }
            return Response(kind: "observed", state: "running")
        case "stop":
            try stop()
            return Response(kind: "observed", state: "stopped")
        default:
            throw OwnerError.invalidRequest
        }
    }

    func stop() throws {
        guard let machine else { return }
        if machine.canStop {
            try awaitResult { completion in
                machine.stop { error in
                    if let error {
                        completion(.failure(error))
                    } else {
                        completion(.success(()))
                    }
                }
            }
        }
        guard machine.state == .stopped else { throw OwnerError.unexpectedState }
        self.machine = nil
    }

    func contain() {
        do { try stop() } catch { exit(70) }
    }

    private func awaitResult(
        _ operation: @escaping (@escaping (Result<Void, Error>) -> Void) -> Void
    ) throws {
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var result: Result<Void, Error>?
        vmQueue.async {
            operation { value in
                lock.lock()
                result = value
                lock.unlock()
                semaphore.signal()
            }
        }
        guard semaphore.wait(timeout: .now() + 120) == .success else {
            throw OwnerError.unexpectedState
        }
        lock.lock()
        let completed = result
        lock.unlock()
        try completed?.get()
    }
}

private func stateName(_ state: VZVirtualMachine.State) -> String {
    switch state {
    case .running: return "running"
    case .paused: return "paused"
    case .stopped: return "stopped"
    case .starting: return "starting"
    case .pausing: return "running"
    case .resuming: return "paused"
    case .stopping: return "running"
    case .error: return "failed"
    @unknown default: return "failed"
    }
}

private func readExactly(_ count: Int) throws -> Data? {
    var result = Data()
    while result.count < count {
        guard let chunk = try FileHandle.standardInput.read(upToCount: count - result.count) else {
            if result.isEmpty { return nil }
            throw OwnerError.invalidFrame
        }
        if chunk.isEmpty {
            if result.isEmpty { return nil }
            throw OwnerError.invalidFrame
        }
        result.append(chunk)
    }
    return result
}

private func readRequest() throws -> Request? {
    guard let prefix = try readExactly(4) else { return nil }
    let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
    guard length > 0 && length <= maxMessageBytes,
          let payload = try readExactly(length) else {
        throw OwnerError.invalidFrame
    }
    return try JSONDecoder().decode(Request.self, from: payload)
}

private func writeResponse(_ response: Response) throws {
    let payload = try JSONEncoder().encode(response)
    guard payload.count <= maxMessageBytes else { throw OwnerError.invalidFrame }
    var length = UInt32(payload.count).bigEndian
    let prefix = Data(bytes: &length, count: MemoryLayout<UInt32>.size)
    try FileHandle.standardOutput.write(contentsOf: prefix)
    try FileHandle.standardOutput.write(contentsOf: payload)
}

guard CommandLine.arguments == [CommandLine.arguments[0], "--sandsurf-owner-v1"] else {
    throw OwnerError.invalidInvocation
}

private let owner = MachineOwner()
do {
    while let request = try readRequest() {
        do {
            let response = try owner.handle(request)
            try writeResponse(response)
            if request.kind == "stop" { break }
        } catch OwnerError.invalidRequest {
            try writeResponse(Response(kind: "not-applied", state: "stopped"))
        }
    }
    owner.contain()
} catch {
    owner.contain()
    throw error
}
