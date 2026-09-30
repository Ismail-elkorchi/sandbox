import Foundation
import Virtualization
import Darwin

private let maxMessageBytes = 1024 * 1024
private let vmQueueKey = DispatchSpecificKey<Bool>()
private let vmQueue: DispatchQueue = {
    let queue = DispatchQueue(label: "sandsurf.virtual-machine")
    queue.setSpecific(key: vmQueueKey, value: true)
    return queue
}()

// All VM/device access belongs to its associated queue. Callbacks already on
// that queue must not synchronously dispatch back to themselves.
private func onVMQueue<T>(_ operation: () -> T) -> T {
    if DispatchQueue.getSpecific(key: vmQueueKey) == true { return operation() }
    return vmQueue.sync(execute: operation)
}

private func nativeState(_ machine: VZVirtualMachine) -> VZVirtualMachine.State {
    onVMQueue { machine.state }
}


private enum OwnerError: Error {
    case invalidInvocation
    case invalidFrame
    case invalidRequest
    case unsupported
    case unexpectedState
    case socketRelay
}

private final class RelayConnection {
    private let local: Int32
    private let guest: VZVirtioSocketConnection
    private let lock = NSLock()
    private var remaining = 2
    private var closed = false
    private let completed: () -> Void

    init(local: Int32, guest: VZVirtioSocketConnection, completed: @escaping () -> Void) {
        self.local = local
        self.guest = guest
        self.completed = completed
    }

    func start() {
        let guestDescriptor = onVMQueue { guest.fileDescriptor }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            pump(from: local, to: guestDescriptor)
            Darwin.shutdown(guestDescriptor, SHUT_WR)
            finishedDirection()
        }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            pump(from: guestDescriptor, to: local)
            Darwin.shutdown(local, SHUT_WR)
            finishedDirection()
        }
    }

    func stop() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        Darwin.shutdown(local, SHUT_RDWR)
        Darwin.close(local)
        lock.unlock()
        onVMQueue { guest.close() }
    }

    private func pump(from source: Int32, to destination: Int32) {
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(source, &buffer, buffer.count)
            if count <= 0 { return }
            var offset = 0
            while offset < count {
                let written = buffer.withUnsafeBytes { bytes in
                    Darwin.write(destination, bytes.baseAddress!.advanced(by: offset), count - offset)
                }
                if written <= 0 { return }
                offset += written
            }
        }
    }

    private func finishedDirection() {
        lock.lock()
        remaining -= 1
        let isComplete = remaining == 0
        lock.unlock()
        if isComplete {
            stop()
            completed()
        }
    }
}

private final class SocketRelay {
    private let path: String
    private let device: VZVirtioSocketDevice
    private let hostConnectPorts: Set<UInt32>
    private let guestListenPorts: Set<UInt32>
    private let lock = NSLock()
    private var listener: Int32 = -1
    private var connections: [UUID: RelayConnection] = [:]
    private var guestListener: VZVirtioSocketListener?
    private var guestDelegate: GuestConnectionDelegate?

    init(
        path: String,
        device: VZVirtioSocketDevice,
        hostConnectPorts: [UInt32],
        guestListenPorts: [UInt32]
    ) throws {
        guard path.hasPrefix("/"),
              !hostConnectPorts.isEmpty,
              (hostConnectPorts + guestListenPorts).allSatisfy({ $0 >= 1024 && $0 != UInt32.max }),
              Set(hostConnectPorts).count == hostConnectPorts.count,
              Set(guestListenPorts).count == guestListenPorts.count else {
            throw OwnerError.socketRelay
        }
        self.path = path
        self.device = device
        self.hostConnectPorts = Set(hostConnectPorts)
        self.guestListenPorts = Set(guestListenPorts)
    }

    func start() throws {
        _ = Darwin.unlink(path)
        let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw OwnerError.socketRelay }
        let bound = relativeUnixSocket(path) { address, length in
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, length)
                }
            }
        }
        guard bound == 0,
              Darwin.chmod(path, mode_t(S_IRUSR | S_IWUSR)) == 0,
              Darwin.listen(descriptor, 32) == 0 else {
            Darwin.close(descriptor)
            _ = Darwin.unlink(path)
            throw OwnerError.socketRelay
        }
        lock.lock()
        listener = descriptor
        lock.unlock()
        if !guestListenPorts.isEmpty {
            let socketListener = VZVirtioSocketListener()
            let socketDelegate = GuestConnectionDelegate(
                basePath: path,
                ports: guestListenPorts,
                add: { [weak self] local, guest in
                    guard let self else {
                        Darwin.close(local)
                        onVMQueue { guest.close() }
                        return
                    }
                    self.add(local: local, guest: guest)
                }
            )
            socketListener.delegate = socketDelegate
            guestListener = socketListener
            guestDelegate = socketDelegate
            onVMQueue { for port in guestListenPorts { device.setSocketListener(socketListener, forPort: port) } }
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in self?.acceptLoop(descriptor) }
    }

    func stop() {
        lock.lock()
        let descriptor = listener
        listener = -1
        let active = Array(connections.values)
        connections.removeAll()
        lock.unlock()
        if descriptor >= 0 {
            Darwin.shutdown(descriptor, SHUT_RDWR)
            Darwin.close(descriptor)
        }
        active.forEach { $0.stop() }
        onVMQueue { for port in guestListenPorts { device.removeSocketListener(forPort: port) } }
        guestListener = nil
        guestDelegate = nil
        _ = Darwin.unlink(path)
    }

    private func acceptLoop(_ descriptor: Int32) {
        while true {
            let client = Darwin.accept(descriptor, nil, nil)
            if client < 0 { return }
            guard let port = requestedPort(client), hostConnectPorts.contains(port) else {
                Darwin.close(client)
                continue
            }
            vmQueue.async { [device, weak self] in
              device.connect(toPort: port) { result in
                guard let self else {
                    Darwin.close(client)
                    if case .success(let guest) = result { guest.close() }
                    return
                }
                switch result {
                case .failure:
                    Darwin.close(client)
                case .success(let guest):
                    let acknowledgement = Array("OK 1024\n".utf8)
                    let acknowledged = acknowledgement.withUnsafeBytes {
                        Darwin.write(client, $0.baseAddress!, acknowledgement.count)
                    }
                    guard acknowledged == acknowledgement.count else {
                        Darwin.close(client)
                        guest.close()
                        return
                    }
                    self.add(local: client, guest: guest)
                }
              }
            }
        }
    }

    private func remove(_ id: UUID) {
        lock.lock()
        connections.removeValue(forKey: id)
        lock.unlock()
    }

    private func add(local: Int32, guest: VZVirtioSocketConnection) {
        let id = UUID()
        let relay = RelayConnection(local: local, guest: guest) { [weak self] in
            self?.remove(id)
        }
        lock.lock()
        if listener < 0 {
            lock.unlock()
            relay.stop()
            return
        }
        connections[id] = relay
        lock.unlock()
        relay.start()
    }

    private func requestedPort(_ descriptor: Int32) -> UInt32? {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(32)
        while bytes.count < 128 {
            var byte: UInt8 = 0
            let count = Darwin.read(descriptor, &byte, 1)
            if count != 1 { return nil }
            if byte == 10 { break }
            bytes.append(byte)
        }
        guard bytes.count < 128,
              let line = String(bytes: bytes, encoding: .utf8),
              line.hasPrefix("CONNECT "),
              !line.dropFirst(8).isEmpty,
              line.dropFirst(8).allSatisfy({ $0.isASCII && $0.isNumber }),
              let port = UInt32(line.dropFirst(8)) else {
            return nil
        }
        return port
    }
}

private final class GuestConnectionDelegate: NSObject, VZVirtioSocketListenerDelegate {
    private let basePath: String
    private let ports: Set<UInt32>
    private let add: (Int32, VZVirtioSocketConnection) -> Void

    init(
        basePath: String,
        ports: Set<UInt32>,
        add: @escaping (Int32, VZVirtioSocketConnection) -> Void
    ) {
        self.basePath = basePath
        self.ports = ports
        self.add = add
    }

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let port = onVMQueue { connection.destinationPort }
        guard ports.contains(port) else { return false }
        DispatchQueue.global(qos: .userInitiated).async { [basePath, add] in
            guard let local = connectUnix("\(basePath)_\(port)") else {
                onVMQueue { connection.close() }
                return
            }
            add(local, connection)
        }
        return true
    }
}


private final class MachineOwner {
    private var machine: VZVirtualMachine?
    private var relay: SocketRelay?

    func handle(_ request: Request) throws -> Response {
        switch request.kind {
        case "inspect":
            guard let machine else { return Response(kind: "unknown", state: "stopped") }
            let state = nativeState(machine)
            switch state {
            case .running, .paused, .stopped, .error:
                return Response(kind: "observed", state: stateName(state))
            default:
                return Response(kind: "unknown", state: stateName(state))
            }
        case "create":
            return try launch(request, savedState: nil)
        case "restore":
            guard let savedState = request.savedState else { throw OwnerError.invalidRequest }
            if #available(macOS 14.0, *) {
                return try launch(request, savedState: savedState)
            }
            return Response(kind: "not-applied", state: "stopped")
        case "save":
            guard let machine,
                  let savedState = request.savedState,
                  savedState.hasPrefix("/"),
                  nativeState(machine) == .paused else {
                throw OwnerError.invalidRequest
            }
            if #available(macOS 14.0, *) {
                let url = URL(fileURLWithPath: savedState)
                guard !FileManager.default.fileExists(atPath: url.path) else {
                    throw OwnerError.invalidRequest
                }
                try awaitResult { completion in
                    machine.saveMachineStateTo(url: url) { error in
                        if let error { completion(.failure(error)) }
                        else { completion(.success(())) }
                    }
                }
                guard nativeState(machine) == .paused else { throw OwnerError.unexpectedState }
                return Response(kind: "observed", state: "paused")
            }
            return Response(kind: "not-applied", state: "paused")
        case "pause":
            guard let machine else { return Response(kind: "not-applied", state: "stopped") }
            guard onVMQueue({ machine.canPause }) else { return Response(kind: "not-applied", state: stateName(nativeState(machine))) }
            try awaitResult { completion in machine.pause(completionHandler: completion) }
            guard nativeState(machine) == .paused else { throw OwnerError.unexpectedState }
            return Response(kind: "observed", state: "paused")
        case "resume":
            guard let machine else { return Response(kind: "not-applied", state: "stopped") }
            guard onVMQueue({ machine.canResume }) else { return Response(kind: "not-applied", state: stateName(nativeState(machine))) }
            try awaitResult { completion in machine.resume(completionHandler: completion) }
            guard nativeState(machine) == .running else { throw OwnerError.unexpectedState }
            return Response(kind: "observed", state: "running")
        case "release":
            guard let machine, nativeState(machine) == .paused else {
                return Response(kind: "not-applied", state: "stopped")
            }
            relay?.stop()
            relay = nil
            self.machine = nil
            return Response(kind: "observed", state: "suspended")
        case "stop":
            try stop()
            return Response(kind: "observed", state: "stopped")
        default:
            throw OwnerError.invalidRequest
        }
    }

    private func launch(_ request: Request, savedState: String?) throws -> Response {
        guard machine == nil,
              let kernel = request.kernel,
              let commandLine = request.commandLine,
              let disks = request.disks,
              let memoryBytes = request.memoryBytes,
              let vcpus = request.vcpus,
              let controlSocket = request.controlSocket,
              let hostConnectPorts = request.hostConnectPorts,
              let guestListenPorts = request.guestListenPorts,
              request.machineId != nil,
              savedState == nil || savedState!.hasPrefix("/") else {
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
        if savedState != nil {
            if #available(macOS 14.0, *) {
                try configuration.validateSaveRestoreSupport()
            } else {
                throw OwnerError.unsupported
            }
        }
        let value = VZVirtualMachine(configuration: configuration, queue: vmQueue)
        machine = value
        if let savedState {
            if #available(macOS 14.0, *) {
                try awaitResult { completion in
                    value.restoreMachineStateFrom(url: URL(fileURLWithPath: savedState)) { error in
                        if let error { completion(.failure(error)) }
                        else { completion(.success(())) }
                    }
                }
                guard nativeState(value) == .paused else { throw OwnerError.unexpectedState }
            } else {
                throw OwnerError.unsupported
            }
        } else {
            try awaitResult { completion in value.start(completionHandler: completion) }
            guard nativeState(value) == .running else { throw OwnerError.unexpectedState }
        }
        guard let socketDevice = onVMQueue({ value.socketDevices.first as? VZVirtioSocketDevice }) else {
            throw OwnerError.unsupported
        }
        let socketRelay = try SocketRelay(
            path: controlSocket,
            device: socketDevice,
            hostConnectPorts: hostConnectPorts,
            guestListenPorts: guestListenPorts
        )
        try socketRelay.start()
        relay = socketRelay
        if savedState != nil {
            try awaitResult { completion in value.resume(completionHandler: completion) }
            guard nativeState(value) == .running else { throw OwnerError.unexpectedState }
        }
        return Response(kind: "observed", state: "running")
    }

    func stop() throws {
        relay?.stop()
        relay = nil
        guard let machine else { return }
        if onVMQueue({ machine.canStop }) {
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
        guard nativeState(machine) == .stopped else { throw OwnerError.unexpectedState }
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
    case .saving: return "paused"
    case .restoring: return "restoring"
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

@main
private enum SandsurfVMHelper {
    static func main() throws {
        guard CommandLine.arguments == [CommandLine.arguments[0], "--sandsurf-owner-v1"] else {
            throw OwnerError.invalidInvocation
        }

        signal(SIGPIPE, SIG_IGN)

        let owner = MachineOwner()
        do {
            while let request = try readRequest() {
                do {
                    let response = try owner.handle(request)
                    try writeResponse(response)
                    if request.kind == "stop" || request.kind == "release" { break }
                } catch OwnerError.invalidRequest {
                    try writeResponse(Response(kind: "not-applied", state: "stopped"))
                }
            }
            owner.contain()
        } catch {
            owner.contain()
            throw error
        }
    }
}
