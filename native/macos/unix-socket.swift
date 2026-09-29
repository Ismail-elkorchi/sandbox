import Foundation
import Darwin

// Apple libpthread's descriptor-relative, per-thread directory primitive.
// https://github.com/apple-oss-distributions/libpthread/blob/main/private/pthread/private.h
@_silgen_name("pthread_fchdir_np")
private func threadDirectory(_ descriptor: Int32) -> Int32

// The result is shared only through this condition. The directory descriptor is
// borrowed until completion; the fresh worker resets its directory before then.
private final class UnixSocketLookup: @unchecked Sendable {
    let directory: Int32
    let name: [UInt8]
    let operation: @Sendable (inout sockaddr_un, socklen_t) -> Int32
    private let condition = NSCondition()
    private var completed = false
    private var value: Int32?

    init(directory: Int32, name: [UInt8], operation: @escaping @Sendable (inout sockaddr_un, socklen_t) -> Int32) {
        self.directory = directory
        self.name = name
        self.operation = operation
    }

    func run() {
        var result: Int32?
        if threadDirectory(directory) == 0 {
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            let length = socklen_t(2 + name.count)
            address.sun_len = UInt8(length)
            withUnsafeMutableBytes(of: &address.sun_path) { bytes in
                bytes.initializeMemory(as: UInt8.self, repeating: 0)
                bytes.copyBytes(from: name)
            }
            result = operation(&address, length)
            if threadDirectory(-1) != 0 { result = nil }
        }
        condition.lock()
        value = result
        completed = true
        condition.signal()
        condition.unlock()
    }

    func result() -> Int32? {
        condition.lock()
        defer { condition.unlock() }
        while !completed { condition.wait() }
        return value
    }
}

/// The AF_UNIX address is only a basename, regardless of the state root's
/// length. Never change the process directory or a reused dispatch worker's
/// directory, and never substitute an unowned short socket path elsewhere.
func relativeUnixSocket(_ path: String, operation: @escaping @Sendable (inout sockaddr_un, socklen_t) -> Int32) -> Int32? {
    guard path.hasPrefix("/"), !path.utf8.contains(0) else { return nil }
    let name = (path as NSString).lastPathComponent
    guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
          name.utf8.count + 1 <= MemoryLayout.size(ofValue: sockaddr_un().sun_path) else { return nil }
    let parent = (path as NSString).deletingLastPathComponent
    let directory = Darwin.open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard directory >= 0 else { return nil }
    defer { Darwin.close(directory) }
    let lookup = UnixSocketLookup(directory: directory, name: Array(name.utf8) + [0], operation: operation)
    Thread { lookup.run() }.start()
    return lookup.result()
}

/// Nonblocking admission plus one absolute deadline. A full Unix backlog is a
/// connection failure, not permission to dispatch onto an unconnected socket.
func connectUnix(_ path: String) -> Int32? {
    let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard descriptor >= 0 else { return nil }
    guard Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
          Darwin.fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else {
        Darwin.close(descriptor)
        return nil
    }
    let connected = relativeUnixSocket(path) { address, length in
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(descriptor, $0, length) }
        }
        if result == 0 { return 0 }
        guard errno == EINPROGRESS else { return -1 }
        let deadline = DispatchTime.now().uptimeNanoseconds + 10_000_000_000
        while DispatchTime.now().uptimeNanoseconds < deadline {
            var event = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
            let remaining = deadline - min(deadline, DispatchTime.now().uptimeNanoseconds)
            let ready = Darwin.poll(&event, 1, Int32(max(1, remaining / 1_000_000)))
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0, event.revents & Int16(POLLNVAL) == 0 else { return -1 }
            var error: Int32 = 0
            var size = socklen_t(MemoryLayout<Int32>.size)
            guard Darwin.getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else { return -1 }
            return 0
        }
        return -1
    }
    guard connected == 0, Darwin.fcntl(descriptor, F_SETFL, 0) == 0 else {
        Darwin.close(descriptor)
        return nil
    }
    return descriptor
}
