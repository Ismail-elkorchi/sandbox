import Foundation

struct Disk: Decodable {
    let path: String
    let readOnly: Bool
}

/// Private native-owner wire contract, tested against Rust's emitted requests.
/// This is channel decoding, not admission of host authority.
struct Request: Decodable {
    let kind: String
    let machineId: String?
    let kernel: String?
    let initialRamdisk: String?
    let commandLine: String?
    let disks: [Disk]?
    let memoryBytes: UInt64?
    let vcpus: Int?
    let controlSocket: String?
    let hostConnectPorts: [UInt32]?
    let guestListenPorts: [UInt32]?
    let savedState: String?

    private enum Fields: String, CodingKey, CaseIterable {
        case kind, machineId, kernel, initialRamdisk, commandLine, disks, memoryBytes,
             vcpus, controlSocket, hostConnectPorts, guestListenPorts, savedState
    }
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(intValue: Int) { return nil }
        init?(stringValue: String) { self.stringValue = stringValue }
    }
    init(from decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: Key.self)
        let allowed = Set(Fields.allCases.map { $0.rawValue })
        guard keys.allKeys.allSatisfy({ allowed.contains($0.stringValue) }) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown native-owner field"))
        }
        let fields = try decoder.container(keyedBy: Fields.self)
        kind = try fields.decode(String.self, forKey: .kind)
        machineId = try fields.decodeIfPresent(String.self, forKey: .machineId)
        kernel = try fields.decodeIfPresent(String.self, forKey: .kernel)
        initialRamdisk = try fields.decodeIfPresent(String.self, forKey: .initialRamdisk)
        commandLine = try fields.decodeIfPresent(String.self, forKey: .commandLine)
        disks = try fields.decodeIfPresent([Disk].self, forKey: .disks)
        memoryBytes = try fields.decodeIfPresent(UInt64.self, forKey: .memoryBytes)
        vcpus = try fields.decodeIfPresent(Int.self, forKey: .vcpus)
        controlSocket = try fields.decodeIfPresent(String.self, forKey: .controlSocket)
        hostConnectPorts = try fields.decodeIfPresent([UInt32].self, forKey: .hostConnectPorts)
        guestListenPorts = try fields.decodeIfPresent([UInt32].self, forKey: .guestListenPorts)
        savedState = try fields.decodeIfPresent(String.self, forKey: .savedState)
    }
}

struct Response: Encodable {
    let kind: String
    let state: String
}
