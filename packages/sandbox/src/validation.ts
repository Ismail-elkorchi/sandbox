import { createHash } from "node:crypto";
import type {
  EnforcementCaveat,
  EnforcementLayer,
  EnforcementReport,
  GuaranteeFact,
} from "./enforcement.js";
import type { SandboxErrorData } from "./errors.js";
import type { GuaranteeId } from "./requirements.js";
import type { ManagedNetworkRule } from "./policy.js";
import type {
  FilesystemAccess,
  FilesystemResourcePurpose,
  SandboxPath,
} from "./policy.js";
import type {
  SandboxArtifactBundle,
  SandboxArtifactEntry,
  SandboxChangeArtifactEntry,
  SandboxChangeBaseEntry,
  SandboxChangeOperation,
  SandboxChangeSet,
  SandboxCleanupReport,
  SandboxResourceUsage,
  SandboxRunResult,
  SandboxTermination,
  SandboxWorkspaceChangeSet,
} from "./result.js";
import type { HardLimit, ResolvedResourceLimits, ResourceLimitScope } from "./resources.js";
import type {
  PreparedProcessSummary,
  PreparedRunSummary,
  PreparedSessionSummary,
} from "./summary.js";

export type JsonObject = Record<string, unknown>;

export function object(value: unknown, label = "value"): JsonObject {
  if (!isObject(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

export function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function string(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${label} must be a string`);
  }
  return value;
}

export function number(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

export function integer(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${label} must be a safe integer`);
  }
  return value;
}

export function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(`${label} must be a boolean`);
  }
  return value;
}

export function array(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} must be an array`);
  }
  return value;
}

export function digest(value: unknown, label: string): string {
  const parsed = string(value, label);
  if (!/^[a-f0-9]{64}$/u.test(parsed)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  }
  return parsed;
}

export function stringArray(value: unknown, label: string): readonly string[] {
  return array(value, label).map((entry, index) => string(entry, `${label}[${index}]`));
}

export function parseEnforcement(value: unknown): EnforcementReport {
  const source = object(value, "enforcement");
  const boundary = object(source.boundary, "enforcement.boundary");
  const implementation = object(source.implementation, "enforcement.implementation");
  const host = object(source.host, "enforcement.host");
  const target = object(source.target, "enforcement.target");
  const filesystem = object(source.filesystem, "enforcement.filesystem");
  const boundaryKind = string(boundary.kind, "boundary.kind");
  if (boundaryKind !== "os-process" && boundaryKind !== "hardware-virtualized") {
    throw new TypeError("invalid enforcement boundary");
  }
  const stability = string(implementation.stability, "implementation.stability");
  if (stability !== "stable" && stability !== "experimental") {
    throw new TypeError("invalid implementation stability");
  }
  const filesystemKind = string(filesystem.kind, "filesystem.kind");
  if (filesystemKind !== "host" && filesystemKind !== "isolated") {
    throw new TypeError("invalid filesystem kind");
  }
  const targetOs = string(target.operatingSystem, "target.operatingSystem");
  if (targetOs !== "linux" && targetOs !== "macos" && targetOs !== "windows") {
    throw new TypeError("invalid target operating system");
  }
  const targetPathStyle = pathStyle(target.pathStyle, "target.pathStyle");
  return {
    boundary: {
      kind: boundaryKind,
    },
    implementation: {
      id: string(implementation.id, "implementation.id"),
      version: string(implementation.version, "implementation.version"),
      buildId: string(implementation.buildId, "implementation.buildId"),
      conformanceManifestId: string(implementation.conformanceManifestId, "implementation.conformanceManifestId"),
      stability,
      mechanism: stringArray(implementation.mechanism, "implementation.mechanism"),
    },
    host: {
      platform: platform(host.platform),
      architecture: string(host.architecture, "host.architecture"),
      pathStyle: pathStyle(host.pathStyle, "host.pathStyle"),
    },
    target: {
      operatingSystem: targetOs,
      pathStyle: targetPathStyle,
    },
    guarantees: array(source.guarantees, "enforcement.guarantees").map(parseGuarantee),
    filesystem: {
      kind: filesystemKind,
      resourceManifestDigest: digest(filesystem.resourceManifestDigest, "filesystem.resourceManifestDigest"),
      visibleRoots: stringArray(filesystem.visibleRoots, "filesystem.visibleRoots"),
    },
    caveats: array(source.caveats, "enforcement.caveats").map(parseCaveat),
  };
}

function parseGuarantee(value: unknown): GuaranteeFact {
  const source = object(value, "guarantee");
  const status = string(source.status, "guarantee.status");
  if (status !== "satisfied" && status !== "unsatisfied") {
    throw new TypeError("invalid guarantee status");
  }
  const result: GuaranteeFact = {
    id: guaranteeId(source.id),
    status,
  };
  const layers = source.enforcedBy;
  const mechanism = source.mechanism;
  const evidence = source.evidence;
  const caveats = source.caveats;
  if (layers !== undefined) result.enforcedBy = array(layers, "guarantee.enforcedBy").map(enforcementLayer);
  if (mechanism !== undefined) result.mechanism = stringArray(mechanism, "guarantee.mechanism");
  if (evidence !== undefined) result.evidence = stringArray(evidence, "guarantee.evidence");
  if (caveats !== undefined) result.caveats = stringArray(caveats, "guarantee.caveats");
  return result;
}

function parseCaveat(value: unknown): EnforcementCaveat {
  const source = object(value, "caveat");
  return {
    code: string(source.code, "caveat.code"),
    message: string(source.message, "caveat.message"),
    affectedGuarantees: array(source.affectedGuarantees, "caveat.affectedGuarantees").map(guaranteeId),
  };
}

function guaranteeId(value: unknown): GuaranteeId {
  const id = string(value, "guarantee.id");
  switch (id) {
    case "runtime.setup-before-exec": case "runtime.no-ambient-environment": case "runtime.no-ambient-handles": case "runtime.executable-identity-bound":
    case "filesystem.resource-identities-bound": case "filesystem.content-read-confined": case "filesystem.content-write-confined": case "filesystem.directory-entry-mutation-confined": case "filesystem.metadata-mutation-confined": case "filesystem.execution-confined": case "filesystem.name-visibility-confined": case "filesystem.isolated-layout":
    case "network.no-external-connect": case "network.no-external-listen": case "network.no-host-loopback": case "network.egress-brokered": case "network.private-addresses-denied":
    case "process.host-visibility-denied": case "process.host-control-denied": case "process.descendant-tree-termination": case "process.group-termination":
    case "ipc.host-endpoints-hidden": case "ipc.host-shared-memory-hidden":
    case "resource.wall-time-hard": case "resource.output-hard": case "resource.memory-hard": case "resource.cpu-time-hard": case "resource.process-count-hard": case "resource.open-files-hard": case "resource.single-file-size-hard":
    case "vm.boot-artifacts-verified": case "vm.guest-control-authenticated": case "vm.control-plane-hidden-from-target": case "vm.host-filesystem-absent-outside-imports":
      return id;
    default: throw new TypeError(`unknown guarantee id ${id}`);
  }
}

function enforcementLayer(value: unknown): EnforcementLayer {
  const layer = string(value, "enforcement layer");
  switch (layer) {
    case "kernel": case "supervisor": case "broker": case "hypervisor": case "guest-kernel": case "guest-agent": case "composition": return layer;
    default: throw new TypeError(`invalid enforcement layer ${layer}`);
  }
}

function platform(value: unknown): NodeJS.Platform {
  const name = string(value, "host.platform");
  switch (name) {
    case "aix": case "android": case "darwin": case "freebsd": case "haiku": case "linux": case "openbsd": case "sunos": case "win32": case "cygwin": case "netbsd": return name;
    default: throw new TypeError(`invalid Node platform ${name}`);
  }
}

function pathStyle(value: unknown, label: string): "posix" | "windows" {
  const style = string(value, label);
  if (style === "posix" || style === "windows") return style;
  throw new TypeError(`${label} is invalid`);
}

export function parseResourceLimits(value: unknown): ResolvedResourceLimits {
  const source = object(value, "resources");
  const result: ResolvedResourceLimits = {
    wallTime: parseHardLimit(source.wallTime, "resources.wallTime", ["process", "session"]),
    output: parseHardLimit(source.output, "resources.output", ["process", "session"]),
  };
  if (source.memory !== undefined) result.memory = parseHardLimit(source.memory, "resources.memory", ["descendant-tree", "session"]);
  if (source.processCount !== undefined) result.processCount = parseHardLimit(source.processCount, "resources.processCount", ["descendant-tree", "session"]);
  if (source.cpuTime !== undefined) result.cpuTime = parseHardLimit(source.cpuTime, "resources.cpuTime", ["descendant-tree", "session"]);
  if (source.openFiles !== undefined) result.openFiles = parseHardLimit(source.openFiles, "resources.openFiles", ["process"]);
  if (source.singleFileSize !== undefined) result.singleFileSize = parseHardLimit(source.singleFileSize, "resources.singleFileSize", ["process"]);
  return result;
}

function parseHardLimit<const Scope extends ResourceLimitScope>(value: unknown, label: string, scopes: readonly Scope[]): HardLimit<Scope> {
  const source = object(value, label);
  if (string(source.enforcement, `${label}.enforcement`) !== "hard") throw new TypeError(`${label}.enforcement must be hard`);
  const scope = string(source.scope, `${label}.scope`);
  const matched = scopes.find((candidate) => candidate === scope);
  if (matched === undefined) throw new TypeError(`${label}.scope is invalid`);
  return { enforcement: "hard", scope: matched, value: number(source.value, `${label}.value`) };
}

export function parseRunSummary(value: unknown): PreparedRunSummary {
  const source = object(value, "summary");
  const session = parseSessionSummary(source);
  return { ...session, execution: parseExecutionSummary(source.execution) };
}

export function parseSessionSummary(value: unknown): PreparedSessionSummary {
  const source = object(value, "summary");
  const isolation = object(source.isolation, "summary.isolation");
  const isolationKind = string(isolation.kind, "isolation.kind");
  const preparedIsolation = isolationKind === "process"
    ? { kind: "process" as const }
    : isolationKind === "hardware-vm"
      ? parseHardwareVmIsolation(isolation)
      : (() => { throw new TypeError("unsupported summary isolation"); })();
  const implementation = object(source.implementation, "summary.implementation");
  const implementationStability = string(implementation.stability, "implementation.stability");
  if (implementationStability !== "stable" && implementationStability !== "experimental") throw new TypeError("invalid implementation stability");
  const filesystem = object(source.filesystem, "summary.filesystem");
  const filesystemKind = string(filesystem.kind, "filesystem.kind");
  if (filesystemKind !== "host" && filesystemKind !== "isolated") throw new TypeError("invalid filesystem kind");
  const processPolicy = object(source.process, "summary.process");
  const visibility = streamMode(processPolicy.visibility, ["session", "host"], "process.visibility");
  const control = streamMode(processPolicy.control, ["session", "host"], "process.control");
  const processTermination = object(processPolicy.termination, "process.termination");
  const terminationScope = streamMode(processTermination.scope, ["descendant-tree", "process-group"], "process.termination.scope");
  const terminationGraceMs = number(processTermination.graceMs, "process.termination.graceMs");
  const ipcPolicy = object(source.ipc, "summary.ipc");
  const ipcVisibility = streamMode(ipcPolicy.visibility, ["session", "host"], "ipc.visibility");
  const network = object(source.network, "summary.network");
  const networkMode = string(network.mode, "network.mode");
  if (networkMode !== "none" && networkMode !== "managed" && networkMode !== "unrestricted") throw new TypeError("invalid prepared network mode");
  const preparedNetwork = networkMode === "none"
    ? {
        mode: "none" as const,
        topology: preparedIsolation.kind === "hardware-vm"
          ? requireLiteral(network.topology, "no-virtual-nic", "network.topology")
          : filesystem.kind === "host"
            ? requireLiteral(network.topology, "blocked-system-calls", "network.topology")
            : requireLiteral(network.topology, "private-namespace", "network.topology"),
      }
    : networkMode === "managed"
      ? {
          mode: "managed" as const,
          topology: requireLiteral(network.topology, "private-namespace-broker", "network.topology"),
          allow: array(network.allow, "network.allow").map(parseManagedNetworkRule),
        }
      : { mode: "unrestricted" as const, topology: requireLiteral(network.topology, "host-network-namespace", "network.topology") };
  const privateHomePath = filesystem.privateHomePath === null ? null : parseSandboxPath(filesystem.privateHomePath, "filesystem.privateHomePath");
  const temporaryPath = filesystem.temporaryPath === null ? null : parseSandboxPath(filesystem.temporaryPath, "filesystem.temporaryPath");
  return {
    isolation: preparedIsolation,
    implementation: {
      id: string(implementation.id, "implementation.id"),
      version: string(implementation.version, "implementation.version"),
      buildId: string(implementation.buildId, "implementation.buildId"),
      conformanceManifestId: string(implementation.conformanceManifestId, "implementation.conformanceManifestId"),
      stability: implementationStability,
    },
    filesystem: {
      kind: filesystemKind,
      resourceManifestDigest: digest(filesystem.resourceManifestDigest, "filesystem.resourceManifestDigest"),
      resources: array(filesystem.resources, "filesystem.resources").map((entry) => {
        const resource = object(entry, "resource");
        const sourcePath = object(resource.source, "resource.source");
        return {
          id: string(resource.id, "resource.id"),
          source: {
            requested: string(sourcePath.requested, "resource.source.requested"),
            resolved: string(sourcePath.resolved, "resource.source.resolved"),
            identityDigest: digest(sourcePath.identityDigest, "resource.source.identityDigest"),
          },
          target: parseSandboxPath(resource.target, "resource.target"),
          access: parseFilesystemAccess(resource.access, "resource.access"),
          purposes: array(resource.purposes, "resource.purposes").map(parseResourcePurpose),
        };
      }),
      masks: array(filesystem.masks, "filesystem.masks").map((entry) => {
        const mask = object(entry, "mask");
        const replacement = string(mask.replacement, "mask.replacement");
        if (replacement !== "inaccessible" && replacement !== "empty-file" && replacement !== "empty-directory") throw new TypeError("invalid mask replacement");
        const path = parseSandboxPath(mask.path, "mask.path");
        if (path.space !== "isolated") throw new TypeError("mask.path must be isolated");
        return { path, replacement };
      }),
      privateHomePath,
      temporaryPath,
    },
    network: preparedNetwork,
    process: { visibility, control, termination: { scope: terminationScope, graceMs: terminationGraceMs } },
    ipc: { visibility: ipcVisibility },
    resources: parseResourceLimits(source.resources),
  };
}

function parseHardwareVmIsolation(source: JsonObject): import("./sandbox.js").SandboxIsolation {
  const image = object(source.image, "isolation.image");
  const trust = string(image.trust, "isolation.image.trust");
  if (trust !== "bundled" && trust !== "explicit-local") throw new TypeError("invalid image trust");
  const filesystemTransport = string(source.filesystemTransport, "isolation.filesystemTransport");
  if (filesystemTransport !== "import") {
    throw new TypeError("invalid VM filesystem transport");
  }
  return {
    kind: "hardware-vm",
    image: {
      manifestPath: string(image.manifestPath, "isolation.image.manifestPath"),
      trust,
      ...(image.digest === undefined ? {} : { digest: digest(image.digest, "isolation.image.digest") }),
    },
    filesystemTransport,
  };
}

function parseManagedNetworkRule(value: unknown): ManagedNetworkRule {
  const source = object(value, "managed network rule");
  if (string(source.transport, "managed transport") !== "tcp") throw new TypeError("managed transport must be TCP");
  const destination = object(source.destination, "managed destination");
  const kind = string(destination.kind, "managed destination kind");
  const parsedDestination: ManagedNetworkRule["destination"] = kind === "dns"
    ? {
        kind,
        name: string(destination.name, "managed DNS name"),
        includeSubdomains: boolean(destination.includeSubdomains, "managed DNS includeSubdomains"),
        allowPrivateAddresses: boolean(destination.allowPrivateAddresses, "managed DNS allowPrivateAddresses"),
      }
    : kind === "ip"
      ? { kind, cidr: string(destination.cidr, "managed IP CIDR") }
      : (() => { throw new TypeError("invalid managed destination kind"); })();
  return {
    transport: "tcp",
    destination: parsedDestination,
    ports: array(source.ports, "managed ports").map((entry) => {
      if (typeof entry === "number") return number(entry, "managed port");
      const range = object(entry, "managed port range");
      return { from: number(range.from, "managed port from"), to: number(range.to, "managed port to") };
    }),
  };
}

export function parseProcessSummary(value: unknown): PreparedProcessSummary {
  const source = object(value, "process summary");
  return {
    execution: parseExecutionSummary(source.execution),
  };
}

function parseExecutionSummary(value: unknown): PreparedRunSummary["execution"] {
  const source = object(value, "execution");
  const stdin = streamMode(source.stdin, ["pipe", "closed"], "execution.stdin");
  const stdout = streamMode(source.stdout, ["pipe", "capture", "discard"], "execution.stdout");
  const stderr = streamMode(source.stderr, ["pipe", "capture", "discard"], "execution.stderr");
  const result: PreparedRunSummary["execution"] = {
    executable: parseSandboxPath(source.executable, "execution.executable"),
    executableIdentityDigest: digest(source.executableIdentityDigest, "execution.executableIdentityDigest"),
    executableContentSha256: digest(source.executableContentSha256, "execution.executableContentSha256"),
    args: stringArray(source.args, "execution.args"),
    cwd: parseSandboxPath(source.cwd, "execution.cwd"),
    cwdIdentityDigest: digest(source.cwdIdentityDigest, "execution.cwdIdentityDigest"),
    environmentNames: stringArray(source.environmentNames, "execution.environmentNames"),
    sensitiveEnvironmentNames: stringArray(source.sensitiveEnvironmentNames, "execution.sensitiveEnvironmentNames"),
    stdin,
    stdout,
    stderr,
  };
  return result;
}

function parseSandboxPath(value: unknown, label: string): SandboxPath {
  const source = object(value, label);
  const space = string(source.space, `${label}.space`);
  const path = string(source.path, `${label}.path`);
  if (space === "host" || space === "isolated") return { space, path };
  throw new TypeError(`${label}.space is invalid`);
}

function parseFilesystemAccess(value: unknown, label: string): FilesystemAccess {
  const source = object(value, label);
  return {
    content: streamMode(source.content, ["read", "read-write"], `${label}.content`),
    directoryEntries: streamMode(source.directoryEntries, ["read", "read-write"], `${label}.directoryEntries`),
    metadata: streamMode(source.metadata, ["read", "read-write"], `${label}.metadata`),
    execution: streamMode(source.execution, ["deny", "allow"], `${label}.execution`),
  };
}

function parseResourcePurpose(value: unknown): FilesystemResourcePurpose {
  return streamMode(value, ["executable", "interpreter", "loader", "library", "cache", "data"], "resource purpose");
}

function streamMode<const T extends string>(value: unknown, choices: readonly T[], label: string): T {
  const parsed = string(value, label);
  const found = choices.find((choice) => choice === parsed);
  if (found === undefined) throw new TypeError(`${label} is invalid`);
  return found;
}

function requireLiteral<const T extends string>(value: unknown, expected: T, label: string): T {
  if (value !== expected) throw new TypeError(`${label} must be ${expected}`);
  return expected;
}

export function parseErrorData(value: unknown): SandboxErrorData {
  const source = object(value, "runtime error");
  const phase = string(source.phase, "error.phase");
  switch (phase) {
    case "probe": case "validate": case "prepare": case "activate": case "spawn": case "execute": case "terminate": case "artifact-export": case "cleanup": break;
    default: throw new TypeError("invalid runtime error phase");
  }
  const result: SandboxErrorData = {
    code: string(source.code, "error.code"),
    message: string(source.message, "error.message").slice(0, 4096),
    phase,
    targetExecuted: boolean(source.targetExecuted, "error.targetExecuted"),
  };
  if (source.implementation !== undefined) result.implementation = string(source.implementation, "error.implementation");
  if (source.platform !== undefined) result.platform = string(source.platform, "error.platform");
  if (source.causeCode !== undefined) result.causeCode = string(source.causeCode, "error.causeCode");
  if (source.enforcement !== undefined) result.enforcement = parseEnforcement(source.enforcement);
  return result;
}

export function parseRunResult(value: unknown, artifactContent = Buffer.alloc(0)): SandboxRunResult {
  const source = object(value, "run result");
  const result: SandboxRunResult = {
    processId: string(source.processId, "result.processId"),
    policyDigest: digest(source.policyDigest, "result.policyDigest"),
    executionDigest: digest(source.executionDigest, "result.executionDigest"),
    termination: parseTermination(source.termination),
    enforcement: parseEnforcement(source.enforcement),
    violations: array(source.violations, "result.violations").map(parseViolation),
    usage: parseUsage(source.usage),
    cleanup: parseCleanup(source.cleanup),
  };
  const segments: BinaryRange[] = [];
  if (source.artifacts !== undefined) {
    const parsed = parseArtifactBundle(source.artifacts, artifactContent);
    result.artifacts = parsed.bundle;
    segments.push(parsed.segment);
  }
  if (source.changeSets !== undefined) {
    result.changeSets = array(source.changeSets, "changeSets").map((entry) => {
      const parsed = parseWorkspaceChangeSet(entry, artifactContent);
      segments.push(parsed.segment);
      return parsed.value;
    });
  }
  validateBinaryRanges(segments, artifactContent.byteLength, "artifact and change-set stream");
  return result;
}

interface BinaryRange { offset: number; length: number }

function parseArtifactBundle(
  value: unknown,
  content: Buffer,
): { bundle: SandboxArtifactBundle; segment: BinaryRange } {
  const source = object(value, "artifacts");
  const bytes = number(source.bytes, "artifacts.bytes");
  const binaryOffset = number(source.binaryOffset, "artifacts.binaryOffset");
  const segment = content.subarray(binaryOffset, binaryOffset + bytes);
  if (segment.byteLength !== bytes) throw new TypeError("artifact content range exceeds the stream");
  const ranges: BinaryRange[] = [];
  const files = array(source.files, "artifacts.files").map((entry) =>
    parseArtifactEntry(entry, segment, ranges, "artifact entry", true));
  validateBinaryRanges(ranges, bytes, "artifact content");
  return {
    bundle: { digest: digest(source.digest, "artifacts.digest"), bytes, files },
    segment: { offset: binaryOffset, length: bytes },
  };
}

function parseWorkspaceChangeSet(
  value: unknown,
  content: Buffer,
): { value: SandboxWorkspaceChangeSet; segment: BinaryRange } {
  const source = object(value, "workspace change set");
  const root = parseSandboxPath(source.root, "change-set root");
  const binaryOffset = number(source.binaryOffset, "change-set binaryOffset");
  const bytes = number(source.bytes, "change-set bytes");
  const segmentContent = content.subarray(binaryOffset, binaryOffset + bytes);
  if (segmentContent.byteLength !== bytes) throw new TypeError("change-set content range exceeds the stream");
  const encoded = object(source.changeSet, "changeSet");
  if (number(encoded.formatVersion, "changeSet.formatVersion") !== 1) {
    throw new TypeError("unsupported change-set format version");
  }
  const ranges: BinaryRange[] = [];
  const base = array(encoded.base, "changeSet.base").map(parseChangeBaseEntry);
  const operations = array(encoded.operations, "changeSet.operations").map((operation) =>
    parseChangeOperation(operation, segmentContent, ranges));
  validateBinaryRanges(ranges, bytes, "change-set content");
  const baseManifestDigest = digest(encoded.baseManifestDigest, "changeSet.baseManifestDigest");
  const baseWire = base.map((entry) => ({
    ...entry,
    sha256: entry.sha256 ?? null,
    linkTarget: entry.linkTarget ?? null,
  }));
  const actualBaseDigest = identityDigest(baseWire);
  if (actualBaseDigest !== baseManifestDigest) throw new TypeError("change-set base manifest digest mismatch");
  const parsed: SandboxChangeSet = {
    formatVersion: 1,
    baseManifestDigest,
    base,
    operations,
    digest: digest(encoded.digest, "changeSet.digest"),
  };
  const expectedDigest = parsed.digest;
  const actualDigest = identityDigest({
    formatVersion: 1,
    baseManifestDigest,
    base: baseWire,
    operations,
    digest: "",
  });
  if (actualDigest !== expectedDigest) throw new TypeError("change-set digest mismatch");
  return {
    value: { root, bytes, changeSet: parsed },
    segment: { offset: binaryOffset, length: bytes },
  };
}

function parseChangeBaseEntry(value: unknown): SandboxChangeBaseEntry {
  const source = object(value, "change-set base entry");
  const kind = artifactKind(source.kind, "change-set base kind");
  const entry: SandboxChangeBaseEntry = {
    path: normalizedRelativePath(source.path, "change-set base path"),
    kind,
    mode: boundedMode(source.mode, "change-set base mode"),
    modifiedUnixMs: integer(source.modifiedUnixMs, "change-set base modifiedUnixMs"),
  };
  if (source.sha256 !== undefined && source.sha256 !== null) entry.sha256 = digest(source.sha256, "change-set base sha256");
  if (source.linkTarget !== undefined && source.linkTarget !== null) entry.linkTarget = noNulString(source.linkTarget, "change-set base linkTarget");
  validateArtifactShape(entry, false);
  return entry;
}

function parseChangeOperation(
  value: unknown,
  content: Buffer,
  ranges: BinaryRange[],
): SandboxChangeOperation {
  const source = object(value, "change-set operation");
  const kind = string(source.kind, "change-set operation kind");
  if (kind === "upsert") {
    return { kind, entry: parseArtifactEntry(source.entry, content, ranges, "change-set upsert", false) };
  }
  if (kind === "delete") {
    return { kind, path: normalizedRelativePath(source.path, "change-set delete path") };
  }
  if (kind === "rename") {
    return {
      kind,
      from: normalizedRelativePath(source.from, "change-set rename source"),
      to: normalizedRelativePath(source.to, "change-set rename destination"),
    };
  }
  throw new TypeError("invalid change-set operation kind");
}

function parseArtifactEntry(
  value: unknown,
  content: Buffer,
  ranges: BinaryRange[],
  label: string,
  coordinatePath: true,
): SandboxArtifactEntry;
function parseArtifactEntry(
  value: unknown,
  content: Buffer,
  ranges: BinaryRange[],
  label: string,
  coordinatePath: false,
): SandboxChangeArtifactEntry;
function parseArtifactEntry(
  value: unknown,
  content: Buffer,
  ranges: BinaryRange[],
  label: string,
  coordinatePath: boolean,
): SandboxArtifactEntry | SandboxChangeArtifactEntry {
  const source = object(value, label);
  if (source.contentHex !== undefined && source.contentHex !== null) {
    throw new TypeError(`${label} content must use binary protocol frames`);
  }
  const kind = artifactKind(source.kind, `${label} kind`);
  const common = {
    kind,
    mode: boundedMode(source.mode, `${label} mode`),
    modifiedUnixMs: integer(source.modifiedUnixMs, `${label} modifiedUnixMs`),
  };
  const parsed: SandboxArtifactEntry | SandboxChangeArtifactEntry = coordinatePath
    ? { ...common, path: parseSandboxPath(source.path, `${label} path`) }
    : { ...common, path: normalizedRelativePath(source.path, `${label} path`) };
  if (kind === "regular-file") {
    const offset = number(source.contentOffset, `${label} content offset`);
    const length = number(source.contentLength, `${label} content length`);
    if (offset + length > content.byteLength) throw new TypeError(`${label} content range exceeds the stream`);
    const bytes = content.subarray(offset, offset + length);
    ranges.push({ offset, length });
    parsed.contentHex = bytes.toString("hex");
    parsed.sha256 = digest(source.sha256, `${label} sha256`);
    if (createHash("sha256").update(bytes).digest("hex") !== parsed.sha256) {
      throw new TypeError(`${label} file digest mismatch`);
    }
  } else if (source.contentOffset !== undefined || source.contentLength !== undefined) {
    throw new TypeError(`${label} non-file carries a content range`);
  }
  if (source.linkTarget !== undefined && source.linkTarget !== null) {
    parsed.linkTarget = noNulString(source.linkTarget, `${label} link target`);
  }
  if (kind !== "regular-file" && source.sha256 !== undefined && source.sha256 !== null) {
    parsed.sha256 = digest(source.sha256, `${label} sha256`);
  }
  validateArtifactShape(parsed, true);
  return parsed;
}

function artifactKind(value: unknown, label: string): SandboxChangeArtifactEntry["kind"] {
  const kind = string(value, label);
  if (kind !== "directory" && kind !== "regular-file" && kind !== "symbolic-link") {
    throw new TypeError(`${label} is invalid`);
  }
  return kind;
}

function validateArtifactShape(
  entry: SandboxArtifactEntry | SandboxChangeArtifactEntry | SandboxChangeBaseEntry,
  requireContent: boolean,
): void {
  if (entry.kind === "regular-file") {
    if (entry.sha256 === undefined || (requireContent && !("contentHex" in entry && entry.contentHex !== undefined)) || entry.linkTarget !== undefined) {
      throw new TypeError("regular-file change-set entry is incomplete");
    }
  } else if (entry.kind === "symbolic-link") {
    if (entry.linkTarget === undefined || entry.sha256 !== undefined || ("contentHex" in entry && entry.contentHex !== undefined)) {
      throw new TypeError("symbolic-link change-set entry is invalid");
    }
  } else if (entry.sha256 !== undefined || entry.linkTarget !== undefined || ("contentHex" in entry && entry.contentHex !== undefined)) {
    throw new TypeError("directory change-set entry is invalid");
  }
}

function validateBinaryRanges(ranges: readonly BinaryRange[], total: number, label: string): void {
  const nonempty = ranges.filter((range) => range.length !== 0).sort((left, right) => left.offset - right.offset);
  let cursor = 0;
  for (const range of nonempty) {
    if (range.offset !== cursor) throw new TypeError(`${label} ranges are overlapping or discontinuous`);
    cursor += range.length;
  }
  if (cursor !== total) throw new TypeError(`${label} contains unreferenced bytes`);
}

function normalizedRelativePath(value: unknown, label: string): string {
  const path = noNulString(value, label);
  if (path.length === 0 || path.startsWith("/") || path.split("/").some((part) => part.length === 0 || part === "." || part === "..")) {
    throw new TypeError(`${label} is not a normalized relative path`);
  }
  return path;
}

function normalizedAbsolutePath(value: unknown, label: string): string {
  const path = noNulString(value, label);
  if (!path.startsWith("/") || path === "/" || path.split("/").slice(1).some((part) => part.length === 0 || part === "." || part === "..")) {
    throw new TypeError(`${label} is not a normalized absolute path`);
  }
  return path;
}

function noNulString(value: unknown, label: string): string {
  const parsed = string(value, label);
  if (parsed.includes("\0")) throw new TypeError(`${label} contains NUL`);
  return parsed;
}

function boundedMode(value: unknown, label: string): number {
  const mode = number(value, label);
  if (mode > 0o7777) throw new TypeError(`${label} is invalid`);
  return mode;
}

function parseTermination(value: unknown): SandboxTermination {
  const source = object(value, "termination");
  const reason = string(source.reason, "termination.reason");
  switch (reason) {
    case "exit": return { reason, code: number(source.code, "termination.code") };
    case "signal": return { reason, signal: string(source.signal, "termination.signal") };
    case "timeout": case "cancelled": case "memory-limit": case "cpu-limit": case "process-limit": case "output-limit": case "single-file-size-limit": return { reason };
    case "runtime-failure": return { reason, error: parseErrorData(source.error) };
    default: throw new TypeError(`unsupported termination reason ${reason}`);
  }
}

function parseUsage(value: unknown): SandboxResourceUsage {
  const source = object(value, "usage");
  const result: SandboxResourceUsage = {
    wallTimeMs: number(source.wallTimeMs, "usage.wallTimeMs"),
    stdoutBytes: number(source.stdoutBytes, "usage.stdoutBytes"),
    stderrBytes: number(source.stderrBytes, "usage.stderrBytes"),
  };
  if (source.cpuTimeMs !== undefined) result.cpuTimeMs = number(source.cpuTimeMs, "usage.cpuTimeMs");
  if (source.peakMemoryBytes !== undefined && source.peakMemoryBytes !== null) result.peakMemoryBytes = number(source.peakMemoryBytes, "usage.peakMemoryBytes");
  if (source.processesCreated !== undefined) result.processesCreated = number(source.processesCreated, "usage.processesCreated");
  if (source.maxConcurrentProcesses !== undefined) result.maxConcurrentProcesses = number(source.maxConcurrentProcesses, "usage.maxConcurrentProcesses");
  if (source.networkConnections !== undefined) result.networkConnections = number(source.networkConnections, "usage.networkConnections");
  return result;
}

export function parseViolation(value: unknown): import("./result.js").StructuredViolation {
  const source = object(value, "violation");
  const detailsSource = object(source.details, "violation.details");
  const details: Record<string, string | number | boolean> = {};
  for (const [name, detail] of Object.entries(detailsSource)) {
    if (typeof detail !== "string" && typeof detail !== "number" && typeof detail !== "boolean") {
      throw new TypeError("violation detail must be a string, number, or boolean");
    }
    details[name] = detail;
  }
  return {
    id: string(source.id, "violation.id"),
    kind: string(source.kind, "violation.kind"),
    processId: string(source.processId, "violation.processId"),
    timestampMs: number(source.timestampMs, "violation.timestampMs"),
    mechanism: string(source.mechanism, "violation.mechanism"),
    details,
  };
}

export function parseCleanup(value: unknown): SandboxCleanupReport {
  const source = object(value, "cleanup");
  return {
    completed: boolean(source.completed, "cleanup.completed"),
    failures: array(source.failures, "cleanup.failures").map((entry) => {
      const failure = object(entry, "cleanup failure");
      return {
        code: string(failure.code, "cleanup failure code"),
        resource: string(failure.resource, "cleanup failure resource"),
        message: string(failure.message, "cleanup failure message"),
      };
    }),
  };
}

function identityDigest(value: unknown): string {
  const chunks: Buffer[] = [];
  putDigestBytes(chunks, Buffer.from("SBX-DIGEST-1"));
  putDigestBytes(chunks, Buffer.from("IDENTITY"));
  encodeCanonical(chunks, value);
  return createHash("sha256").update(Buffer.concat(chunks)).digest("hex");
}

function encodeCanonical(chunks: Buffer[], value: unknown): void {
  if (value === null) {
    chunks.push(Buffer.from([0]));
  } else if (typeof value === "boolean") {
    chunks.push(Buffer.from([1, value ? 1 : 0]));
  } else if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("canonical number is not a safe integer");
    const encoded = Buffer.alloc(10);
    encoded[0] = 2;
    encoded[1] = value >= 0 ? 0 : 1;
    if (value >= 0) encoded.writeBigUInt64BE(BigInt(value), 2);
    else encoded.writeBigInt64BE(BigInt(value), 2);
    chunks.push(encoded);
  } else if (typeof value === "string") {
    chunks.push(Buffer.from([3]));
    putDigestBytes(chunks, Buffer.from(value));
  } else if (Array.isArray(value)) {
    chunks.push(Buffer.from([4]), digestLength(value.length));
    for (const entry of value) encodeCanonical(chunks, entry);
  } else if (isObject(value)) {
    const entries = Object.entries(value).sort(([left], [right]) => Buffer.from(left).compare(Buffer.from(right)));
    chunks.push(Buffer.from([5]), digestLength(entries.length));
    for (const [key, entry] of entries) {
      putDigestBytes(chunks, Buffer.from(key));
      encodeCanonical(chunks, entry);
    }
  } else {
    throw new TypeError("unsupported canonical digest value");
  }
}

function putDigestBytes(chunks: Buffer[], bytes: Buffer): void {
  chunks.push(digestLength(bytes.length), bytes);
}

function digestLength(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new TypeError("canonical digest length overflow");
  }
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}
