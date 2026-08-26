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
  SandboxArtifactBundle,
  SandboxArtifactEntry,
  SandboxChangeBaseEntry,
  SandboxChangeOperation,
  SandboxChangeSet,
  SandboxCleanupReport,
  SandboxResourceUsage,
  SandboxRunResult,
  SandboxTermination,
  SandboxWorkspaceChangeSet,
} from "./result.js";
import type { ResourceLimits } from "./resources.js";
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
  const host = object(source.host, "enforcement.host");
  const target = object(source.target, "enforcement.target");
  const runtimeView = object(source.runtimeView, "enforcement.runtimeView");
  const conformance = object(source.conformance, "enforcement.conformance");
  const boundaryKind = string(boundary.kind, "boundary.kind");
  if (boundaryKind !== "os-process" && boundaryKind !== "hardware-virtualized") {
    throw new TypeError("invalid enforcement boundary");
  }
  const stability = string(boundary.stability, "boundary.stability");
  if (stability !== "stable" && stability !== "experimental") {
    throw new TypeError("invalid backend stability");
  }
  const runtimeKind = string(runtimeView.kind, "runtimeView.kind");
  if (runtimeKind !== "system" && runtimeKind !== "empty") {
    throw new TypeError("invalid runtime view");
  }
  const targetOs = string(target.operatingSystem, "target.operatingSystem");
  if (targetOs !== "linux" && targetOs !== "macos" && targetOs !== "windows") {
    throw new TypeError("invalid target operating system");
  }
  const targetPathStyle = pathStyle(target.pathStyle, "target.pathStyle");
  return {
    boundary: {
      kind: boundaryKind,
      backendId: string(boundary.backendId, "boundary.backendId"),
      backendVersion: string(boundary.backendVersion, "boundary.backendVersion"),
      stability,
      mechanism: stringArray(boundary.mechanism, "boundary.mechanism"),
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
    runtimeView: {
      kind: runtimeKind,
      manifestDigest: digest(runtimeView.manifestDigest, "runtimeView.manifestDigest"),
      visibleRoots: stringArray(runtimeView.visibleRoots, "runtimeView.visibleRoots"),
    },
    caveats: array(source.caveats, "enforcement.caveats").map(parseCaveat),
    conformance: {
      manifestId: string(conformance.manifestId, "conformance.manifestId"),
      buildId: string(conformance.buildId, "conformance.buildId"),
    },
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
    case "filesystem.grant-roots-identity-bound": case "filesystem.read-confined": case "filesystem.content-write-confined": case "filesystem.namespace-mutation-confined": case "filesystem.metadata-mutation-confined": case "filesystem.execution-confined": case "filesystem.host-user-data-hidden":
    case "network.no-external-connect": case "network.no-external-listen": case "network.no-host-loopback": case "network.egress-brokered": case "network.private-addresses-denied":
    case "process.host-enumeration-denied": case "process.host-control-denied": case "process.complete-tree-termination":
    case "ipc.host-endpoints-hidden-outside-grants": case "ipc.host-shared-memory-hidden":
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

export function parseResourceLimits(value: unknown): ResourceLimits {
  const source = object(value, "resources");
  const result: ResourceLimits = {
    wallTimeMs: number(source.wallTimeMs, "resources.wallTimeMs"),
    memoryBytes: number(source.memoryBytes, "resources.memoryBytes"),
    maxProcesses: number(source.maxProcesses, "resources.maxProcesses"),
    maxOutputBytes: number(source.maxOutputBytes, "resources.maxOutputBytes"),
    terminationGraceMs: number(source.terminationGraceMs, "resources.terminationGraceMs"),
  };
  if (source.cpuTimeMs !== undefined) result.cpuTimeMs = number(source.cpuTimeMs, "resources.cpuTimeMs");
  if (source.maxOpenFilesPerProcess !== undefined) result.maxOpenFilesPerProcess = number(source.maxOpenFilesPerProcess, "resources.maxOpenFilesPerProcess");
  if (source.maxSingleFileBytes !== undefined) result.maxSingleFileBytes = number(source.maxSingleFileBytes, "resources.maxSingleFileBytes");
  return result;
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
  const backend = object(source.backend, "summary.backend");
  const backendStability = string(backend.stability, "backend.stability");
  if (backendStability !== "stable" && backendStability !== "experimental") throw new TypeError("invalid backend stability");
  const filesystem = object(source.filesystem, "summary.filesystem");
  const runtimeView = string(filesystem.runtimeView, "filesystem.runtimeView");
  if (runtimeView !== "system" && runtimeView !== "empty") throw new TypeError("invalid runtime view");
  const processPolicy = object(source.process, "summary.process");
  if (string(processPolicy.hostProcesses, "process.hostProcesses") !== "deny" || string(processPolicy.hostIpc, "process.hostIpc") !== "deny") throw new TypeError("invalid process policy");
  const network = object(source.network, "summary.network");
  const networkMode = string(network.mode, "network.mode");
  if (networkMode !== "none" && networkMode !== "managed" && networkMode !== "unrestricted") throw new TypeError("invalid prepared network mode");
  const preparedNetwork = networkMode === "none"
    ? {
        mode: "none" as const,
        topology: preparedIsolation.kind === "hardware-vm"
          ? requireLiteral(network.topology, "no-virtual-nic", "network.topology")
          : requireLiteral(network.topology, "private-namespace", "network.topology"),
      }
    : networkMode === "managed"
      ? {
          mode: "managed" as const,
          topology: requireLiteral(network.topology, "private-namespace-broker", "network.topology"),
          allow: array(network.allow, "network.allow").map(parseManagedNetworkRule),
        }
      : { mode: "unrestricted" as const, topology: requireLiteral(network.topology, "host-network-namespace", "network.topology") };
  const privateHomePath = filesystem.privateHomePath === null ? null : string(filesystem.privateHomePath, "filesystem.privateHomePath");
  return {
    isolation: preparedIsolation,
    backend: {
      id: string(backend.id, "backend.id"),
      version: string(backend.version, "backend.version"),
      stability: backendStability,
    },
    filesystem: {
      runtimeView,
      runtimeManifestDigest: digest(filesystem.runtimeManifestDigest, "filesystem.runtimeManifestDigest"),
      grants: array(filesystem.grants, "filesystem.grants").map((entry) => {
        const grant = object(entry, "grant");
        const access = string(grant.access, "grant.access");
        const execution = string(grant.execution, "grant.execution");
        if (access !== "read" && access !== "read-write") throw new TypeError("invalid grant access");
        if (execution !== "deny" && execution !== "allow") throw new TypeError("invalid grant execution");
        return {
          requestedHostPath: string(grant.requestedHostPath, "grant.requestedHostPath"),
          resolvedHostPath: string(grant.resolvedHostPath, "grant.resolvedHostPath"),
          hostIdentityDigest: digest(grant.hostIdentityDigest, "grant.hostIdentityDigest"),
          targetPath: string(grant.targetPath, "grant.targetPath"),
          access,
          execution,
        };
      }),
      masks: array(filesystem.masks, "filesystem.masks").map((entry) => {
        const mask = object(entry, "mask");
        const replacement = string(mask.replacement, "mask.replacement");
        if (replacement !== "inaccessible" && replacement !== "empty-file" && replacement !== "empty-directory") throw new TypeError("invalid mask replacement");
        return { targetPath: string(mask.targetPath, "mask.targetPath"), replacement };
      }),
      privateHomePath,
      temporaryPath: string(filesystem.temporaryPath, "filesystem.temporaryPath"),
    },
    network: preparedNetwork,
    process: { hostProcesses: "deny", hostIpc: "deny" },
    resources: parseResourceLimits(source.resources),
  };
}

function parseHardwareVmIsolation(source: JsonObject): import("./sandbox.js").SandboxIsolation {
  const image = object(source.image, "isolation.image");
  const trust = string(image.trust, "isolation.image.trust");
  if (trust !== "bundled" && trust !== "explicit-local") throw new TypeError("invalid image trust");
  const filesystemTransport = string(source.filesystemTransport, "isolation.filesystemTransport");
  if (filesystemTransport !== "ephemeral" && filesystemTransport !== "import") {
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
    resources: parseResourceLimits(source.resources),
    execution: parseExecutionSummary(source.execution),
  };
}

function parseExecutionSummary(value: unknown): PreparedRunSummary["execution"] {
  const source = object(value, "execution");
  const stdin = streamMode(source.stdin, ["pipe", "closed"], "execution.stdin");
  const stdout = streamMode(source.stdout, ["pipe", "capture", "discard"], "execution.stdout");
  const stderr = streamMode(source.stderr, ["pipe", "capture", "discard"], "execution.stderr");
  const result: PreparedRunSummary["execution"] = {
    executable: string(source.executable, "execution.executable"),
    args: stringArray(source.args, "execution.args"),
    cwd: string(source.cwd, "execution.cwd"),
    cwdIdentityDigest: digest(source.cwdIdentityDigest, "execution.cwdIdentityDigest"),
    environmentNames: stringArray(source.environmentNames, "execution.environmentNames"),
    sensitiveEnvironmentNames: stringArray(source.sensitiveEnvironmentNames, "execution.sensitiveEnvironmentNames"),
    stdin,
    stdout,
    stderr,
  };
  if (source.executableIdentityDigest !== undefined) result.executableIdentityDigest = digest(source.executableIdentityDigest, "execution.executableIdentityDigest");
  if (source.executableContentSha256 !== undefined) result.executableContentSha256 = digest(source.executableContentSha256, "execution.executableContentSha256");
  return result;
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
  if (source.backend !== undefined) result.backend = string(source.backend, "error.backend");
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
    parseArtifactEntry(entry, segment, ranges, "artifact entry"));
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
  const targetPath = normalizedAbsolutePath(source.targetPath, "change-set targetPath");
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
    value: { targetPath, bytes, changeSet: parsed },
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
    return { kind, entry: parseArtifactEntry(source.entry, content, ranges, "change-set upsert") };
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
): SandboxArtifactEntry {
  const source = object(value, label);
  if (source.contentHex !== undefined && source.contentHex !== null) {
    throw new TypeError(`${label} content must use binary protocol frames`);
  }
  const kind = artifactKind(source.kind, `${label} kind`);
  const parsed: SandboxArtifactEntry = {
    path: noNulString(source.path, `${label} path`),
    kind,
    mode: boundedMode(source.mode, `${label} mode`),
    modifiedUnixMs: integer(source.modifiedUnixMs, `${label} modifiedUnixMs`),
  };
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

function artifactKind(value: unknown, label: string): SandboxArtifactEntry["kind"] {
  const kind = string(value, label);
  if (kind !== "directory" && kind !== "regular-file" && kind !== "symbolic-link") {
    throw new TypeError(`${label} is invalid`);
  }
  return kind;
}

function validateArtifactShape(entry: SandboxArtifactEntry | SandboxChangeBaseEntry, requireContent: boolean): void {
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
