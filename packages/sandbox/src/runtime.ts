import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdtemp, open, readFile, rm, writeFile, type FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PassThrough, Writable } from "node:stream";
import { spawn, type ChildProcess, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { EnforcementReport } from "./enforcement.js";
import type { VerifiedSandboxExtension } from "./extension.js";
import {
  SandboxProtocolError,
  SandboxPreparationExpiredError,
  SandboxRuntimeCrashedError,
  SandboxRuntimeIntegrityError,
  SandboxRuntimeNotFoundError,
  errorFromData,
  type SandboxError,
  type SandboxErrorData,
} from "./errors.js";
import type { SandboxProcess, SandboxProcessIdentity } from "./process.js";
import type { SandboxEvent, SandboxRunResult } from "./result.js";
import {
  FrameDecodeError,
  FrameDecoder,
  MAX_STREAM_PAYLOAD,
  MessageType,
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  decodeControl,
  encodeBinaryFrame,
  encodeControlFrame,
  type ProtocolFrame,
} from "./protocol.js";
import {
  array,
  boolean,
  number,
  object,
  parseErrorData,
  parseRunResult,
  parseViolation,
  string,
  type JsonObject,
} from "./validation.js";

interface PendingRequest {
  expected: readonly MessageType[];
  resolve(value: unknown): void;
  reject(error: Error): void;
}

interface ActiveProcessHooks {
  output(stream: "stdout" | "stderr", chunk: Buffer): void;
  artifact(chunk: Buffer): void;
  exit(value: unknown): void;
  event(value: unknown): void;
  fail(error: SandboxError): void;
}

export interface RuntimeSupport {
  protocol: { major: number; minor: number };
  packageVersion: string;
  host: { platform: string; architecture: string };
  backends: readonly {
    id: string;
    isolation: string;
    stability: "stable" | "experimental";
    available: boolean;
    capabilities: Readonly<Record<string, unknown>>;
  }[];
}

export class RuntimeLocator {
  readonly #extension: VerifiedSandboxExtension | undefined;

  constructor(extension?: VerifiedSandboxExtension) {
    this.#extension = extension;
  }

  locate(): Promise<VerifiedRuntime> {
    return this.#extension === undefined
      ? locateAndVerifyRuntime()
      : locateAndVerifyExplicitRuntime(this.#extension.runtimePath, this.#extension.runtimeDigest);
  }
}

interface VerifiedRuntime {
  path: string;
  file: FileHandle;
  cleanup?: () => Promise<void>;
}

async function locateAndVerifyExplicitRuntime(path: string, expected: string): Promise<VerifiedRuntime> {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o022) !== 0) {
    throw new SandboxRuntimeIntegrityError({
      code: "runtime_integrity.extension_file",
      message: "extension runtime is not an immutable regular file",
      phase: "probe",
      targetExecuted: false,
    });
  }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  const opened = await file.stat();
  const bytes = await file.readFile();
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (opened.dev !== metadata.dev || opened.ino !== metadata.ino || actual !== expected) {
    await file.close();
    throw new SandboxRuntimeIntegrityError({
      code: "runtime_integrity.extension_replaced",
      message: "extension runtime identity or digest changed",
      phase: "probe",
      targetExecuted: false,
    });
  }
  return { path, file };
}

async function locateAndVerifyRuntime(): Promise<VerifiedRuntime> {
  if (
    (process.platform !== "linux" && process.platform !== "darwin" && process.platform !== "win32")
    || (process.arch !== "x64" && process.arch !== "arm64")
  ) {
    throw new SandboxRuntimeNotFoundError({
      code: "runtime_not_found.platform",
      message: `no bundled runtime for ${process.platform}-${process.arch}`,
      phase: "probe",
      targetExecuted: false,
      platform: process.platform,
    });
  }
  const packageDirectory = dirname(fileURLToPath(import.meta.url));
  const nativeRoot = resolve(packageDirectory, "../native");
  const nativePlatform = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "macos" : "linux";
  const executableSuffix = process.platform === "win32" ? ".exe" : "";
  const binaryName = `sandbox-runtime-${nativePlatform}-${process.arch}${executableSuffix}`;
  const binaryPath = resolve(nativeRoot, `${nativePlatform}-${process.arch}`, binaryName);
  const manifestPath = resolve(nativeRoot, "manifest.json");
  let metadata;
  try {
    metadata = await lstat(binaryPath);
  } catch {
    throw new SandboxRuntimeNotFoundError({
      code: "runtime_not_found.binary",
      message: `bundled runtime is absent for ${nativePlatform}-${process.arch}`,
      phase: "probe",
      targetExecuted: false,
      platform: process.platform,
    });
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o022) !== 0) {
    throw new SandboxRuntimeIntegrityError({
      code: "runtime_integrity.file_type",
      message: "bundled runtime must be a non-symbolic, non-group-writable regular file",
      phase: "probe",
      targetExecuted: false,
      platform: process.platform,
    });
  }
  let manifest: JsonObject;
  try {
    manifest = object(JSON.parse(await readFile(manifestPath, "utf8")), "native manifest");
  } catch {
    throw new SandboxRuntimeIntegrityError({
      code: "runtime_integrity.manifest",
      message: "native runtime integrity manifest is missing or invalid",
      phase: "probe",
      targetExecuted: false,
      platform: process.platform,
    });
  }
  const files = object(manifest.files, "native manifest files");
  const manifestKey = `${nativePlatform}-${process.arch}/${binaryName}`;
  const expected = string(files[manifestKey], `native manifest ${manifestKey}`);
  let file: FileHandle;
  try {
    file = await open(binaryPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw new SandboxRuntimeIntegrityError({
      code: "runtime_integrity.open",
      message: "bundled runtime could not be opened without following links",
      phase: "probe",
      targetExecuted: false,
      platform: process.platform,
    });
  }
  const openedMetadata = await file.stat();
  if (!openedMetadata.isFile() || openedMetadata.dev !== metadata.dev || openedMetadata.ino !== metadata.ino) {
    await file.close();
    throw new SandboxRuntimeIntegrityError({
      code: "runtime_integrity.replaced",
      message: "bundled runtime identity changed during verification",
      phase: "probe",
      targetExecuted: false,
      platform: process.platform,
    });
  }
  const bytes = await file.readFile();
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (!/^[a-f0-9]{64}$/u.test(expected) || actual !== expected) {
    await file.close();
    throw new SandboxRuntimeIntegrityError({
      code: "runtime_integrity.digest",
      message: "bundled runtime digest does not match its package manifest",
      phase: "probe",
      targetExecuted: false,
      platform: process.platform,
    });
  }
  if (process.platform === "darwin") {
    try {
      await verifyMacCodeSignature(binaryPath);
    } catch (error) {
      await file.close();
      throw new SandboxRuntimeIntegrityError({
        code: "runtime_integrity.code_signature",
        message: error instanceof Error ? error.message : "bundled runtime code signature is invalid",
        phase: "probe",
        targetExecuted: false,
        platform: process.platform,
      });
    }
  }
  if (process.platform === "win32") {
    const snapshotDirectory = await mkdtemp(join(tmpdir(), "sandbox-runtime-snapshot-"));
    const snapshotPath = join(snapshotDirectory, binaryName);
    try {
      await writeFile(snapshotPath, bytes, { flag: "wx", mode: 0o700 });
      const snapshot = await open(snapshotPath, constants.O_RDONLY);
      await file.close();
      return {
        path: snapshotPath,
        file: snapshot,
        cleanup: () => rm(snapshotDirectory, { recursive: true, force: true }),
      };
    } catch (error) {
      await file.close();
      await rm(snapshotDirectory, { recursive: true, force: true });
      throw error;
    }
  }
  return { path: binaryPath, file };
}

function verifyMacCodeSignature(path: string): Promise<void> {
  return new Promise((resolveVerification, rejectVerification) => {
    const child = spawn("/usr/bin/codesign", ["--verify", "--strict", "--verbose=0", path], {
      stdio: "ignore",
      env: { PATH: "/usr/bin:/bin" },
    });
    const deadline = setTimeout(() => child.kill("SIGKILL"), 5_000);
    deadline.unref();
    child.once("error", (error) => {
      clearTimeout(deadline);
      rejectVerification(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(deadline);
      if (code === 0 && signal === null) resolveVerification();
      else rejectVerification(new Error(`bundled runtime code-signature verification failed (${code ?? signal ?? "unknown"})`));
    });
  });
}

export class RuntimeClient {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #decoder = new FrameDecoder();
  readonly #pending = new Map<string, PendingRequest>();
  readonly #stderr: Buffer[] = [];
  readonly #stderrLimit = 16 * 1024;
  #stderrBytes = 0;
  #requestSequence = 1;
  #writeChain: Promise<void> = Promise.resolve();
  #closed = false;
  #shuttingDown = false;
  #shutdownPromise: Promise<void> | undefined;
  #active: ActiveProcessHooks | undefined;
  #pendingOutput: { stream: "stdout" | "stderr"; chunk: Buffer }[] = [];
  #pendingArtifacts: Buffer[] = [];
  #pendingEvents: unknown[] = [];
  #pendingExit: unknown | undefined;
  #processLifecycle: "idle" | "starting" | "running" | "exited" = "idle";
  #stdinCredit = 0;
  #stdinWaiters: (() => void)[] = [];
  readonly #expirationHandlers = new Map<string, { runtimeExits: boolean; callback(): void }>();
  #expirationExitExpected = false;
  #helloResolve: (() => void) | undefined;
  #helloReject: ((error: Error) => void) | undefined;
  #helloReceived = false;
  readonly #runtimeCleanup: (() => Promise<void>) | undefined;
  #runtimeCleanupPromise: Promise<void> | undefined;

  private constructor(child: ChildProcessWithoutNullStreams, runtimeCleanup?: () => Promise<void>) {
    this.#child = child;
    this.#runtimeCleanup = runtimeCleanup;
    child.stdout.on("data", (chunk: Buffer) => this.#receive(chunk));
    child.stderr.on("data", (chunk: Buffer) => this.#receiveEmergency(chunk));
    child.stdin.on("error", (error) => this.#crash(error));
    child.on("error", (error) => this.#crash(error));
    child.on("exit", (code, signal) => {
      void this.#cleanupRuntimeSnapshot();
      if (this.#expirationExitExpected) {
        this.#closed = true;
        return;
      }
      if (!this.#closed && !this.#shuttingDown) {
        const details = this.#emergencyText();
        this.#crash(new Error(`runtime exited unexpectedly (${code ?? signal ?? "unknown"})${details.length === 0 ? "" : `: ${details}`}`));
      }
    });
  }

  static async launch(locator: RuntimeLocator): Promise<RuntimeClient> {
    const runtime = await locator.locate();
    const descriptorExecutionPath = process.platform === "linux"
      ? "/proc/self/fd/3"
      : process.platform === "darwin"
        ? "/dev/fd/3"
        : runtime.path;
    const child = spawn(descriptorExecutionPath, [], {
      stdio: process.platform === "win32"
        ? ["pipe", "pipe", "pipe"] as const
        : ["pipe", "pipe", "pipe", runtime.file.fd] as const,
      windowsHide: true,
      env: { LANG: "C", LC_ALL: "C" },
    });
    await runtime.file.close();
    if (!hasProtocolPipes(child)) {
      child.kill("SIGKILL");
      await withDeadline(waitForExit(child), 2_000, "runtime pipe cleanup deadline exceeded").catch(() => undefined);
      await runtime.cleanup?.();
      throw new Error("runtime protocol pipes were not created");
    }
    const client = new RuntimeClient(child, runtime.cleanup);
    const hello = new Promise<void>((resolveHello, rejectHello) => {
      client.#helloResolve = resolveHello;
      client.#helloReject = rejectHello;
    });
    await client.#sendControl(MessageType.Hello, {
      protocolMajor: PROTOCOL_MAJOR,
      protocolMinor: PROTOCOL_MINOR,
      packageVersion: "0.1.0",
    });
    try {
      await withDeadline(hello, 5_000, "runtime HELLO deadline exceeded");
    } catch (error) {
      child.kill("SIGKILL");
      await withDeadline(waitForExit(child), 2_000, "runtime HELLO cleanup deadline exceeded").catch(() => undefined);
      await client.#cleanupRuntimeSnapshot();
      throw error;
    }
    return client;
  }

  request(messageType: MessageType, expected: MessageType | readonly MessageType[], body: JsonObject = {}): Promise<unknown> {
    if (this.#closed) return Promise.reject(this.#crashedError("runtime is closed"));
    if (messageType === MessageType.StartPreparedRun || messageType === MessageType.StartPreparedProcess) {
      if (this.#processLifecycle === "starting" || this.#processLifecycle === "running") {
        return Promise.reject(new FrameDecodeError("a process is already starting or running"));
      }
      this.#processLifecycle = "starting";
      this.#stdinCredit = 0;
      this.#pendingOutput = [];
      this.#pendingArtifacts = [];
      this.#pendingEvents = [];
      this.#pendingExit = undefined;
    }
    const requestId = `node-${this.#requestSequence++}`;
    const expectedTypes = typeof expected === "number" ? [expected] : expected;
    return new Promise<unknown>((resolveRequest, rejectRequest) => {
      this.#pending.set(requestId, { expected: expectedTypes, resolve: resolveRequest, reject: rejectRequest });
      void this.#sendControl(messageType, { ...body, requestId }).catch((error: unknown) => {
        this.#pending.delete(requestId);
        if (expectedTypes.includes(MessageType.ProcessStarted)) this.#processLifecycle = "idle";
        rejectRequest(error instanceof Error ? error : new Error("protocol write failed"));
      });
    });
  }

  async probe(request: JsonObject = {}): Promise<RuntimeSupport> {
    const response = object(await this.request(MessageType.Probe, MessageType.ProbeResult, { request }), "probe response");
    return parseSupport(response.support);
  }

  attachProcess(hooks: ActiveProcessHooks): void {
    if (this.#active !== undefined) throw new Error("runtime already has an attached process");
    this.#active = hooks;
    for (const output of this.#pendingOutput) hooks.output(output.stream, output.chunk);
    this.#pendingOutput = [];
    for (const chunk of this.#pendingArtifacts) hooks.artifact(chunk);
    this.#pendingArtifacts = [];
    for (const event of this.#pendingEvents) hooks.event(event);
    this.#pendingEvents = [];
    if (this.#pendingExit !== undefined) {
      const exit = this.#pendingExit;
      this.#pendingExit = undefined;
      hooks.exit(exit);
    }
  }

  watchPreparationExpiration(id: string, runtimeExits: boolean, callback: () => void): void {
    this.#expirationHandlers.set(id, { runtimeExits, callback });
  }

  unwatchPreparationExpiration(id: string): void {
    this.#expirationHandlers.delete(id);
  }

  detachProcess(hooks: ActiveProcessHooks): void {
    if (this.#active === hooks) this.#active = undefined;
  }

  async sendStdin(bytes: Buffer): Promise<void> {
    let offset = 0;
    while (offset < bytes.byteLength) {
      await this.#waitForStdinCredit();
      const count = Math.min(bytes.byteLength - offset, MAX_STREAM_PAYLOAD, this.#stdinCredit);
      this.#stdinCredit -= count;
      await this.#sendBinary(MessageType.Stdin, bytes.subarray(offset, offset + count));
      offset += count;
    }
  }

  grantOutput(stream: "stdout" | "stderr", bytes: number): void {
    if (bytes > 0) {
      void this.#sendControl(MessageType.StreamCredit, { stream, bytes }).catch((error: unknown) => {
        this.#crash(error instanceof Error ? error : new Error("credit write failed"));
      });
    }
  }

  shutdown(): Promise<void> {
    this.#shutdownPromise ??= this.#performShutdown();
    return this.#shutdownPromise;
  }

  async #performShutdown(): Promise<void> {
    if (this.#closed) {
      if (this.#child.exitCode === null && this.#child.signalCode === null) {
        this.#child.kill("SIGKILL");
        await withDeadline(
          waitForExit(this.#child),
          2_000,
          "crashed runtime forced-exit deadline exceeded",
        ).catch(() => undefined);
      }
      await this.#cleanupRuntimeSnapshot();
      return;
    }
    this.#shuttingDown = true;
    try {
      await withDeadline(
        this.request(MessageType.Shutdown, MessageType.RuntimeMetrics),
        2_000,
        "runtime shutdown acknowledgement deadline exceeded",
      );
    } catch {
      // Cleanup remains idempotent even after a runtime-side failure.
    }
    this.#closed = true;
    this.#child.stdin.end();
    if (this.#child.exitCode === null && this.#child.signalCode === null) {
      try {
        await withDeadline(waitForExit(this.#child), 2_000, "runtime exit deadline exceeded");
      } catch {
        this.#child.kill("SIGKILL");
        await withDeadline(waitForExit(this.#child), 2_000, "runtime forced-exit deadline exceeded").catch(() => undefined);
      }
    }
    if (this.#active !== undefined) {
      const error = this.#crashedError("runtime shut down before the active process produced a final result");
      this.#rejectAll(error);
      this.#active.fail(error);
    }
    await this.#cleanupRuntimeSnapshot();
  }

  #cleanupRuntimeSnapshot(): Promise<void> {
    this.#runtimeCleanupPromise ??= this.#runtimeCleanup?.() ?? Promise.resolve();
    return this.#runtimeCleanupPromise;
  }

  #receive(chunk: Buffer): void {
    try {
      for (const frame of this.#decoder.push(chunk)) this.#dispatch(frame);
    } catch (error) {
      this.#crash(error instanceof Error ? error : new FrameDecodeError("protocol decode failed"));
    }
  }

  #dispatch(frame: ProtocolFrame): void {
    if (frame.messageType === MessageType.Stdout || frame.messageType === MessageType.Stderr) {
      if (this.#processLifecycle !== "running") throw new FrameDecodeError("process output is out of lifecycle order");
      const stream = frame.messageType === MessageType.Stdout ? "stdout" : "stderr";
      if (this.#active === undefined) {
        const buffered = this.#pendingOutput.reduce((total, item) => total + item.chunk.byteLength, 0);
        if (buffered + frame.payload.byteLength > 2 * 1024 * 1024) throw new FrameDecodeError("pre-attachment output queue exceeded its bound");
        this.#pendingOutput.push({ stream, chunk: frame.payload });
      } else {
        this.#active.output(stream, frame.payload);
      }
      return;
    }
    if (frame.messageType === MessageType.Artifact) {
      if (this.#processLifecycle !== "running") throw new FrameDecodeError("artifact output is out of lifecycle order");
      if (this.#active === undefined) {
        const buffered = this.#pendingArtifacts.reduce((total, chunk) => total + chunk.byteLength, 0);
        if (buffered + frame.payload.byteLength > 128 * 1024 * 1024) {
          throw new FrameDecodeError("pre-attachment artifact and change-set queue exceeded its bound");
        }
        this.#pendingArtifacts.push(frame.payload);
      } else {
        this.#active.artifact(frame.payload);
      }
      return;
    }
    const value = decodeControl(frame);
    const source = object(value, "protocol control message");
    if (frame.messageType === MessageType.HelloAck) {
      if (this.#helloReceived || this.#helloResolve === undefined) throw new FrameDecodeError("duplicate or unsolicited HELLO_ACK");
      const major = number(source.protocolMajor, "HELLO_ACK protocolMajor");
      if (major !== PROTOCOL_MAJOR) throw new FrameDecodeError("runtime protocol major mismatch");
      this.#helloReceived = true;
      this.#helloResolve?.();
      this.#helloResolve = undefined;
      this.#helloReject = undefined;
      return;
    }
    if (frame.messageType === MessageType.Error) {
      const error = errorFromData(parseErrorData(source.error));
      if (typeof source.requestId === "string") {
        const pending = this.#pending.get(source.requestId);
        if (pending === undefined) throw new FrameDecodeError("error response has no matching request");
        this.#pending.delete(source.requestId);
        if (pending?.expected.includes(MessageType.ProcessStarted) === true) this.#processLifecycle = "idle";
        pending?.reject(error);
      } else {
        this.#rejectAll(error);
        this.#active?.fail(error);
      }
      return;
    }
    if (frame.messageType === MessageType.ProcessExit) {
      if (this.#processLifecycle !== "running") throw new FrameDecodeError("process exit is out of lifecycle order");
      this.#processLifecycle = "exited";
      if (this.#active === undefined) this.#pendingExit = value;
      else this.#active.exit(value);
      return;
    }
    if (frame.messageType === MessageType.StreamCredit) {
      if (this.#processLifecycle !== "running") throw new FrameDecodeError("stream credit is out of lifecycle order");
      if (string(source.stream, "credit.stream") === "stdin") {
        const bytes = number(source.bytes, "credit.bytes");
        if (bytes === 0 || this.#stdinCredit + bytes > 16 * 1024 * 1024) throw new FrameDecodeError("stdin credit overflow");
        this.#stdinCredit += bytes;
        for (const waiter of this.#stdinWaiters.splice(0)) waiter();
      }
      return;
    }
    if (frame.messageType === MessageType.Event && typeof source.requestId !== "string") {
      if (string(source.kind, "runtime event kind") === "preparation-expired") {
        const id = string(source.id, "expired preparation id");
        const handler = this.#expirationHandlers.get(id);
        if (handler !== undefined) {
          this.#expirationHandlers.delete(id);
          this.#expirationExitExpected ||= handler.runtimeExits;
          handler.callback();
        }
        const error = new SandboxPreparationExpiredError({
          code: "preparation_expired.runtime",
          message: "prepared authority expired",
          phase: "activate",
          targetExecuted: false,
        });
        this.#rejectAll(error);
        return;
      }
      if (this.#processLifecycle !== "running") throw new FrameDecodeError("process event is out of lifecycle order");
      if (this.#active === undefined) {
        if (this.#pendingEvents.length >= 1024) throw new FrameDecodeError("pre-attachment event queue exceeded its bound");
        this.#pendingEvents.push(value);
      } else {
        this.#active.event(value);
      }
      return;
    }
    const requestId = string(source.requestId, "response.requestId");
    const pending = this.#pending.get(requestId);
    if (pending === undefined) throw new FrameDecodeError("response has no matching request");
    if (!pending.expected.includes(frame.messageType)) throw new FrameDecodeError("response is out of lifecycle order");
    if (frame.messageType === MessageType.ProcessStarted) {
      if (this.#processLifecycle !== "starting") throw new FrameDecodeError("process start is out of lifecycle order");
      this.#processLifecycle = "running";
    }
    this.#pending.delete(requestId);
    pending.resolve(value);
  }

  #sendControl(messageType: MessageType, value: unknown): Promise<void> {
    return this.#enqueueWrite(encodeControlFrame(messageType, value));
  }

  #sendBinary(messageType: MessageType, value: Buffer): Promise<void> {
    return this.#enqueueWrite(encodeBinaryFrame(messageType, value));
  }

  #enqueueWrite(frame: Buffer): Promise<void> {
    const write = this.#writeChain.then(
      () => new Promise<void>((resolveWrite, rejectWrite) => {
        this.#child.stdin.write(frame, (error) => {
          if (error === null || error === undefined) resolveWrite();
          else rejectWrite(error);
        });
      }),
    );
    this.#writeChain = write.catch(() => undefined);
    return write;
  }

  #waitForStdinCredit(): Promise<void> {
    if (this.#stdinCredit > 0) return Promise.resolve();
    if (this.#closed) return Promise.reject(this.#crashedError("runtime closed while writing stdin"));
    return new Promise((resolveCredit) => this.#stdinWaiters.push(resolveCredit));
  }

  #receiveEmergency(chunk: Buffer): void {
    if (this.#stderrBytes >= this.#stderrLimit) return;
    const accepted = chunk.subarray(0, this.#stderrLimit - this.#stderrBytes);
    this.#stderr.push(Buffer.from(accepted));
    this.#stderrBytes += accepted.byteLength;
  }

  #emergencyText(): string {
    return Buffer.concat(this.#stderr).toString("utf8").replaceAll(/[\u0000-\u001f]+/gu, " ").slice(0, this.#stderrLimit);
  }

  #crash(cause: Error): void {
    if (this.#closed) return;
    this.#closed = true;
    const error = this.#crashedError(cause.message);
    this.#helloReject?.(error);
    this.#helloResolve = undefined;
    this.#helloReject = undefined;
    this.#rejectAll(error);
    this.#active?.fail(error);
    for (const waiter of this.#stdinWaiters.splice(0)) waiter();
    if (this.#child.exitCode === null && this.#child.signalCode === null) this.#child.kill("SIGKILL");
  }

  #rejectAll(error: Error): void {
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear();
  }

  #crashedError(message: string): SandboxRuntimeCrashedError {
    return new SandboxRuntimeCrashedError({
      code: "runtime_crashed.process",
      message: message.slice(0, 4096),
      phase: "execute",
      targetExecuted: this.#active !== undefined || this.#processLifecycle === "running" || this.#processLifecycle === "exited",
      platform: process.platform,
    });
  }
}

function parseSupport(value: unknown): RuntimeSupport {
  const source = object(value, "support");
  const protocol = object(source.protocol, "support.protocol");
  const host = object(source.host, "support.host");
  return {
    protocol: {
      major: number(protocol.major, "support.protocol.major"),
      minor: number(protocol.minor, "support.protocol.minor"),
    },
    packageVersion: string(source.packageVersion, "support.packageVersion"),
    host: {
      platform: string(host.platform, "support.host.platform"),
      architecture: string(host.architecture, "support.host.architecture"),
    },
    backends: array(source.backends, "support.backends").map((entry) => {
      const backend = object(entry, "support backend");
      const stability = string(backend.stability, "backend.stability");
      if (stability !== "stable" && stability !== "experimental") throw new TypeError("invalid backend stability");
      return {
        id: string(backend.id, "backend.id"),
        isolation: string(backend.isolation, "backend.isolation"),
        stability,
        available: boolean(backend.available, "backend.available"),
        capabilities: object(backend.capabilities, "backend.capabilities"),
      };
    }),
  };
}

class AsyncEventQueue implements AsyncIterable<SandboxEvent> {
  readonly #values: SandboxEvent[] = [];
  readonly #waiters: ((result: IteratorResult<SandboxEvent>) => void)[] = [];
  #ended = false;

  push(value: SandboxEvent): void {
    const waiter = this.#waiters.shift();
    if (waiter === undefined) this.#values.push(value);
    else waiter({ done: false, value });
  }

  end(): void {
    this.#ended = true;
    for (const waiter of this.#waiters.splice(0)) waiter({ done: true, value: undefined });
  }

  [Symbol.asyncIterator](): AsyncIterator<SandboxEvent> {
    return {
      next: () => {
        const value = this.#values.shift();
        if (value !== undefined) return Promise.resolve({ done: false, value });
        if (this.#ended) return Promise.resolve({ done: true, value: undefined });
        return new Promise((resolveNext) => this.#waiters.push(resolveNext));
      },
    };
  }
}

class RuntimeStdin extends Writable {
  readonly #client: RuntimeClient;
  readonly #processId: string;

  constructor(client: RuntimeClient, processId: string) {
    super({ highWaterMark: 64 * 1024 });
    this.#client = client;
    this.#processId = processId;
  }

  override _write(
    chunk: Buffer | Uint8Array | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const bytes = typeof chunk === "string" ? Buffer.from(chunk, encoding) : Buffer.from(chunk);
    void this.#client.sendStdin(bytes).then(() => callback(), callback);
  }

  override _final(callback: (error?: Error | null) => void): void {
    void this.#client
      .request(MessageType.CloseStdin, MessageType.Event, { id: this.#processId })
      .then(() => callback(), callback);
  }
}

export interface RuntimeProcessOptions {
  id: string;
  identity: SandboxProcessIdentity;
  policyDigest: string;
  executionDigest: string;
  enforcement: EnforcementReport;
  stdinMode: "pipe" | "closed";
  stdoutMode: "pipe" | "capture" | "discard";
  stderrMode: "pipe" | "capture" | "discard";
  closeRuntimeAfterWait: boolean;
  signal?: AbortSignal;
  finished?(): void;
}

export class RuntimeProcess implements SandboxProcess, ActiveProcessHooks {
  readonly id: string;
  readonly identity: SandboxProcessIdentity;
  readonly stdin: Writable | null;
  readonly stdout: PassThrough | null;
  readonly stderr: PassThrough | null;
  readonly #client: RuntimeClient;
  readonly #options: RuntimeProcessOptions;
  readonly #events = new AsyncEventQueue();
  readonly #stdoutCapture: Buffer[] = [];
  readonly #stderrCapture: Buffer[] = [];
  readonly #artifactCapture: Buffer[] = [];
  readonly #waitPromise: Promise<SandboxRunResult>;
  #resolveWait: ((result: SandboxRunResult) => void) | undefined;
  #rejectWait: ((error: Error) => void) | undefined;
  #completed = false;
  #abortListener: (() => void) | undefined;
  #stdoutWithheldCredit = 0;
  #stderrWithheldCredit = 0;
  #stdoutDrainPending = false;
  #stderrDrainPending = false;

  constructor(client: RuntimeClient, options: RuntimeProcessOptions) {
    this.#client = client;
    this.#options = options;
    this.id = options.id;
    this.identity = options.identity;
    this.stdin = options.stdinMode === "pipe" ? new RuntimeStdin(client, options.id) : null;
    this.stdout = options.stdoutMode === "pipe" ? new PassThrough({ highWaterMark: 64 * 1024 }) : null;
    this.stderr = options.stderrMode === "pipe" ? new PassThrough({ highWaterMark: 64 * 1024 }) : null;
    this.#waitPromise = new Promise((resolveWait, rejectWait) => {
      this.#resolveWait = resolveWait;
      this.#rejectWait = rejectWait;
    });
    client.attachProcess(this);
    if (options.signal !== undefined) {
      this.#abortListener = () => void this.terminate("cancelled");
      if (options.signal.aborted) this.#abortListener();
      else options.signal.addEventListener("abort", this.#abortListener, { once: true });
    }
  }

  events(): AsyncIterable<SandboxEvent> {
    return this.#events;
  }

  wait(): Promise<SandboxRunResult> {
    return this.#waitPromise;
  }

  async terminate(reason: "cancelled" | "timeout" | "caller-request" = "caller-request"): Promise<void> {
    if (this.#completed) return;
    this.#events.push({ kind: "termination-started", reason });
    await this.#client.request(MessageType.Terminate, MessageType.Event, { id: this.id, reason });
  }

  output(stream: "stdout" | "stderr", chunk: Buffer): void {
    const mode = stream === "stdout" ? this.#options.stdoutMode : this.#options.stderrMode;
    if (mode === "capture") {
      (stream === "stdout" ? this.#stdoutCapture : this.#stderrCapture).push(Buffer.from(chunk));
      this.#client.grantOutput(stream, chunk.byteLength);
      return;
    }
    const destination = stream === "stdout" ? this.stdout : this.stderr;
    if (destination === null) {
      this.#client.grantOutput(stream, chunk.byteLength);
      return;
    }
    if (destination.write(chunk)) {
      this.#client.grantOutput(stream, chunk.byteLength);
    } else {
      if (stream === "stdout") {
        this.#stdoutWithheldCredit += chunk.byteLength;
        if (!this.#stdoutDrainPending) {
          this.#stdoutDrainPending = true;
          destination.once("drain", () => {
            const bytes = this.#stdoutWithheldCredit;
            this.#stdoutWithheldCredit = 0;
            this.#stdoutDrainPending = false;
            this.#client.grantOutput("stdout", bytes);
          });
        }
      } else {
        this.#stderrWithheldCredit += chunk.byteLength;
        if (!this.#stderrDrainPending) {
          this.#stderrDrainPending = true;
          destination.once("drain", () => {
            const bytes = this.#stderrWithheldCredit;
            this.#stderrWithheldCredit = 0;
            this.#stderrDrainPending = false;
            this.#client.grantOutput("stderr", bytes);
          });
        }
      }
    }
  }

  artifact(chunk: Buffer): void {
    const captured = this.#artifactCapture.reduce((total, value) => total + value.byteLength, 0);
    if (captured + chunk.byteLength > 128 * 1024 * 1024) {
      throw new FrameDecodeError("artifact and change-set stream exceeded its bound");
    }
    this.#artifactCapture.push(Buffer.from(chunk));
  }

  exit(value: unknown): void {
    if (this.#completed) return;
    try {
      const result = parseRunResult(value, Buffer.concat(this.#artifactCapture));
      if (
        result.processId !== this.id
        || result.policyDigest !== this.#options.policyDigest
        || result.executionDigest !== this.#options.executionDigest
      ) {
        throw new FrameDecodeError("process result identity does not match the prepared execution");
      }
      if (this.#options.stdoutMode === "capture") result.stdout = Buffer.concat(this.#stdoutCapture);
      if (this.#options.stderrMode === "capture") result.stderr = Buffer.concat(this.#stderrCapture);
      this.#finish(!this.#options.closeRuntimeAfterWait);
      if (this.#options.closeRuntimeAfterWait) {
        void this.#client.shutdown().then(
          () => {
            this.#options.finished?.();
            this.#resolveWait?.(result);
          },
          (error: unknown) => {
            this.#options.finished?.();
            this.#rejectWait?.(error instanceof Error ? error : new Error("runtime shutdown failed"));
          },
        );
      } else {
        this.#resolveWait?.(result);
      }
    } catch (error) {
      this.#finish();
      this.#rejectWait?.(error instanceof Error ? error : new Error("invalid process result"));
    }
  }

  event(value: unknown): void {
    const source = object(value, "runtime event");
    const kind = string(source.kind, "runtime event kind");
    if (kind === "termination-started") {
      this.#events.push({ kind, reason: string(source.reason, "termination reason") });
    } else if (kind === "violation") {
      const violation = parseViolation(source.violation);
      if (violation.processId !== this.id) throw new FrameDecodeError("violation process identity mismatch");
      this.#events.push({ kind, violation });
    } else if (kind === "cleanup-warning") {
      this.#events.push({ kind, code: string(source.code, "cleanup warning code"), message: string(source.message, "cleanup warning message") });
    }
  }

  fail(error: SandboxError): void {
    if (this.#completed) return;
    this.#finish();
    this.#rejectWait?.(error);
  }

  #finish(release = true): void {
    this.#completed = true;
    this.stdout?.end();
    this.stderr?.end();
    this.stdin?.destroy();
    this.#events.end();
    if (this.#options.signal !== undefined && this.#abortListener !== undefined) {
      this.#options.signal.removeEventListener("abort", this.#abortListener);
    }
    this.#client.detachProcess(this);
    if (release) this.#options.finished?.();
  }
}

export function parseProcessStarted(value: unknown): { id: string; identity: SandboxProcessIdentity } {
  const source = object(value, "process started");
  const identity = object(source.identity, "process identity");
  const kind = string(identity.kind, "process identity kind");
  if (kind === "host-process") return { id: string(source.id, "process id"), identity: { kind, pid: number(identity.pid, "process pid") } };
  if (kind === "guest-process") return { id: string(source.id, "process id"), identity: { kind, pid: number(identity.pid, "process pid") } };
  if (kind === "opaque") return { id: string(source.id, "process id"), identity: { kind } };
  throw new TypeError("invalid process identity kind");
}

export function protocolError(cause: unknown): SandboxProtocolError {
  return new SandboxProtocolError({
    code: "protocol.client",
    message: cause instanceof Error ? cause.message.slice(0, 4096) : "invalid runtime protocol data",
    phase: "execute",
    targetExecuted: false,
    platform: process.platform,
  });
}

function withDeadline<T>(promise: Promise<T>, milliseconds: number, message: string): Promise<T> {
  return new Promise<T>((resolveDeadline, rejectDeadline) => {
    const timeout = setTimeout(() => rejectDeadline(new Error(message)), milliseconds);
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolveDeadline(value);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        rejectDeadline(error);
      },
    );
  });
}

function waitForExit(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise<void>((resolveExit) => child.once("exit", () => resolveExit()));
}

function hasProtocolPipes(child: ChildProcess): child is ChildProcessWithoutNullStreams {
  return child.stdin !== null && child.stdout !== null && child.stderr !== null;
}
