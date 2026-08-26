import {
  verifyExtension,
  type SandboxExtensionRegistration,
  type SandboxImageReference,
  type VerifiedSandboxExtension,
} from "./extension.js";
import type { EnforcementReport } from "./enforcement.js";
import {
  SandboxCleanupError,
  SandboxPreparationError,
  SandboxPreparationExpiredError,
  SandboxUnsupportedError,
} from "./errors.js";
import type { SandboxPolicy } from "./policy.js";
import type { PreparedSandboxRun } from "./prepared-run.js";
import type {
  PreparedSandboxProcess,
  PreparedSandboxSession,
} from "./prepared-session.js";
import type { SandboxProcess } from "./process.js";
import type { SandboxProcessOptions } from "./process-options.js";
import type { EnforcementRequirements } from "./requirements.js";
import type { ResourceLimits } from "./resources.js";
import type { SandboxRunResult } from "./result.js";
import {
  RuntimeClient,
  RuntimeLocator,
  RuntimeProcess,
  parseProcessStarted,
  protocolError,
  type RuntimeSupport,
} from "./runtime.js";
import type { SandboxSession } from "./session.js";
import type {
  PreparedProcessSummary,
  PreparedRunSummary,
  PreparedSessionSummary,
} from "./summary.js";
import { MessageType } from "./protocol.js";
import {
  digest,
  number,
  object,
  parseEnforcement,
  parseCleanup,
  parseProcessSummary,
  parseRunSummary,
  parseSessionSummary,
  string,
  type JsonObject,
} from "./validation.js";

export type SandboxIsolation =
  | { kind: "process" }
  | {
      kind: "hardware-vm";
      image: SandboxImageReference;
      filesystemTransport: "ephemeral" | "import";
    };

export interface CreateSandboxOptions {
  allowExperimentalBackends?: boolean;
  extensions?: readonly SandboxExtensionRegistration[];
}

export interface SandboxSessionOptions {
  isolation: SandboxIsolation;
  policy: SandboxPolicy;
  requirements: EnforcementRequirements;
  resources?: Partial<ResourceLimits>;
  preparedTtlMs?: number;
  signal?: AbortSignal;
}

export interface SandboxRunOptions extends SandboxSessionOptions {
  process: SandboxProcessOptions;
}

export interface SandboxProbeRequest {
  isolation?: SandboxIsolation["kind"];
  required?: readonly string[];
}

export type SandboxSupport = RuntimeSupport;

export interface Sandbox {
  probe(request?: SandboxProbeRequest): Promise<SandboxSupport>;
  prepareRun(options: SandboxRunOptions): Promise<PreparedSandboxRun>;
  prepareSession(options: SandboxSessionOptions): Promise<PreparedSandboxSession>;
  run(options: SandboxRunOptions): Promise<SandboxRunResult>;
  dispose(): Promise<void>;
}

export async function createSandbox(options: CreateSandboxOptions = {}): Promise<Sandbox> {
  const extensions = new Map<"hardware-vm", VerifiedSandboxExtension>();
  for (const registration of options.extensions ?? []) {
    if (extensions.has(registration.kind)) {
      throw new SandboxPreparationError({
        code: "preparation.duplicate_extension",
        message: `extension ${registration.kind} was registered more than once`,
        phase: "validate",
        targetExecuted: false,
      });
    }
    extensions.set(registration.kind, await verifyExtension(registration));
  }
  return new SandboxImplementation(options.allowExperimentalBackends ?? false, extensions);
}

class SandboxImplementation implements Sandbox {
  readonly #allowExperimentalBackends: boolean;
  readonly #extensions: ReadonlyMap<"hardware-vm", VerifiedSandboxExtension>;
  readonly #clients = new Set<RuntimeClient>();
  #disposed = false;

  constructor(
    allowExperimentalBackends: boolean,
    extensions: ReadonlyMap<"hardware-vm", VerifiedSandboxExtension>,
  ) {
    this.#allowExperimentalBackends = allowExperimentalBackends;
    this.#extensions = extensions;
  }

  async probe(request: SandboxProbeRequest = {}): Promise<SandboxSupport> {
    this.#ensureOpen();
    const client = await this.#client(request.isolation ?? "process");
    try {
      return await client.probe({
        isolation: request.isolation ?? "process",
        required: request.required ?? [],
        allowExperimentalBackends: this.#allowExperimentalBackends,
      });
    } finally {
      await client.shutdown();
      this.#clients.delete(client);
    }
  }

  async prepareRun(options: SandboxRunOptions): Promise<PreparedSandboxRun> {
    this.#ensureOpen();
    this.#validateIsolation(options.isolation);
    throwIfAborted(options.signal, "run preparation was cancelled");
    const client = await this.#client(options.isolation.kind);
    try {
      const response = object(
        await raceAbort(
          client.request(MessageType.PrepareRun, MessageType.RunPrepared, {
            options: serializeRunOptions(options, this.#allowExperimentalBackends),
          }),
          options.signal,
          () => client.shutdown(),
        ),
        "prepared run",
      );
      const prepared = new PreparedRunImplementation(
        this,
        client,
        string(response.id, "prepared run id"),
        digest(response.policyDigest, "prepared policy digest"),
        digest(response.executionDigest, "prepared execution digest"),
        parseRunSummary(response.summary),
        parseEnforcement(response.enforcement),
        number(response.expiresAtMs, "prepared expiration"),
      );
      if (options.signal !== undefined) prepared.bindAbort(options.signal);
      return prepared;
    } catch (error) {
      await client.shutdown();
      this.#clients.delete(client);
      throw normalizeProtocolError(error);
    }
  }

  async prepareSession(options: SandboxSessionOptions): Promise<PreparedSandboxSession> {
    this.#ensureOpen();
    this.#validateIsolation(options.isolation);
    throwIfAborted(options.signal, "session preparation was cancelled");
    const client = await this.#client(options.isolation.kind);
    try {
      const response = object(
        await raceAbort(
          client.request(MessageType.PrepareSession, MessageType.SessionPrepared, {
            options: serializeSessionOptions(options, this.#allowExperimentalBackends),
          }),
          options.signal,
          () => client.shutdown(),
        ),
        "prepared session",
      );
      const prepared = new PreparedSessionImplementation(
        this,
        client,
        string(response.id, "prepared session id"),
        digest(response.policyDigest, "prepared policy digest"),
        parseSessionSummary(response.summary),
        parseEnforcement(response.enforcement),
        number(response.expiresAtMs, "prepared expiration"),
      );
      if (options.signal !== undefined) prepared.bindAbort(options.signal);
      return prepared;
    } catch (error) {
      await client.shutdown();
      this.#clients.delete(client);
      throw normalizeProtocolError(error);
    }
  }

  async run(options: SandboxRunOptions): Promise<SandboxRunResult> {
    const prepared = await this.prepareRun(options);
    const target = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
      ...(options.process.signal === undefined ? {} : { signal: options.process.signal }),
    });
    return target.wait();
  }

  async dispose(): Promise<void> {
    if (this.#disposed) return;
    this.#disposed = true;
    const clients = [...this.#clients];
    this.#clients.clear();
    await Promise.allSettled(clients.map((client) => client.shutdown()));
  }

  release(client: RuntimeClient): void {
    this.#clients.delete(client);
  }

  async #client(isolation: SandboxIsolation["kind"]): Promise<RuntimeClient> {
    const extension = isolation === "hardware-vm" ? this.#extensions.get("hardware-vm") : undefined;
    if (isolation === "hardware-vm" && extension === undefined) {
      throw new SandboxUnsupportedError({
        code: "unsupported.isolation",
        message: "hardware-vm isolation requires an explicitly registered extension",
        phase: "probe",
        targetExecuted: false,
        platform: process.platform,
      });
    }
    const client = await RuntimeClient.launch(new RuntimeLocator(extension));
    if (this.#disposed) {
      await client.shutdown();
      throw new SandboxPreparationError({
        code: "preparation.disposed",
        message: "sandbox was disposed while starting its runtime",
        phase: "prepare",
        targetExecuted: false,
      });
    }
    this.#clients.add(client);
    return client;
  }

  #validateIsolation(isolation: SandboxIsolation): void {
    if (isolation.kind !== "hardware-vm") return;
    const extension = this.#extensions.get("hardware-vm");
    if (extension === undefined) return;
    if (isolation.image.trust === "explicit-local" && !extension.explicitLocalImages) {
      throw new SandboxUnsupportedError({
        code: "unsupported.explicit_local_image",
        message: "the registered hardware-VM extension does not accept explicit-local images",
        phase: "validate",
        targetExecuted: false,
      });
    }
    if (isolation.image.trust === "bundled") {
      const digestValue = isolation.image.digest;
      if (digestValue === undefined || !extension.bundledImageManifestDigests.includes(digestValue)) {
        throw new SandboxUnsupportedError({
          code: "unsupported.bundled_image",
          message: "the requested bundled image is not in the extension trust manifest",
          phase: "validate",
          targetExecuted: false,
        });
      }
    }
  }

  #ensureOpen(): void {
    if (this.#disposed) {
      throw new SandboxPreparationError({
        code: "preparation.disposed",
        message: "sandbox is disposed",
        phase: "prepare",
        targetExecuted: false,
      });
    }
  }
}

class PreparedRunImplementation implements PreparedSandboxRun {
  #consumed = false;
  #expired = false;
  #abortSignal: AbortSignal | undefined;
  #abortListener: (() => void) | undefined;

  constructor(
    readonly owner: SandboxImplementation,
    readonly client: RuntimeClient,
    readonly id: string,
    readonly policyDigest: string,
    readonly executionDigest: string,
    readonly summary: PreparedRunSummary,
    readonly enforcement: EnforcementReport,
    readonly expiresAtMs: number,
  ) {
    client.watchPreparationExpiration(id, true, () => {
      this.#expired = true;
    });
  }

  bindAbort(signal: AbortSignal): void {
    this.#abortSignal = signal;
    this.#abortListener = () => void this.cancel();
    signal.addEventListener("abort", this.#abortListener, { once: true });
  }

  async start(expected: { policyDigest: string; executionDigest: string; signal?: AbortSignal }): Promise<SandboxProcess> {
    if (this.#consumed) throw consumedError("prepared run");
    if (this.#expired || Date.now() >= this.expiresAtMs) {
      this.#consumed = true;
      this.#unbindAbort();
      this.client.unwatchPreparationExpiration(this.id);
      await this.client.shutdown();
      this.owner.release(this.client);
      throw expiredError("prepared run");
    }
    this.#consumed = true;
    this.client.unwatchPreparationExpiration(this.id);
    this.#unbindAbort();
    try {
      const response = await this.client.request(MessageType.StartPreparedRun, MessageType.ProcessStarted, {
        id: this.id,
        policyDigest: expected.policyDigest,
        executionDigest: expected.executionDigest,
      });
      const started = parseProcessStarted(response);
      return new RuntimeProcess(this.client, {
        id: started.id,
        identity: started.identity,
        policyDigest: this.policyDigest,
        executionDigest: this.executionDigest,
        enforcement: this.enforcement,
        stdinMode: this.summary.execution.stdin,
        stdoutMode: this.summary.execution.stdout,
        stderrMode: this.summary.execution.stderr,
        closeRuntimeAfterWait: true,
        ...(expected.signal === undefined ? {} : { signal: expected.signal }),
        finished: () => this.owner.release(this.client),
      });
    } catch (error) {
      await this.client.shutdown();
      this.owner.release(this.client);
      throw normalizeProtocolError(error);
    }
  }

  async cancel(): Promise<void> {
    if (this.#consumed) return;
    this.#consumed = true;
    this.client.unwatchPreparationExpiration(this.id);
    this.#unbindAbort();
    try {
      await this.client.request(MessageType.CancelPreparedRun, MessageType.Event, { id: this.id });
    } finally {
      await this.client.shutdown();
      this.owner.release(this.client);
    }
  }

  #unbindAbort(): void {
    if (this.#abortSignal !== undefined && this.#abortListener !== undefined) {
      this.#abortSignal.removeEventListener("abort", this.#abortListener);
    }
  }
}

class PreparedSessionImplementation implements PreparedSandboxSession {
  #consumed = false;
  #expired = false;
  #abortSignal: AbortSignal | undefined;
  #abortListener: (() => void) | undefined;

  constructor(
    readonly owner: SandboxImplementation,
    readonly client: RuntimeClient,
    readonly id: string,
    readonly policyDigest: string,
    readonly summary: PreparedSessionSummary,
    readonly enforcement: EnforcementReport,
    readonly expiresAtMs: number,
  ) {
    client.watchPreparationExpiration(id, true, () => {
      this.#expired = true;
    });
  }

  bindAbort(signal: AbortSignal): void {
    this.#abortSignal = signal;
    this.#abortListener = () => void this.cancel();
    signal.addEventListener("abort", this.#abortListener, { once: true });
  }

  async activate(expected: { policyDigest: string; signal?: AbortSignal }): Promise<SandboxSession> {
    if (this.#consumed) throw consumedError("prepared session");
    if (this.#expired || Date.now() >= this.expiresAtMs) {
      this.#consumed = true;
      this.#unbindAbort();
      this.client.unwatchPreparationExpiration(this.id);
      await this.client.shutdown();
      this.owner.release(this.client);
      throw expiredError("prepared session");
    }
    this.#consumed = true;
    this.client.unwatchPreparationExpiration(this.id);
    this.#unbindAbort();
    try {
      const response = object(await this.client.request(MessageType.ActivateSession, MessageType.SessionActive, {
        id: this.id,
        policyDigest: expected.policyDigest,
      }), "active session");
      const id = string(response.id, "active session id");
      const policyDigest = digest(response.policyDigest, "active policy digest");
      const enforcement = parseEnforcement(response.enforcement);
      const session = new SessionImplementation(this.owner, this.client, id, policyDigest, enforcement);
      if (expected.signal !== undefined) session.bindAbort(expected.signal);
      return session;
    } catch (error) {
      await this.client.shutdown();
      this.owner.release(this.client);
      throw normalizeProtocolError(error);
    }
  }

  async cancel(): Promise<void> {
    if (this.#consumed) return;
    this.#consumed = true;
    this.client.unwatchPreparationExpiration(this.id);
    this.#unbindAbort();
    try {
      await this.client.request(MessageType.CancelPreparedSession, MessageType.Event, { id: this.id });
    } finally {
      await this.client.shutdown();
      this.owner.release(this.client);
    }
  }

  #unbindAbort(): void {
    if (this.#abortSignal !== undefined && this.#abortListener !== undefined) {
      this.#abortSignal.removeEventListener("abort", this.#abortListener);
    }
  }
}

class SessionImplementation implements SandboxSession {
  #closed = false;
  #prepared = false;
  #running: SandboxProcess | undefined;
  #abortSignal: AbortSignal | undefined;
  #abortListener: (() => void) | undefined;

  constructor(
    readonly owner: SandboxImplementation,
    readonly client: RuntimeClient,
    readonly id: string,
    readonly policyDigest: string,
    readonly enforcement: EnforcementReport,
  ) {}

  bindAbort(signal: AbortSignal): void {
    this.#abortSignal = signal;
    this.#abortListener = () => void this.close();
    if (signal.aborted) this.#abortListener();
    else signal.addEventListener("abort", this.#abortListener, { once: true });
  }

  async prepare(processOptions: SandboxProcessOptions): Promise<PreparedSandboxProcess> {
    if (this.#closed) throw consumedError("session");
    if (this.#prepared || this.#running !== undefined) throw consumedError("session process slot");
    throwIfAborted(processOptions.signal, "process preparation was cancelled");
    this.#prepared = true;
    try {
      const response = object(await this.client.request(MessageType.PrepareProcess, MessageType.ProcessPrepared, {
        sessionId: this.id,
        process: serializeProcessOptions(processOptions),
      }), "prepared process");
      return new PreparedProcessImplementation(
        this,
        string(response.id, "prepared process id"),
        digest(response.policyDigest, "prepared process policy digest"),
        digest(response.executionDigest, "prepared process execution digest"),
        parseProcessSummary(response.summary),
        number(response.expiresAtMs, "prepared process expiration"),
      );
    } catch (error) {
      this.#prepared = false;
      throw normalizeProtocolError(error);
    }
  }

  async run(processOptions: SandboxProcessOptions): Promise<SandboxRunResult> {
    const prepared = await this.prepare(processOptions);
    const target = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
      ...(processOptions.signal === undefined ? {} : { signal: processOptions.signal }),
    });
    return target.wait();
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#running !== undefined) {
      await this.#running.terminate("caller-request").catch(() => undefined);
      await this.#running.wait().catch(() => undefined);
    }
    let cleanupError: SandboxCleanupError | undefined;
    try {
      const response = object(
        await this.client.request(MessageType.CloseSession, MessageType.SessionClosed, { id: this.id }),
        "closed session",
      );
      const cleanup = parseCleanup(response.cleanup);
      if (!cleanup.completed) {
        cleanupError = new SandboxCleanupError({
          code: "cleanup.session",
          message: cleanup.failures.map((failure) => `${failure.resource}: ${failure.message}`).join("; ")
            || "session cleanup did not complete",
          phase: "cleanup",
          targetExecuted: this.#running !== undefined,
        });
      }
    } finally {
      if (this.#abortSignal !== undefined && this.#abortListener !== undefined) {
        this.#abortSignal.removeEventListener("abort", this.#abortListener);
      }
      await this.client.shutdown();
      this.owner.release(this.client);
    }
    if (cleanupError !== undefined) throw cleanupError;
  }

  preparedFinished(): void {
    this.#prepared = false;
  }

  processStarted(process: SandboxProcess): void {
    this.#prepared = false;
    this.#running = process;
  }

  processFinished(process: SandboxProcess): void {
    if (this.#running === process) this.#running = undefined;
  }
}

class PreparedProcessImplementation implements PreparedSandboxProcess {
  #consumed = false;
  #expired = false;

  constructor(
    readonly session: SessionImplementation,
    readonly id: string,
    readonly policyDigest: string,
    readonly executionDigest: string,
    readonly summary: PreparedProcessSummary,
    readonly expiresAtMs: number,
  ) {
    session.client.watchPreparationExpiration(id, false, () => {
      this.#expired = true;
      session.preparedFinished();
    });
  }

  async start(expected: { policyDigest: string; executionDigest: string; signal?: AbortSignal }): Promise<SandboxProcess> {
    if (this.#consumed) throw consumedError("prepared process");
    if (this.#expired) {
      this.#consumed = true;
      this.session.client.unwatchPreparationExpiration(this.id);
      this.session.preparedFinished();
      throw expiredError("prepared process");
    }
    if (Date.now() >= this.expiresAtMs) {
      await this.cancel().catch(() => undefined);
      throw expiredError("prepared process");
    }
    this.#consumed = true;
    this.session.client.unwatchPreparationExpiration(this.id);
    try {
      const response = await this.session.client.request(MessageType.StartPreparedProcess, MessageType.ProcessStarted, {
        id: this.id,
        policyDigest: expected.policyDigest,
        executionDigest: expected.executionDigest,
      });
      const started = parseProcessStarted(response);
      let target: RuntimeProcess;
      target = new RuntimeProcess(this.session.client, {
        id: started.id,
        identity: started.identity,
        policyDigest: this.policyDigest,
        executionDigest: this.executionDigest,
        enforcement: this.session.enforcement,
        stdinMode: this.summary.execution.stdin,
        stdoutMode: this.summary.execution.stdout,
        stderrMode: this.summary.execution.stderr,
        closeRuntimeAfterWait: false,
        ...(expected.signal === undefined ? {} : { signal: expected.signal }),
        finished: () => this.session.processFinished(target),
      });
      this.session.processStarted(target);
      return target;
    } catch (error) {
      this.session.preparedFinished();
      throw normalizeProtocolError(error);
    }
  }

  async cancel(): Promise<void> {
    if (this.#consumed) return;
    this.#consumed = true;
    this.session.client.unwatchPreparationExpiration(this.id);
    try {
      await this.session.client.request(MessageType.CancelPreparedProcess, MessageType.Event, { id: this.id });
    } finally {
      this.session.preparedFinished();
    }
  }
}

function serializeRunOptions(options: SandboxRunOptions, globalExperimental: boolean): JsonObject {
  return {
    ...serializeSessionOptions(options, globalExperimental),
    process: serializeProcessOptions(options.process),
  };
}

function serializeSessionOptions(options: SandboxSessionOptions, globalExperimental: boolean): JsonObject {
  return {
    isolation: options.isolation,
    policy: options.policy,
    requirements: {
      ...options.requirements,
      allowExperimentalBackend:
        (options.requirements.allowExperimentalBackend ?? false) && globalExperimental,
    },
    resources: options.resources ?? {},
    ...(options.preparedTtlMs === undefined ? {} : { preparedTtlMs: options.preparedTtlMs }),
  };
}

function serializeProcessOptions(options: SandboxProcessOptions): JsonObject {
  return {
    executable: options.executable,
    args: options.args ?? [],
    cwd: options.cwd,
    ...(options.environment === undefined ? {} : { environment: options.environment }),
    stdin: options.stdin ?? "closed",
    stdout: options.stdout ?? "capture",
    stderr: options.stderr ?? "capture",
    ...(options.artifacts === undefined ? {} : { artifacts: options.artifacts }),
    ...(options.changeSet === undefined ? {} : { changeSet: options.changeSet }),
    resources: options.resources ?? {},
  };
}

function throwIfAborted(signal: AbortSignal | undefined, message: string): void {
  if (signal?.aborted === true) {
    throw new SandboxPreparationError({
      code: "preparation.cancelled",
      message,
      phase: "prepare",
      targetExecuted: false,
    });
  }
}

async function raceAbort<T>(
  operation: Promise<T>,
  signal: AbortSignal | undefined,
  cancelled: () => Promise<void>,
): Promise<T> {
  if (signal === undefined) return operation;
  return new Promise<T>((resolveOperation, rejectOperation) => {
    const onAbort = () => {
      void cancelled();
      rejectOperation(new SandboxPreparationError({
        code: "preparation.cancelled",
        message: "preparation was cancelled",
        phase: "prepare",
        targetExecuted: false,
      }));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    void operation.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolveOperation(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        rejectOperation(error);
      },
    );
  });
}

function consumedError(name: string): SandboxPreparationError {
  return new SandboxPreparationError({
    code: "preparation.consumed",
    message: `${name} is already consumed, cancelled, closed, or busy`,
    phase: "activate",
    targetExecuted: false,
  });
}

function expiredError(name: string): SandboxPreparationExpiredError {
  return new SandboxPreparationExpiredError({
    code: "preparation_expired.local",
    message: `${name} expired before activation`,
    phase: "activate",
    targetExecuted: false,
  });
}

function normalizeProtocolError(error: unknown): Error {
  if (error instanceof Error) return error;
  return protocolError(error);
}
