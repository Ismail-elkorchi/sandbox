import { Buffer } from "node:buffer";
import { createReadStream } from "node:fs";
import { timingSafeEqual } from "node:crypto";
import { dirname } from "node:path";
import { appendOutput, OUTPUT_CHUNK_BYTES } from "./execution-output.js";
import { controlResponse, type ControlCommand } from "./execution-control.js";
import net from "node:net";
import { finished } from "node:stream/promises";
import {
  parseRunForHost,
  readRecord,
  readControl,
  sandboxErrorData,
  terminalReceipt,
  digestRun,
  writeControl,
  ZERO_HASH,
  writeRecord,
  type ExecutionRecord,
} from "./execution-record.js";
import { SandboxPreparationExpiredError, SandboxPreparationError } from "./errors.js";
import { createSandbox } from "./sandbox.js";
import type { PreparedSandboxRun } from "./prepared-run.js";
import type { SandboxProcess } from "./process.js";

const directory = process.argv[2];
const executionId = process.argv[3];
if (directory === undefined || directory.length === 0 || executionId === undefined) process.exit(2);

void run(directory, executionId).catch(async () => {
  try {
    const current = await readRecord(directory, executionId);
    if (current.phase !== "settled" && current.phase !== "rejected" && current.phase !== "retired") {
      await writeRecord(directory, {
        ...current, phase: "unknown", unknownAtMs: Date.now(),
        diagnostic: "Detached execution host failed before terminal publication.",
      }, current.phase);
    }
  } catch { /* Preserve committed evidence even if failure reporting is unavailable. */ }
  process.exitCode = 1;
});

async function run(executionDirectory: string, executionId: string): Promise<void> {
  const initial = await waitForOwnedRecord(executionDirectory, executionId);
  const input = await readAdmissionInput();
  const { run: requestedRun } = parseRunForHost(JSON.parse(input));
  if (digestRun(requestedRun) !== initial.requestDigest || requestedRun.resources?.output?.value !== initial.outputLimit) throw new Error("Admission request identity mismatch.");

  let processHandle: SandboxProcess | undefined;
  let preparedHandle: PreparedSandboxRun | undefined;
  let targetMayHaveExecuted = false;
  let endpoint = 0;
  let cursor = 0;
  let sequence = 0;
  let outputHash = ZERO_HASH;
  let retainedBytes = 0;
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let outputWrites = Promise.resolve();
  const terminalPublication = Promise.withResolvers<void>();
  // Cancellation may await publication; ordinary execution has no waiter.
  void terminalPublication.promise.catch(() => undefined);
  async function publishTerminal(record: Extract<ExecutionRecord, { phase: "settled" | "rejected" | "unknown" }>): Promise<void> {
    try {
      await writeRecord(executionDirectory, record);
      terminalPublication.resolve();
    } catch (error) {
      terminalPublication.reject(error);
      throw error;
    }
  }
  let activationExpected: { policyDigest: string; executionDigest: string } | undefined;
  let activationAcceptance: Promise<void> | undefined;
  let resolveActivation: ((value: { policyDigest: string; executionDigest: string }) => void) | undefined;
  let rejectActivation: ((error: Error) => void) | undefined;
  const activation = new Promise<{ policyDigest: string; executionDigest: string }>((resolve, reject) => {
    resolveActivation = resolve;
    rejectActivation = reject;
  });

  const authority: ControlAuthority = {
    process: () => processHandle,
    prepared: () => preparedHandle,
    async activate(expected) {
      if (activationExpected !== undefined) {
        if (activationExpected.policyDigest !== expected.policyDigest || activationExpected.executionDigest !== expected.executionDigest) {
          throw new Error("Prepared execution was already activated with different digests.");
        }
        await activationAcceptance;
        return;
      }
      if (preparedHandle === undefined) throw new Error("Sandbox execution is not prepared for activation.");
      if (expected.policyDigest !== preparedHandle.policyDigest || expected.executionDigest !== preparedHandle.executionDigest || Date.now() >= preparedHandle.expiresAtMs) {
        throw new Error("Activation authority is invalid or expired.");
      }
      activationExpected = expected;
      const acceptance = writeRecord(executionDirectory, {
        ...initial,
        schemaVersion: 1,
        phase: "activating",
        executionId: initial.executionId,
        requestDigest: initial.requestDigest,
        createdAtMs: initial.createdAtMs,
        workerPid: process.pid,
        authToken: initial.authToken,
        endpoint,
        policyDigest: expected.policyDigest,
        executionDigest: expected.executionDigest,
        activatedAtMs: Date.now(),
      }, "prepared").then(() => resolveActivation?.(expected));
      activationAcceptance = acceptance;
      try {
        await acceptance;
      } catch (error) {
        activationExpected = undefined;
        activationAcceptance = undefined;
        throw error;
      }
    },
    async cancel() {
      await preparedHandle?.cancel();
      preparedHandle = undefined;
      rejectActivation?.(new SandboxPreparationError({
        code: "preparation.cancelled",
        message: "Prepared execution was cancelled before activation.",
        phase: "activate",
        targetExecuted: false,
      }));
      await terminalPublication.promise;
    },
  };

  let controlQueue = Promise.resolve();
  const server = net.createServer((socket) => {
    let request = "";
    let handled = false;
    socket.on("error", () => undefined);
    socket.setTimeout(2_000, () => socket.destroy());
    socket.on("data", (chunk: Buffer) => {
      request += chunk.toString("utf8");
      if (Buffer.byteLength(request) > 128 * 1024) { socket.destroy(); return; }
      if (handled || !request.includes("\n")) return;
      handled = true; socket.pause();
      let command: ControlCommand;
      try {
        const parsed: unknown = JSON.parse(request);
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new TypeError();
        const value = parsed as Record<string, unknown>;
        if (typeof value.id !== "string" || !/^[a-f0-9-]{36}$/u.test(value.id) || typeof value.token !== "string" || !/^[a-f0-9]{64}$/u.test(value.token)) throw new TypeError();
        if (!timingSafeEqual(Buffer.from(value.token, "hex"), Buffer.from(initial.authToken, "hex"))) {
          socket.end(controlResponse(value.token, value.id, "authentication-rejected")); return;
        }
        const { token: _token, ...fields } = value;
        command = validateCommand(fields);
      } catch { socket.destroy(); return; }
      if (command.kind === "ping") { socket.end(controlResponse(initial.authToken, command.id)); return; }
      const execute = async () => {
        let accepted = false;
        try {
          const previous = readControl(dirname(executionDirectory), executionId);
          if (previous?.id === command.id) {
            if (previous.digest !== digestRun(command) || previous.status !== "applied") throw new Error("Conflicting or uncertain control delivery.");
            socket.end(controlResponse(initial.authToken, command.id)); return;
          }
          validateOperation(command, authority);
          writeControl(dirname(executionDirectory), executionId, { id: command.id, digest: digestRun(command), status: "accepted" });
          accepted = true;
          await handleControl(command, authority);
          writeControl(dirname(executionDirectory), executionId, { id: command.id, digest: digestRun(command), status: "applied" });
          socket.end(controlResponse(initial.authToken, command.id));
        } catch {
          socket.end(controlResponse(initial.authToken, command.id, "operation-rejected", accepted ? "unknown" : "not-applied"));
        }
      };
      controlQueue = controlQueue.then(execute, execute);
    });
  });
  let sandbox: Awaited<ReturnType<typeof createSandbox>> | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => resolve());
    });
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("Detached execution host did not receive a TCP endpoint.");
    endpoint = address.port;
    await writeRecord(executionDirectory, { ...initial, workerPid: process.pid, endpoint });
    sandbox = await createSandbox();
    const stdoutMode = requestedRun.process.stdout ?? "pipe";
    const stderrMode = requestedRun.process.stderr ?? "pipe";
    const run = {
      ...requestedRun,
      process: {
        ...requestedRun.process,
        stdout: stdoutMode === "discard" ? "discard" as const : "pipe" as const,
        stderr: stderrMode === "discard" ? "discard" as const : "pipe" as const,
      },
    };
    const prepared = await sandbox.prepareRun(run);
    preparedHandle = prepared;
    initial.preparation = { policyDigest: prepared.policyDigest, executionDigest: prepared.executionDigest,
      summary: prepared.summary, enforcement: prepared.enforcement, expiresAtMs: prepared.expiresAtMs };
    await writeRecord(executionDirectory, {
      ...initial,
      schemaVersion: 1,
      phase: "prepared",
      executionId: initial.executionId,
      requestDigest: initial.requestDigest,
      createdAtMs: initial.createdAtMs,
      workerPid: process.pid,
      authToken: initial.authToken,
      endpoint,
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
      summary: prepared.summary,
      enforcement: prepared.enforcement,
      expiresAtMs: prepared.expiresAtMs,
    });
    const expected = await waitForActivation(activation, prepared.expiresAtMs);
    processHandle = await prepared.start(expected);
    preparedHandle = undefined;
    targetMayHaveExecuted = true;
    await writeRecord(executionDirectory, {
      ...initial,
      schemaVersion: 1,
      phase: "running",
      executionId: initial.executionId,
      requestDigest: initial.requestDigest,
      createdAtMs: initial.createdAtMs,
      workerPid: process.pid,
      authToken: initial.authToken,
      endpoint,
      processId: processHandle.id,
      policyDigest: expected.policyDigest,
      executionDigest: expected.executionDigest,
    }, "activating");

    const retain = (stream: "stdout" | "stderr", data: Buffer): void => {
      const retained = data.subarray(0, Math.max(0, initial.outputLimit - retainedBytes));
      retainedBytes += retained.length;
      for (let offset = 0; offset < retained.length; offset += OUTPUT_CHUNK_BYTES) {
        const copy = Buffer.from(retained.subarray(offset, offset + OUTPUT_CHUNK_BYTES));
        outputWrites = outputWrites.then(async () => {
          const cursorStart = cursor;
          cursor += copy.byteLength; sequence += 1;
          if (stream === "stdout") stdoutBytes += copy.byteLength; else stderrBytes += copy.byteLength;
          outputHash = await appendOutput(executionDirectory, {
            sequence, cursorStart, cursorEnd: cursor, stream,
            dataBase64: copy.toString("base64"), previousHash: outputHash,
          });
        });
        void outputWrites.catch(() => undefined);
      }
    };
    processHandle.stdout?.on("data", (chunk: Buffer | string) => retain("stdout", Buffer.from(chunk)));
    processHandle.stderr?.on("data", (chunk: Buffer | string) => retain("stderr", Buffer.from(chunk)));
    const [completed] = await Promise.all([
      processHandle.wait(),
      ...[processHandle.stdout, processHandle.stderr].flatMap((stream) =>
        stream === null ? [] : [finished(stream, { readable: true, writable: false, cleanup: true })]),
    ]);
    await outputWrites;
    const { stdout: _stdout, stderr: _stderr, ...result } = completed;
    await publishTerminal(terminalReceipt({
      ...initial, phase: "settled" as const, workerPid: process.pid, endpoint, settledAtMs: Date.now(), result,
    }, {
      finalCursor: cursor, outputHash, stdoutBytes, stderrBytes,
      omittedStdoutBytes: Math.max(0, result.usage.stdoutBytes - stdoutBytes),
      omittedStderrBytes: Math.max(0, result.usage.stderrBytes - stderrBytes),
    }));
  } catch (error) {
    await outputWrites.catch(() => undefined);
    const data = sandboxErrorData(error, targetMayHaveExecuted);
    if (data.targetExecuted) {
      await publishTerminal({
        ...initial,
        schemaVersion: 1,
        phase: "unknown",
        executionId: initial.executionId,
        requestDigest: initial.requestDigest,
        createdAtMs: initial.createdAtMs,
        workerPid: process.pid,
        authToken: initial.authToken,
        endpoint,
        unknownAtMs: Date.now(),
        diagnostic: data.message,
      });
    } else {
      await publishTerminal(terminalReceipt({
        ...initial, phase: "rejected" as const, workerPid: process.pid, endpoint, rejectedAtMs: Date.now(), error: data,
      }, { finalCursor: cursor, outputHash, stdoutBytes, stderrBytes, omittedStdoutBytes: 0, omittedStderrBytes: 0 }));
    }
  } finally {
    await sandbox?.dispose().catch(() => undefined);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function validateCommand(value: Record<string, unknown>): ControlCommand {
  const allowed = new Set(["id", "kind", "policyDigest", "executionDigest", "dataBase64"]);
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new TypeError("Invalid control fields.");
  if (value.kind !== "ping" && value.kind !== "activate" && value.kind !== "write" && value.kind !== "close-input" && value.kind !== "terminate") throw new TypeError("Invalid control kind.");
  if (value.kind === "activate" && (typeof value.policyDigest !== "string" || typeof value.executionDigest !== "string"
    || !/^(?:[a-z0-9_-]+:)?[a-f0-9]{64}$/u.test(value.policyDigest) || !/^(?:[a-z0-9_-]+:)?[a-f0-9]{64}$/u.test(value.executionDigest))) throw new TypeError("Invalid activation authority.");
  if (value.kind === "write" && (typeof value.dataBase64 !== "string" || Buffer.from(value.dataBase64, "base64").toString("base64") !== value.dataBase64
    || Buffer.from(value.dataBase64, "base64").length > 64 * 1024)) throw new TypeError("Invalid input bytes.");
  return value as unknown as ControlCommand;
}
function validateOperation(command: ControlCommand, authority: ControlAuthority): void {
  const prepared = authority.prepared();
  if (command.kind === "activate") {
    if (prepared !== undefined && (command.policyDigest !== prepared.policyDigest || command.executionDigest !== prepared.executionDigest || Date.now() >= prepared.expiresAtMs)) throw new Error("Invalid preparation.");
    return;
  }
  if (command.kind === "terminate" && prepared !== undefined) return;
  const target = authority.process();
  if (target === undefined) throw new Error("Sandbox process is not running.");
  if (command.kind === "write" && (target.stdin === null || target.stdin.writableEnded)) throw new Error("Sandbox input is unavailable.");
}
async function handleControl(command: ControlCommand, authority: ControlAuthority): Promise<void> {
  if (command.kind === "activate") { await authority.activate({ policyDigest: command.policyDigest!, executionDigest: command.executionDigest! }); return; }
  if (command.kind === "terminate" && authority.process() === undefined && authority.prepared() !== undefined) { await authority.cancel(); return; }
  const target = authority.process();
  if (target === undefined) throw new Error("Sandbox process is not running.");
  if (command.kind === "write") {
    await new Promise<void>((resolve, reject) => target.stdin!.write(Buffer.from(command.dataBase64!, "base64"), (error) => error ? reject(error) : resolve()));
  } else if (command.kind === "close-input") {
    if (target.stdin === null || target.stdin.writableEnded) return;
    await new Promise<void>((resolve, reject) => target.stdin!.end((error?: Error | null) => error ? reject(error) : resolve()));
  } else if (command.kind === "terminate") {
    await target.terminate("caller-request");
  }
}

interface ControlAuthority {
  process(): SandboxProcess | undefined;
  prepared(): PreparedSandboxRun | undefined;
  activate(expected: { policyDigest: string; executionDigest: string }): Promise<void>;
  cancel(): Promise<void>;
}

async function waitForActivation(
  activation: Promise<{ policyDigest: string; executionDigest: string }>,
  expiresAtMs: number,
): Promise<{ policyDigest: string; executionDigest: string }> {
  const delay = Math.max(0, expiresAtMs - Date.now());
  let expirationTimer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      activation,
      new Promise<never>((_, reject) => {
        expirationTimer = setTimeout(() => reject(new SandboxPreparationExpiredError({
          code: "preparation_expired.detached_execution",
          message: "Prepared execution expired before activation.",
          phase: "activate",
          targetExecuted: false,
        })), delay);
      }),
    ]);
  } finally {
    if (expirationTimer !== undefined) clearTimeout(expirationTimer);
  }
}

async function waitForOwnedRecord(executionDirectory: string, executionId: string) {
  const deadline = Date.now() + 10_000;
  while (true) {
    const record = await readRecord(executionDirectory, executionId);
    if (record.phase !== "preparing") throw new Error("Detached execution host no longer owns admission.");
    if (record.workerPid === process.pid) return record;
    if (Date.now() >= deadline) throw new Error("Detached execution host did not acquire its execution record.");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function readAdmissionInput(): Promise<string> {
  const input = createReadStream("", { fd: 3, autoClose: true });
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of input) {
    const value = Buffer.from(chunk);
    bytes += value.byteLength;
    if (bytes > 2 * 1024 * 1024) throw new RangeError("Detached execution request exceeds the 2 MiB admission bound.");
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}
