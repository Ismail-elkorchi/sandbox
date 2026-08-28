import { Buffer } from "node:buffer";
import { createReadStream } from "node:fs";
import net from "node:net";
import {
  appendOutput,
  parseRunForHost,
  readRecord,
  sandboxErrorData,
  writeReceipt,
  writeRecord,
} from "./execution-record.js";
import { SandboxPreparationExpiredError, SandboxPreparationError } from "./errors.js";
import { createSandbox } from "./sandbox.js";
import type { PreparedSandboxRun } from "./prepared-run.js";
import type { SandboxProcess } from "./process.js";
import type { SandboxRunResult } from "./result.js";

const directory = process.argv[2];
if (directory === undefined || directory.length === 0) process.exit(2);

void run(directory).catch(async (error: unknown) => {
  try {
    const record = await readRecord(directory);
    if (record.phase !== "expired") {
      await writeRecord(directory, {
        schemaVersion: 1,
        phase: "unknown",
        executionId: record.executionId,
        requestDigest: record.requestDigest,
        createdAtMs: record.createdAtMs,
        workerPid: process.pid,
        authToken: "authToken" in record ? record.authToken : "unavailable",
        endpoint: "endpoint" in record && record.endpoint !== undefined ? record.endpoint : 0,
        unknownAtMs: Date.now(),
        reason: "execution-host-failed",
        diagnostic: bounded(error),
      });
    }
  } catch {
    // A caller will classify an unreadable record as an unknown outcome.
  }
  process.exitCode = 1;
});

async function run(executionDirectory: string): Promise<void> {
  const initial = await waitForOwnedRecord(executionDirectory);
  const input = await readAdmissionInput();
  const { run: requestedRun, limits } = parseRunForHost(JSON.parse(input));

  let processHandle: SandboxProcess | undefined;
  let preparedHandle: PreparedSandboxRun | undefined;
  let targetMayHaveExecuted = false;
  let endpoint = 0;
  let cursor = 0;
  let sequence = 0;
  let outputHash = "0".repeat(64);
  let outputWrites = Promise.resolve();
  const capturedStdout: Buffer[] = [];
  const capturedStderr: Buffer[] = [];
  let activationExpected: { policyDigest: string; executionDigest: string } | undefined;
  let resolveActivation: ((value: { policyDigest: string; executionDigest: string }) => void) | undefined;
  let rejectActivation: ((error: Error) => void) | undefined;
  const activation = new Promise<{ policyDigest: string; executionDigest: string }>((resolve, reject) => {
    resolveActivation = resolve;
    rejectActivation = reject;
  });

  const authority: ControlAuthority = {
    process: () => processHandle,
    prepared: () => preparedHandle,
    activate(expected) {
      if (activationExpected !== undefined) {
        if (activationExpected.policyDigest !== expected.policyDigest || activationExpected.executionDigest !== expected.executionDigest) {
          throw new Error("Prepared execution was already activated with different digests.");
        }
        return;
      }
      activationExpected = expected;
      resolveActivation?.(expected);
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
    },
  };

  const server = net.createServer((socket) => {
    let request = "";
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      request += chunk.toString("utf8");
      if (Buffer.byteLength(request) > 128 * 1024) socket.destroy(new Error("Control request exceeds its bound."));
      if (!handled && request.includes("\n")) {
        handled = true;
        socket.pause();
      void handleControl(request, initial.authToken, authority).then(
        () => socket.end(`${JSON.stringify({ accepted: true })}\n`),
        (error: unknown) => socket.end(`${JSON.stringify({ accepted: false, error: bounded(error) })}\n`),
      );
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Detached execution host did not receive a TCP endpoint.");
  endpoint = address.port;
  await writeRecord(executionDirectory, { ...initial, workerPid: process.pid, endpoint });

  const sandbox = await createSandbox();
  try {
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
    await writeRecord(executionDirectory, {
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
      schemaVersion: 1,
      phase: "running",
      executionId: initial.executionId,
      requestDigest: initial.requestDigest,
      createdAtMs: initial.createdAtMs,
      workerPid: process.pid,
      authToken: initial.authToken,
      endpoint,
      processId: processHandle.id,
    });

    const retain = (stream: "stdout" | "stderr", data: Buffer): void => {
      const copy = Buffer.from(data);
      if (stream === "stdout" && stdoutMode === "capture") capturedStdout.push(copy);
      if (stream === "stderr" && stderrMode === "capture") capturedStderr.push(copy);
      outputWrites = outputWrites.then(async () => {
        const cursorStart = cursor;
        cursor += copy.byteLength;
        sequence += 1;
        outputHash = await appendOutput(executionDirectory, {
          sequence,
          cursorStart,
          cursorEnd: cursor,
          stream,
          dataBase64: copy.toString("base64"),
          previousHash: outputHash,
        });
      });
    };
    processHandle.stdout?.on("data", (chunk: Buffer | string) => retain("stdout", Buffer.from(chunk)));
    processHandle.stderr?.on("data", (chunk: Buffer | string) => retain("stderr", Buffer.from(chunk)));
    let result = await processHandle.wait();
    await outputWrites;
    if (stdoutMode === "capture" || stderrMode === "capture") {
      result = {
        ...result,
        ...(stdoutMode === "capture" ? { stdout: Buffer.concat(capturedStdout) } : {}),
        ...(stderrMode === "capture" ? { stderr: Buffer.concat(capturedStderr) } : {}),
      };
    }
    await writeReceipt(executionDirectory, result);
    const settledAtMs = Date.now();
    await writeRecord(executionDirectory, {
      schemaVersion: 1,
      phase: "settled",
      executionId: initial.executionId,
      requestDigest: initial.requestDigest,
      createdAtMs: initial.createdAtMs,
      workerPid: process.pid,
      authToken: initial.authToken,
      endpoint,
      processId: processHandle.id,
      settledAtMs,
      expiresAtMs: settledAtMs + limits.completedRetentionMs,
      cursorEnd: cursor,
      outputHash,
    });
  } catch (error) {
    await outputWrites.catch(() => undefined);
    const data = sandboxErrorData(error, targetMayHaveExecuted);
    if (data.targetExecuted) {
      await writeRecord(executionDirectory, {
        schemaVersion: 1,
        phase: "unknown",
        executionId: initial.executionId,
        requestDigest: initial.requestDigest,
        createdAtMs: initial.createdAtMs,
        workerPid: process.pid,
        authToken: initial.authToken,
        endpoint,
        unknownAtMs: Date.now(),
        reason: "execution-host-failed",
        diagnostic: data.message,
      });
    } else {
      const rejectedAtMs = Date.now();
      await writeRecord(executionDirectory, {
        schemaVersion: 1,
        phase: "rejected",
        executionId: initial.executionId,
        requestDigest: initial.requestDigest,
        createdAtMs: initial.createdAtMs,
        workerPid: process.pid,
        authToken: initial.authToken,
        endpoint,
        rejectedAtMs,
        expiresAtMs: rejectedAtMs + limits.completedRetentionMs,
        error: data,
      });
    }
  } finally {
    await sandbox.dispose().catch(() => undefined);
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

async function handleControl(
  text: string,
  expectedToken: string,
  authority: ControlAuthority,
): Promise<void> {
  const value: unknown = JSON.parse(text);
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("Control request must be an object.");
  const request = value as Record<string, unknown>;
  if (request.token !== expectedToken) throw new Error("Execution control authentication failed.");
  if (request.kind === "ping") return;
  if (request.kind === "activate") {
    if (typeof request.policyDigest !== "string" || typeof request.executionDigest !== "string") throw new TypeError("Activation digests are invalid.");
    authority.activate({ policyDigest: request.policyDigest, executionDigest: request.executionDigest });
    return;
  }
  if (request.kind === "terminate" && authority.process() === undefined && authority.prepared() !== undefined) {
    await authority.cancel();
    return;
  }
  const target = authority.process();
  if (target === undefined) throw new Error("Sandbox process is not running.");
  if (request.kind === "write") {
    if (typeof request.dataBase64 !== "string") throw new TypeError("Sandbox input is invalid.");
    const data = Buffer.from(request.dataBase64, "base64");
    if (data.byteLength > 64 * 1024 || target.stdin === null) throw new Error("Sandbox process input is unavailable.");
    await new Promise<void>((resolve, reject) => target.stdin?.write(data, (error) => error ? reject(error) : resolve()));
    return;
  }
  if (request.kind === "close-input") {
    if (target.stdin === null || target.stdin.writableEnded) return;
    await new Promise<void>((resolve, reject) => target.stdin?.end((error?: Error | null) => error ? reject(error) : resolve()));
    return;
  }
  if (request.kind === "terminate") {
    await target.terminate("caller-request");
    return;
  }
  throw new TypeError("Unknown execution control request.");
}

interface ControlAuthority {
  process(): SandboxProcess | undefined;
  prepared(): PreparedSandboxRun | undefined;
  activate(expected: { policyDigest: string; executionDigest: string }): void;
  cancel(): Promise<void>;
}

async function waitForActivation(
  activation: Promise<{ policyDigest: string; executionDigest: string }>,
  expiresAtMs: number,
): Promise<{ policyDigest: string; executionDigest: string }> {
  const delay = Math.max(0, expiresAtMs - Date.now());
  return Promise.race([
    activation,
    new Promise<never>((_, reject) => setTimeout(() => reject(new SandboxPreparationExpiredError({
      code: "preparation_expired.detached_execution",
      message: "Prepared execution expired before activation.",
      phase: "activate",
      targetExecuted: false,
    })), delay)),
  ]);
}

async function waitForOwnedRecord(executionDirectory: string) {
  const deadline = Date.now() + 10_000;
  while (true) {
    const record = await readRecord(executionDirectory);
    if (record.phase !== "expired" && record.workerPid === process.pid) return record;
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

function bounded(error: unknown): string {
  const value = error instanceof Error ? error.message : String(error);
  return value.length <= 4096 ? value : `${value.slice(0, 4093)}...`;
}
