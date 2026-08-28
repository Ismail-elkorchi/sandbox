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
import { createSandbox } from "./sandbox.js";
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
  let targetMayHaveExecuted = false;
  let endpoint = 0;
  let cursor = 0;
  let sequence = 0;
  let outputHash = "0".repeat(64);
  let outputWrites = Promise.resolve();
  const capturedStdout: Buffer[] = [];
  const capturedStderr: Buffer[] = [];

  const server = net.createServer((socket) => {
    let request = "";
    let handled = false;
    socket.on("data", (chunk: Buffer) => {
      request += chunk.toString("utf8");
      if (Buffer.byteLength(request) > 128 * 1024) socket.destroy(new Error("Control request exceeds its bound."));
      if (!handled && request.includes("\n")) {
        handled = true;
        socket.pause();
      void handleControl(request, initial.authToken, () => processHandle).then(
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
    processHandle = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
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
  processHandle: () => SandboxProcess | undefined,
): Promise<void> {
  const value: unknown = JSON.parse(text);
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("Control request must be an object.");
  const request = value as Record<string, unknown>;
  if (request.token !== expectedToken) throw new Error("Execution control authentication failed.");
  if (request.kind === "ping") return;
  const target = processHandle();
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
