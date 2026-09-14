import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { admitExecution, executionDirectory, normalizeLimits, readRecord, terminalReceipt, writeRecord, ZERO_HASH } from "../../dist/execution-record.js";
import { appendOutput } from "../../dist/execution-output.js";

export const digest = (digit) => "sha256:" + digit.repeat(64);
export const enforcement = {
  boundary: { kind: "os-process" },
  implementation: { id: "test", version: "test", buildId: "test", conformanceManifestId: "test", stability: "experimental", mechanism: [] },
  host: { platform: process.platform, architecture: process.arch, pathStyle: "posix" },
  target: { operatingSystem: "linux", pathStyle: "posix" },
  guarantees: [], filesystem: { kind: "isolated", resourceManifestDigest: "0".repeat(64), visibleRoots: [] }, caveats: [],
};
export async function fixture(root, id, options = {}) {
  const initial = {
    schemaVersion: 1, contract: "retained-execution", phase: "preparing", executionId: id,
    requestDigest: options.requestDigest ?? digest("1"), createdAtMs: 1, admitterPid: 0, workerPid: 0, authToken: "a".repeat(64), outputLimit: options.outputLimit ?? 1024 * 1024,
    metadataLimit: 8 * 1024 * 1024,
  };
  admitExecution(root, initial, normalizeLimits({ directory: root, ...options.limits }));
  const directory = executionDirectory(root, id);
  await mkdir(directory);
  await writeFile(join(directory, "output.jsonl"), "", { mode: 0o600 });
  let sequence = 0;
  const boundary = { finalCursor: 0, outputHash: ZERO_HASH, stdoutBytes: 0, stderrBytes: 0, omittedStdoutBytes: 0, omittedStderrBytes: 0 };
  const append = async (stream, data) => {
    const bytes = Buffer.from(data);
    boundary.outputHash = await appendOutput(directory, {
      sequence: ++sequence, cursorStart: boundary.finalCursor, cursorEnd: boundary.finalCursor + bytes.length,
      stream, dataBase64: bytes.toString("base64"), previousHash: boundary.outputHash,
    });
    boundary.finalCursor += bytes.length;
    if (stream === "stdout") boundary.stdoutBytes += bytes.length; else boundary.stderrBytes += bytes.length;
  };
  const running = { ...initial, phase: "running", endpoint: options.endpoint ?? 1,
    policyDigest: digest("2"), executionDigest: digest("3"), processId: "test-process" };
  const prepare = async () => {
    const summary = {
      isolation: { kind: "process" }, implementation: { ...enforcement.implementation },
      filesystem: { kind: "isolated", resourceManifestDigest: "0".repeat(64), resources: [], masks: [], privateHomePath: null, temporaryPath: null },
      network: { mode: "none", topology: "private-namespace" },
      process: { visibility: "session", control: "session", termination: { scope: "descendant-tree", graceMs: 0 } }, ipc: { visibility: "session" },
      resources: { wallTime: { enforcement: "hard", scope: "process", value: 1000 }, output: { enforcement: "hard", scope: "process", value: initial.outputLimit } },
      execution: { executable: { space: "isolated", path: "/test" }, cwd: { space: "isolated", path: "/" }, executableIdentityDigest: "0".repeat(64),
        executableContentSha256: "0".repeat(64), cwdIdentityDigest: "0".repeat(64), args: [], environmentNames: [], sensitiveEnvironmentNames: [], stdin: "pipe", stdout: "pipe", stderr: "pipe" },
    };
    delete summary.implementation.mechanism;
    initial.preparation = { policyDigest: running.policyDigest, executionDigest: running.executionDigest, summary, enforcement, expiresAtMs: Date.now() + 60_000 };
    running.preparation = initial.preparation;
    await writeRecord(directory, { ...initial, ...initial.preparation, phase: "prepared", endpoint: running.endpoint });
  };
  const accept = async () => {
    if ((await readRecord(directory, id)).phase === "preparing") await prepare();
    await writeRecord(directory, { ...initial, phase: "activating", endpoint: running.endpoint,
      policyDigest: running.policyDigest, executionDigest: running.executionDigest, activatedAtMs: Date.now() });
  };
  const start = async (overrides = {}) => {
    const current = await readRecord(directory, id);
    if (current.phase === "preparing" || current.phase === "prepared") await accept();
    Object.assign(running, overrides);
    await writeRecord(directory, running);
  };
  const settledRecord = () => terminalReceipt({
      ...initial, phase: "settled", endpoint: running.endpoint, settledAtMs: 2,
      result: { processId: running.processId, policyDigest: running.policyDigest, executionDigest: running.executionDigest,
        termination: { reason: "exit", code: 0 }, enforcement, violations: [],
        usage: { wallTimeMs: 1, stdoutBytes: boundary.stdoutBytes, stderrBytes: boundary.stderrBytes }, cleanup: { completed: true, failures: [] } },
    }, { ...boundary });
  const settle = async () => {
    if ((await readRecord(directory, id)).phase !== "running") await start();
    const terminal = settledRecord();
    await writeRecord(directory, terminal);
    return terminal;
  };
  const reject = async () => {
    const terminal = terminalReceipt({ ...initial, phase: "rejected", endpoint: 0, rejectedAtMs: 2,
      error: { code: "spawn.test", message: "test rejection", phase: "spawn", targetExecuted: false } }, { ...boundary });
    await writeRecord(directory, terminal);
    return terminal;
  };
  return { initial, running, directory, append, boundary, prepare, accept, start, settledRecord, settle, reject };
}
