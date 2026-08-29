import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createSandbox, openSandboxExecutionRepository } from "../dist/index.js";
import { executionDirectory, readRecord, writeRecord } from "../dist/execution-record.js";
import { baseOptions } from "./helpers.mjs";

const linux = process.platform === "linux" && await (async () => {
  const sandbox = await createSandbox();
  try {
    const support = await sandbox.probe();
    return support.backends.some((backend) => backend.id === "linux-namespace-v1" && backend.available);
  } catch {
    return false;
  } finally {
    await sandbox.dispose();
  }
})();

function detachedRun(process, overrides = {}) {
  return {
    ...baseOptions(overrides),
    resources: { maxOutputBytes: 1024 * 1024 },
    process,
  };
}

test("execution repository binds one identity to one exact request", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-execution-identity-"));
  const repository = await openSandboxExecutionRepository({ directory, startupTimeoutMs: 2_000 });
  try {
    const request = {
      executionId: "same-effect",
      run: detachedRun({ executable: "/bin/true", cwd: "/" }),
    };
    const [first, second] = await Promise.all([
      repository.prepare(request, { waitMs: 2_000 }),
      repository.prepare(request, { waitMs: 2_000 }),
    ]);
    assert.equal(first.requestDigest, second.requestDigest);
    await assert.rejects(
      repository.prepare({
        executionId: request.executionId,
        run: detachedRun({ executable: "/bin/false", cwd: "/" }),
      }),
      /different request/,
    );
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("execution repository fails closed for unsupported detached contracts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-execution-contract-"));
  const repository = await openSandboxExecutionRepository({ directory });
  try {
    await assert.rejects(
      repository.prepare({
        executionId: "missing-output-bound",
        run: { ...baseOptions(), process: { executable: "/bin/true", cwd: "/" } },
      }),
      /maxOutputBytes/,
    );
    await assert.rejects(
      repository.prepare({
        executionId: "hardware-vm",
        run: {
          ...detachedRun({ executable: "/bin/true", cwd: "/" }),
          isolation: { kind: "hardware-vm" },
        },
      }),
      /process isolation only/,
    );
    const run = detachedRun({ executable: "/bin/true", cwd: "/" });
    Object.defineProperty(run, "unexpected", { enumerable: true, get: () => "side effect" });
    await assert.rejects(repository.prepare({ executionId: "accessor", run }), /must not contain accessors/);
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("execution repository creates a private authority directory", async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-execution-permissions-"));
  const directory = join(parent, "repository");
  const repository = await openSandboxExecutionRepository({ directory });
  try {
    if (process.platform !== "win32") assert.equal((await stat(directory)).mode & 0o077, 0);
    const missing = await repository.inspect("missing");
    assert.deepEqual(missing, {
      kind: "unknown",
      executionId: "missing",
      reason: "not-found",
      diagnostic: "No execution record exists for this identity.",
      output: { cursorStart: 0, cursorEnd: 0, availableCursorEnd: 0, stdoutBytes: 0, stderrBytes: 0, cursorExpired: false, chunks: [] },
    });
  } finally {
    await repository.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("accepted activation authority is never exposed as prepared", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-execution-activating-"));
  const repository = await openSandboxExecutionRepository({ directory, startupTimeoutMs: 2_000 });
  try {
    const stateDirectory = executionDirectory(directory, "accepted-authority");
    await mkdir(stateDirectory, { mode: 0o700 });
    await writeRecord(stateDirectory, {
      schemaVersion: 1,
      phase: "activating",
      executionId: "accepted-authority",
      requestDigest: `sha256:${"1".repeat(64)}`,
      createdAtMs: Date.now(),
      workerPid: process.pid,
      authToken: "private-test-authority",
      endpoint: 1,
      policyDigest: `sha256:${"2".repeat(64)}`,
      executionDigest: `sha256:${"3".repeat(64)}`,
      activatedAtMs: Date.now(),
    });

    const observation = await repository.inspect("accepted-authority");
    assert.equal(observation.kind, "preparing");
    assert.equal((await readRecord(stateDirectory)).phase, "activating");
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("detached execution survives its admitting application process", { skip: !linux }, async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-execution-caller-death-"));
  try {
    for (let repetition = 0; repetition < 8; repetition += 1) {
      const workspace = join(parent, `case-${repetition}`);
      const repositoryDirectory = join(workspace, "repository");
      const marker = join(workspace, "completed");
      await mkdir(workspace);
      const child = spawn(process.execPath, [
        join(import.meta.dirname, "fixtures", "detached-execution-caller.mjs"),
        repositoryDirectory,
        workspace,
      ], { stdio: ["ignore", "pipe", "inherit"] });
      const admitted = await readOneLine(child.stdout);
      assert.equal(admitted, "admitted");
      assert.equal(await new Promise((resolve) => child.once("exit", resolve)), 0);

      const repository = await openSandboxExecutionRepository({ directory: repositoryDirectory });
      try {
        const observation = await inspectUntilTerminal(repository, "caller-loss", { waitMs: 5_000 });
        assert.equal(
          observation.kind,
          "settled",
          observation.kind === "rejected" ? JSON.stringify(observation.error) : `Unexpected ${observation.kind} observation.`,
        );
        assert.equal(observation.output.chunks.map((chunk) => chunk.data.toString()).join(""), "detached-output");
        assert.equal(await readFile(marker, "utf8"), "completed");
      } finally {
        await repository.close();
      }
    }
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("two callers share one isolated execution and output cursors are exact", { skip: !linux }, async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-execution-two-callers-"));
  const directory = join(parent, "repository");
  const counter = join(parent, "counter");
  const repositoryA = await openSandboxExecutionRepository({ directory });
  const repositoryB = await openSandboxExecutionRepository({ directory });
  try {
    const request = {
      executionId: "shared",
      run: detachedRun({
        executable: "/bin/sh",
        args: ["-c", "printf x >> /workspace/counter; printf 123456789"],
        cwd: "/workspace",
        stdout: "pipe",
      }, {
        policy: {
          filesystem: {
            runtime: { kind: "system" },
            grants: [{ hostPath: parent, targetPath: "/workspace", access: "read-write" }],
          },
          network: { mode: "none" },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
      }),
    };
    const [first, second] = await Promise.all([
      activate(repositoryA, request, { waitMs: 5_000, maxBytes: 4 }),
      activate(repositoryB, request, { waitMs: 5_000, maxBytes: 4 }),
    ]);
    assert.equal(first.kind, "settled");
    assert.equal(second.kind, "settled");
    assert.equal(await readFile(counter, "utf8"), "x");
    const firstText = first.output.chunks.map((chunk) => chunk.data.toString()).join("");
    assert.equal(firstText, "1234");
    const rest = await repositoryA.inspect("shared", { afterCursor: first.output.cursorEnd, maxBytes: 32 });
    assert.equal(rest.output.chunks.map((chunk) => chunk.data.toString()).join(""), "56789");
  } finally {
    await repositoryA.close();
    await repositoryB.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("execution host loss becomes an unknown outcome and kills its isolated process tree", { skip: !linux }, async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-execution-host-loss-"));
  const directory = join(parent, "repository");
  const lateMarker = join(parent, "late");
  const repository = await openSandboxExecutionRepository({ directory, startupTimeoutMs: 100 });
  try {
    const request = {
      executionId: "host-loss",
      run: detachedRun({
        executable: "/bin/sh",
        args: ["-c", "sleep 1; printf late > /workspace/late"],
        cwd: "/workspace",
      }, {
        policy: {
          filesystem: {
            runtime: { kind: "system" },
            grants: [{ hostPath: parent, targetPath: "/workspace", access: "read-write" }],
          },
          network: { mode: "none" },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
      }),
    };
    const prepared = await repository.prepare(request, { waitMs: 500 });
    assert.equal(prepared.kind, "prepared");
    await repository.activate(request.executionId, prepared);
    assert.notEqual((await readRecord(executionDirectory(directory, request.executionId))).phase, "prepared");
    const observation = await repository.inspect(request.executionId, { waitMs: 500 });
    assert.equal(observation.kind, "running");
    const statePath = await stateFile(directory, "host-loss");
    const envelope = JSON.parse(await readFile(statePath, "utf8"));
    process.kill(envelope.value.workerPid, "SIGKILL");
    await new Promise((resolve) => setTimeout(resolve, 250));
    const unknown = await repository.inspect("host-loss");
    assert.equal(unknown.kind, "unknown");
    assert.equal(unknown.reason, "execution-host-unreachable");
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    await assert.rejects(readFile(lateMarker), { code: "ENOENT" });
  } finally {
    await repository.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("a durable result and cleanup receipt settles after worker death before state publication", { skip: !linux }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-execution-receipt-recovery-"));
  let repository = await openSandboxExecutionRepository({ directory, startupTimeoutMs: 10 });
  try {
    const request = {
      executionId: "receipt-recovery",
      run: detachedRun({ executable: "/bin/printf", args: ["receipt-survives"], cwd: "/", stdout: "pipe" }),
    };
    const settled = await activate(repository, request, { waitMs: 5_000 });
    assert.equal(settled.kind, "settled");
    assert.equal(settled.result.cleanup.completed, true);
    const stateDirectory = executionDirectory(directory, request.executionId);
    const state = await readRecord(stateDirectory);
    assert.equal(state.phase, "settled");
    await writeRecord(stateDirectory, {
      schemaVersion: 1,
      phase: "running",
      executionId: state.executionId,
      requestDigest: state.requestDigest,
      createdAtMs: state.createdAtMs,
      workerPid: state.workerPid,
      authToken: state.authToken,
      endpoint: state.endpoint,
      processId: state.processId,
    });
    await repository.close();
    repository = await openSandboxExecutionRepository({ directory, startupTimeoutMs: 10 });
    const recovered = await repository.inspect(request.executionId, { waitMs: 100 });
    assert.equal(recovered.kind, "settled");
    assert.equal(recovered.result.cleanup.completed, true);
    assert.equal(recovered.output.chunks.map((chunk) => chunk.data.toString()).join(""), "receipt-survives");
    assert.equal((await readRecord(stateDirectory)).phase, "settled");
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("terminal execution receipts expire without becoming replayable", { skip: !linux }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-execution-expiry-"));
  const repository = await openSandboxExecutionRepository({ directory, expiredIdentityRetentionMs: 50 });
  try {
    const request = {
      executionId: "expires",
      run: detachedRun({ executable: "/bin/true", cwd: "/" }),
    };
    const settled = await activate(repository, request, { waitMs: 5_000 });
    assert.equal(settled.kind, "settled");
    const stateDirectory = executionDirectory(directory, request.executionId);
    const settledRecord = await readRecord(stateDirectory);
    assert.equal(settledRecord.phase, "settled");
    await writeRecord(stateDirectory, { ...settledRecord, expiresAtMs: Date.now() - 1 });
    assert.equal((await repository.inspect("expires")).kind, "expired");
    const expiredRecord = await readRecord(stateDirectory);
    assert.equal(expiredRecord.phase, "expired");
    await writeRecord(stateDirectory, { ...expiredRecord, expiredAtMs: Date.now() - 51 });
    const removed = await repository.inspect("expires");
    assert.equal(removed.kind, "unknown");
    assert.equal(removed.reason, "not-found");
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
});

async function readOneLine(stream) {
  let value = "";
  for await (const chunk of stream) {
    value += chunk.toString();
    const newline = value.indexOf("\n");
    if (newline >= 0) return value.slice(0, newline);
  }
  throw new Error("Child exited before writing a line.");
}

async function activate(repository, request, query) {
  const deadline = Date.now() + (query.waitMs ?? 0);
  let observation = await repository.prepare(request, query);
  while (observation.kind === "preparing" || observation.kind === "prepared" || observation.kind === "running") {
    if (observation.kind === "prepared") await repository.activate(request.executionId, observation);
    const waitMs = Math.max(0, deadline - Date.now());
    observation = await repository.inspect(request.executionId, { ...query, waitMs });
    if (waitMs === 0) return observation;
  }
  return observation;
}

async function inspectUntilTerminal(repository, executionId, query) {
  const deadline = Date.now() + (query.waitMs ?? 0);
  let observation;
  do {
    const waitMs = Math.max(0, deadline - Date.now());
    observation = await repository.inspect(executionId, { ...query, waitMs });
    if (observation.kind !== "preparing" && observation.kind !== "prepared" && observation.kind !== "running") {
      return observation;
    }
    if (waitMs === 0) return observation;
  } while (true);
}

async function stateFile(root, executionId) {
  const { createHash } = await import("node:crypto");
  return join(root, `execution-${createHash("sha256").update(executionId).digest("hex")}`, "state.json");
}
