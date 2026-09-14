import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fixture } from "./fixtures/execution-records.mjs";
import { sendControl } from "../dist/execution-control.js";
import { openSandboxExecutionRepository } from "../dist/index.js";
import { executionDirectory, readRecord, writeRecord } from "../dist/execution-record.js";
import {
  baseOptions,
  isolatedPath,
  isolatedPolicy,
  isolatedResource,
  linuxImplementationEligible,
  readWriteAccess,
  runtimeResources,
} from "./helpers.mjs";

const linux = await linuxImplementationEligible();

test("cancelling a preparation publishes terminal truth before it can be forgotten", { skip: !linux }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-cancel-publication-"));
  const repository = await openSandboxExecutionRepository({ directory });
  try {
    for (let attempt = 0; attempt < 6; attempt++) {
      const executionId = `cancel-${attempt}`;
      const prepared = await repository.prepare({ executionId, run: detachedRun({ executable: "/bin/true", cwd: "/" }) }, { waitMs: 5_000 });
      assert.equal(prepared.kind, "prepared");
      await repository.terminate(executionId);
      const terminal = await repository.inspect(executionId);
      assert.equal(terminal.kind, "rejected");
      await repository.forget(executionId, { receiptDigest: terminal.receipt.digest });
      const absent = await repository.inspect(executionId);
      assert.equal(absent.kind, "retired");
      assert.equal(absent.reason, "released");
    }
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("terminal output includes every stdout and stderr chunk before publication", { skip: !linux }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-output-publication-"));
  const repository = await openSandboxExecutionRepository({ directory });
  try {
    const result = await activate(repository, {
      executionId: "both-streams",
      run: detachedRun({ executable: "/bin/sh", cwd: "/", args: ["-c", "i=0; while [ $i -lt 100 ]; do printf 'out-%s\\n' $i; printf 'err-%s\\n' $i >&2; i=$((i+1)); done; exit 7"], stdout: "pipe", stderr: "pipe" })
    }, { waitMs: 5_000, maxBytes: 8_192 });
    assert.equal(result.kind, "settled", JSON.stringify(result));
    assert.deepEqual(result.result.termination, { reason: "exit", code: 7 });
    for (const [stream, prefix] of [["stdout", "out"], ["stderr", "err"]]) {
      const text = result.output.chunks.filter((chunk) => chunk.stream === stream).map((chunk) => chunk.data.toString()).join("");
      assert.equal(text, Array.from({ length: 100 }, (_, index) => `${prefix}-${index}\n`).join(""));
    }
    assert.equal((await repository.inspect("both-streams")).kind, "settled");
  } finally {
    await repository.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("real worker rejects wrong tokens and digests and deduplicates a repeated input delivery", { skip: !linux }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-control-authority-"));
  const repository = await openSandboxExecutionRepository({ directory });
  const executionId = "input-once";
  try {
    const prepared = await repository.prepare({ executionId, run: detachedRun({ executable: "/bin/sh", cwd: "/", stdin: "pipe", stdout: "pipe",
      args: ["-c", 'IFS= read -r first; IFS= read -r second; printf "%s|%s" "$first" "$second"'] }) });
    assert.equal(prepared.kind, "prepared");
    const state = await readRecord(executionDirectory(directory, executionId), executionId);
    await assert.rejects(sendControl(state.endpoint, "f".repeat(64), { kind: "ping", id: randomUUID() }), (error) => error.failure === "authentication-rejected");
    await assert.rejects(sendControl(state.endpoint, state.authToken, { kind: "activate", id: randomUUID(), policyDigest: "0".repeat(64), executionDigest: "0".repeat(64) }),
      (error) => error.failure === "operation-rejected" && error.delivery === "not-applied");
    assert.equal((await repository.inspect(executionId)).kind, "prepared");
    await repository.activate(executionId, prepared);
    let running;
    for (let attempt = 0; attempt < 100; attempt++) {
      running = await repository.inspect(executionId, { waitMs: 25 });
      if (running.kind === "running") break;
    }
    assert.equal(running.kind, "running");
    const command = { id: randomUUID(), kind: "write", dataBase64: Buffer.from("one\n").toString("base64") };
    await sendControl(state.endpoint, state.authToken, command);
    await sendControl(state.endpoint, state.authToken, command);
    await repository.writeInput(executionId, Buffer.from("two\n"));
    const terminal = await inspectUntilTerminal(repository, executionId, { waitMs: 5000 });
    assert.equal(terminal.kind, "settled");
    assert.equal(Buffer.concat(terminal.output.chunks.map((chunk) => chunk.data)).toString(), "one|two");
    assert.deepEqual(terminal.preparation.summary, prepared.summary);
  } finally { await repository.close(); await rm(directory, { recursive: true, force: true }); }
});

test("unactivated preparation deadline rejects without running the effect", { skip: !linux }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-preparation-deadline-"));
  const repository = await openSandboxExecutionRepository({ directory });
  try {
    const run = { ...detachedRun({ executable: "/bin/true", cwd: "/" }), preparedTtlMs: 100 };
    const prepared = await repository.prepare({ executionId: "deadline", run });
    assert.ok(prepared.kind === "prepared" || prepared.kind === "rejected");
    await new Promise((resolve) => setTimeout(resolve, 150));
    const terminal = await repository.inspect("deadline");
    assert.equal(terminal.kind, "rejected");
    assert.equal(terminal.error.targetExecuted, false);
    assert.match(terminal.error.code, /preparation_expired/);
    if (prepared.kind === "prepared") await assert.rejects(repository.activate("deadline", prepared), /no live control/);
  } finally { await repository.close(); await rm(directory, { recursive: true, force: true }); }
});

test("detached output limits preserve original captured bytes and exact omission counts", { skip: !linux }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-detached-output-limit-"));
  const repository = await openSandboxExecutionRepository({ directory });
  try {
    const run = detachedRun({ executable: "/bin/sh", cwd: "/", stdout: "capture", args: ["-c", "while :; do printf 1234567890; done"] });
    run.resources.output.value = 1024;
    const terminal = await activate(repository, { executionId: "limit", run }, { waitMs: 5000, maxBytes: 1024 });
    assert.equal(terminal.kind, "settled");
    assert.equal(terminal.result.termination.reason, "output-limit");
    assert.equal(terminal.result.stdout, undefined);
    assert.equal(terminal.receipt.finalCursor, 1024);
    assert.equal(terminal.receipt.stdoutBytes + terminal.receipt.omittedStdoutBytes, terminal.result.usage.stdoutBytes);
    assert.ok(terminal.receipt.omittedStdoutBytes > 0);
    const bytes = Buffer.concat(terminal.output.chunks.map((chunk) => chunk.data));
    assert.deepEqual(bytes, Buffer.from("1234567890".repeat(103)).subarray(0, 1024));
  } finally { await repository.close(); await rm(directory, { recursive: true, force: true }); }
});

function detachedRun(process, overrides = {}) {
  const options = baseOptions(overrides);
  return {
    ...options,
    resources: {
      ...options.resources,
      output: { enforcement: "hard", scope: "process", value: 1024 * 1024 },
    },
    process: {
      ...process,
      executable: typeof process.executable === "string" ? isolatedPath(process.executable) : process.executable,
      cwd: typeof process.cwd === "string" ? isolatedPath(process.cwd) : process.cwd,
    },
  };
}

function workspacePolicy(path) {
  return isolatedPolicy([
    ...runtimeResources(),
    isolatedResource("workspace", path, "/workspace", readWriteAccess(), ["data"]),
  ]);
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
        run: { ...baseOptions(), process: { executable: isolatedPath("/bin/true"), cwd: isolatedPath("/") } },
      }),
      /resources\.output/,
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
      output: { kind: "not-requested" },
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
    const item = await fixture(directory, "accepted-authority");
    await item.accept();
    const stateDirectory = item.directory;

    const observation = await repository.inspect("accepted-authority");
    assert.equal(observation.kind, "unknown");
    assert.equal(observation.controlFailure, "unreachable");
    assert.equal((await readRecord(stateDirectory, "accepted-authority")).phase, "activating");
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
        policy: workspacePolicy(parent),
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
        policy: workspacePolicy(parent),
      }),
    };
    const prepared = await repository.prepare(request, { waitMs: 500 });
    assert.equal(prepared.kind, "prepared");
    await repository.activate(request.executionId, prepared);
    assert.notEqual((await readRecord(executionDirectory(directory, request.executionId), request.executionId)).phase, "prepared");
    const observation = await repository.inspect(request.executionId, { waitMs: 500 });
    assert.equal(observation.kind, "running");
    const state = await readRecord(executionDirectory(directory, "host-loss"), "host-loss");
    process.kill(state.workerPid, "SIGKILL");
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

test("terminal publication is immutable and survives former deadlines and restart", { skip: !linux }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "sandbox-execution-retention-"));
  let repository = await openSandboxExecutionRepository({ directory });
  try {
    const request = { executionId: "retained", run: detachedRun({ executable: "/bin/printf", args: ["receipt-survives"], cwd: "/", stdout: "pipe" }) };
    const settled = await activate(repository, request, { waitMs: 5_000, maxBytes: 1024 });
    assert.equal(settled.kind, "settled");
    const stateDirectory = executionDirectory(directory, request.executionId);
    const state = await readRecord(stateDirectory, request.executionId);
    await assert.rejects(writeRecord(stateDirectory, { ...state, phase: "unknown", unknownAtMs: Date.now(), diagnostic: "stale failure" }), /immutable/);
    await repository.close();
    t.mock.timers.enable({ apis: ["Date"], now: Date.now() + 7 * 24 * 60 * 60 * 1000 });
    repository = await openSandboxExecutionRepository({ directory });
    const retained = await repository.inspect(request.executionId, { maxBytes: 1024 });
    assert.equal(retained.kind, "settled");
    assert.deepEqual(retained.receipt, settled.receipt);
    assert.equal(retained.output.chunks.map((chunk) => chunk.data.toString()).join(""), "receipt-survives");
    await assert.rejects(repository.forget(request.executionId, { receiptDigest: "sha256:" + "f".repeat(64) }), /does not match/);
    await repository.forget(request.executionId, { receiptDigest: retained.receipt.digest });
    await repository.forget(request.executionId, { receiptDigest: retained.receipt.digest });
    assert.equal((await repository.prepare(request)).kind, "retired");
  } finally {
    t.mock.timers.reset();
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
  query = { maxBytes: 256 * 1024, ...query };
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
  query = { maxBytes: 256 * 1024, ...query };
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
