import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { before, test } from "node:test";
import { Sandbox, SandboxFilesystem, SandboxProcess, SandsurfHostError } from "../dist/index.js";
import { createSandsurfGuestPath, createSandsurfMutation, encodeSandsurfFrame, SandsurfFrameDecoder, sandsurfDigest, sandsurfGuestPathUtf8, validateSandsurfGuestPath, validateSandsurfMutation, validateSandsurfRelease } from "../dist/sandsurf-protocol.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixture = resolve(root, `target/debug/examples/contract_fixture${process.platform === "win32" ? ".exe" : ""}`);
before(() => {
  const built = spawnSync("cargo", ["build", "--locked", "-p", "sandsurf-protocol", "--example", "contract_fixture"], { cwd: root, encoding: "utf8", timeout: 120_000 });
  assert.equal(built.status, 0, built.stderr);
});
function native(mode, input, ...args) { return spawnSync(fixture, [mode, ...args], { input, maxBuffer: 1024 * 1024, timeout: 10_000 }); }

test("Rust and TypeScript encode every Sandsurf digest domain identically", () => {
  const value = { z: 1, a: [true, null, "é", -13, Number.MAX_SAFE_INTEGER], "\u{10000}": "astral", "\ue000": "BMP" };
  for (const domain of ["sandbox", "grant", "operation", "receipt", "output", "release", "image", "checkpoint", "transfer", "network", "secret", "resource", "exposure"]) {
    const result = native("digest", JSON.stringify(value), domain);
    assert.equal(result.status, 0, result.stderr.toString());
    assert.equal(result.stdout.toString(), sandsurfDigest(domain, value));
  }
  for (const value of [0.1, -0, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, undefined, "\ud800", new Date()]) assert.throws(() => sandsurfDigest("operation", value));
});

test("Rust and TypeScript agree on valid and invalid mutation fields", () => {
  const value = createSandsurfMutation({
    sandboxId: "box", epoch: 1, operationId: "op", grantId: "grant", expectedRevision: 2,
    request: { kind: "spawn", request: {
      sandboxId: "box", epoch: 1, processId: "process", operationId: "op",
      argv: ["/bin/echo", "hello"], cwd: "/workspace", environment: { PATH: "/usr/bin:/bin" },
      user: "agent", stdio: "pipes", terminalSize: null, lifetime: "job", activeDeadlineMillis: null, elapsedDeadlineUnixMillis: null, outputBytes: 1024,
    } },
  });
  validateSandsurfMutation(value);
  const accepted = native("mutation", JSON.stringify(value));
  assert.equal(accepted.status, 0, accepted.stderr.toString());
  assert.deepEqual(JSON.parse(accepted.stdout), value);
  for (const invalid of [{ ...value, epoch: -1 }, { ...value, epoch: 0.5 }, { ...value, sandboxId: "../escape" }, { ...value, epoch: Number.MAX_SAFE_INTEGER + 1 }, { ...value, currentGrants: [] }, { ...value, requestDigest: "a".repeat(64) }, { ...value, request: { ...value.request, request: { ...value.request.request, cwd: "/workspace/../host" } } }]) {
    assert.throws(() => validateSandsurfMutation(invalid));
    assert.notEqual(native("mutation", JSON.stringify(invalid)).status, 0);
  }
});

test("release dispositions require a full boundary and explicit evidence fields", () => {
  const output = { finalCursor: 0, chunks: 0, stdoutBytes: 0, stderrBytes: 0, terminalBytes: 0, omittedBytes: 0, finalHash: "a".repeat(64) };
  const receiptDigest = "b".repeat(64);
  for (const disposition of [
    { kind: "complete-capture", commitment: { storeId: "store", commitmentId: "capture", manifestDigest: "c".repeat(64), receiptDigest, output } },
    { kind: "continuing-retention", pin: "pin" },
    { kind: "authorized-loss", authorization: "approval" },
  ]) {
    const value = { operationId: "release", receiptDigest, output, disposition };
    validateSandsurfRelease(value);
    const accepted = native("release", JSON.stringify(value));
    assert.equal(accepted.status, 0, accepted.stderr.toString());
    assert.deepEqual(JSON.parse(accepted.stdout), value);
  }
  for (const value of [{ receiptDigest }, { operationId: "release", receiptDigest, output, disposition: { kind: "acknowledged" } }, { operationId: "release", receiptDigest, output, disposition: { kind: "complete-capture", reference: "some-url" } }]) {
    assert.throws(() => validateSandsurfRelease(value));
    assert.notEqual(native("release", JSON.stringify(value)).status, 0);
  }
});

test("guest paths preserve bytes across Rust and TypeScript", () => {
  const path = createSandsurfGuestPath(Buffer.from([0x2f, 0x77, 0x2f, 0xff]));
  validateSandsurfGuestPath(path);
  assert.equal(sandsurfGuestPathUtf8(path), undefined);
  const accepted = native("path", JSON.stringify(path));
  assert.equal(accepted.status, 0, accepted.stderr.toString());
  assert.deepEqual(JSON.parse(accepted.stdout), path);
  for (const invalid of [[], [...Buffer.from("relative")], [...Buffer.from("/a/../b")], [0x2f, 0]]) {
    assert.throws(() => validateSandsurfGuestPath(invalid));
    assert.notEqual(native("path", JSON.stringify(invalid)).status, 0);
  }
});

test("binary frame interoperability includes fragmentary input, EOF and zero-length end", () => {
  for (const kind of ["data", "control", "credit", "end"]) {
    const frame = { kind, stream: kind === "control" ? 0 : 23, sequence: Number.MAX_SAFE_INTEGER, authentication: Buffer.alloc(32), payload: kind === "end" ? Buffer.alloc(0) : kind === "credit" ? Buffer.alloc(8) : Buffer.from([0, 255, 128, 10]) };
    const bytes = encodeSandsurfFrame(frame);
    const nativeResult = native("frame", bytes);
    assert.equal(nativeResult.status, 0, nativeResult.stderr.toString());
    assert.deepEqual(nativeResult.stdout, bytes);
    const decoder = new SandsurfFrameDecoder();
    const decoded = [];
    for (const byte of bytes) decoded.push(...decoder.push(Buffer.from([byte])));
    decoder.finish();
    assert.deepEqual(decoded, [frame]);
    for (let length = 1; length < bytes.length; length++) {
      const partial = new SandsurfFrameDecoder(); [...partial.push(bytes.subarray(0, length))];
      assert.throws(() => partial.finish());
    }
  }
});

test("decoder rejects oversized allocation and remains failed", () => {
  const bytes = encodeSandsurfFrame({ kind: "control", stream: 0, sequence: 1, authentication: Buffer.alloc(32), payload: Buffer.alloc(0) });
  bytes.writeUInt32BE(0xffff_ffff, 20);
  const decoder = new SandsurfFrameDecoder();
  assert.throws(() => [...decoder.push(bytes)]);
  assert.throws(() => decoder.finish());
  assert.throws(() => [...decoder.push(Buffer.alloc(0))]);
  assert.notEqual(native("frame", bytes).status, 0);
});

test("process input is explicit and output follow waits on replayable runtime events", async () => {
  const bytes = Buffer.from("ok");
  const digest = createHash("sha256").update(bytes).digest("hex");
  let ready = false;
  const workload = [];
  const sandbox = {
    id: "box",
    events: {
      async read() { return { cursor: ready ? 3 : 2, available: ready ? 3 : 2, events: [] }; },
      async *follow({ after }) {
        assert.equal(after, 2);
        ready = true;
        yield { cursor: 3, digest: "a".repeat(64), value: { kind: "output", processId: "process", boundary: { finalCursor: 2 } } };
      },
    },
    async workload(request, capability, operationId) {
      workload.push({ request, capability, operationId });
      return { delivery: "applied" };
    },
    async hostRequest(request) {
      if (request.kind === "read-evidence") return {
        kind: "runtime",
        response: {
          kind: "output",
          page: ready
            ? { after: request.after, cursor: 2, available: 2, chunks: request.after === 0 ? [{ offset: 0, stream: "stdout", bytes: [...bytes], bytesDigest: digest }] : [] }
            : { after: request.after, cursor: request.after, available: 0, chunks: [] },
        },
      };
      if (request.kind === "get-receipt") return {
        kind: "runtime",
        response: ready
          ? { kind: "receipt", digest: "b".repeat(64), receipt: { output: { finalCursor: 2 } } }
          : { kind: "receipt", digest: null, receipt: null },
      };
      throw new Error(`Unexpected request ${request.kind}`);
    },
  };
  const process = new SandboxProcess(sandbox, "process");
  await process.input.write(Uint8Array.of(1, 2), { operationId: "write-input" });
  await process.input.close({ operationId: "close-input" });
  assert.deepEqual(workload.map((entry) => entry.request.kind), ["write-input", "close-input"]);
  const output = [];
  for await (const chunk of process.output.follow({ after: 0 })) output.push(...chunk.bytes);
  assert.deepEqual(output, [...bytes]);
});

test("streamed file writes have chunk-boundary-independent identities and preserve ambiguous stages", async () => {
  const bytes = Buffer.alloc(70_001, 0x5a);
  const expectedDigest = createHash("sha256").update(bytes).digest("hex");
  const run = async (chunks, failChunk = false) => {
    const operations = [];
    const sandbox = {
      id: "box",
      async inspect() { return { machine: { kind: "current", value: { epoch: 1 } } }; },
      async workload(request, capability, operationId) {
        assert.equal(capability, "write-files");
        operations.push({ operationId, request });
        return { request: { requestDigest: "a".repeat(64) } };
      },
      async guest(request) {
        if (failChunk && operations.at(-1)?.request.request.kind === "write-chunk") throw new SandsurfHostError("transport", "ambiguous delivery");
        return { kind: "file", response: { kind: "complete", request } };
      },
    };
    const filesystem = new SandboxFilesystem(sandbox);
    await assert.doesNotReject(async () => filesystem.writeStream("/workspace/data", chunks, { length: bytes.byteLength, digest: expectedDigest, operationId: "stable-write", transferId: "stable-transfer" }));
    return operations;
  };
  const first = await run([bytes.subarray(0, 10_000), bytes.subarray(10_000)]);
  const second = await run([bytes.subarray(0, 1), bytes.subarray(1, 65_537), bytes.subarray(65_537)]);
  assert.deepEqual(first, second);
  assert.deepEqual(first.filter(({ request }) => request.request.kind === "write-chunk").map(({ request }) => request.request.bytes.length), [65_536, 4_465]);

  const operations = [];
  const sandbox = {
    id: "box",
    async inspect() { return { machine: { kind: "current", value: { epoch: 1 } } }; },
    async workload(request, _capability, operationId) { operations.push({ request, operationId }); return { request: { requestDigest: "b".repeat(64) } }; },
    async guest() { if (operations.at(-1)?.request.request.kind === "write-chunk") throw new SandsurfHostError("transport", "ambiguous delivery"); return { kind: "file", response: { kind: "complete" } }; },
  };
  await assert.rejects(new SandboxFilesystem(sandbox).writeStream("/workspace/data", [bytes], { length: bytes.byteLength, digest: expectedDigest, operationId: "ambiguous-write", transferId: "ambiguous-transfer" }), /ambiguous delivery/u);
  assert.equal(operations.some(({ request }) => request.request.kind === "abort-write"), false);
});

test("filesystem reads use bounded grant-checked queries without consuming mutation identities", async () => {
  let workloadCalls = 0;
  const requests = [];
  const sandbox = {
    id: "box",
    async workload() { workloadCalls += 1; throw new Error("read entered mutation ledger"); },
    async guest(request, capability) {
      requests.push(request);
      assert.equal(capability, "read-files");
      return { kind: "file", response: { kind: "stat", value: { kind: "regular", size: 0 } } };
    },
  };
  const response = await new SandboxFilesystem(sandbox).stat("/workspace/file");
  assert.equal(response.kind, "stat");
  assert.equal(workloadCalls, 0);
  assert.deepEqual(requests.map((request) => request.kind), ["filesystem-query"]);
});

test("caller preconditions are forwarded as stale-write fences, not refreshed authority", async () => {
  const requests = [];
  const host = {
    async request(request) {
      requests.push(request);
      if (request.kind === "workload") return { kind: "dispatch", operation: { delivery: "applied" } };
      throw new Error(`Unexpected request ${request.kind}`);
    },
    async approve() { throw new Error("ordinary workload dispatch requested application approval"); },
  };
  const sandbox = new Sandbox(host, {
    id: "box", imageDigest: "a".repeat(64), resources: { vcpus: 1, memoryMiB: 1, diskBytes: 1, outputBytes: 1, processes: 1 },
    runtimeConfiguration: { network: { rules: [] }, exposures: [], resources: { workloadMemoryBytes: 1, workloadProcesses: 1 } },
    configurationRevision: 99, reservation: "held", lifecycleIntent: {}, machine: { kind: "unavailable", lastKnown: null }, workloadDefaults: { environment: {}, user: "agent", workingDirectory: "/workspace", entrypoint: [], command: [] }, lifetime: { idleStopAfterMillis: null, expiresAtUnixMillis: null, expirationAction: "stop" }, lastActivityUnixMillis: 1,
  });
  await sandbox.workload({ kind: "mkdir" }, "write-files", "stable-operation", { expectedRevision: 7, expectedEpoch: 3 });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].expectedRevision, 7);
  assert.equal(requests[0].epoch, 3);
});

test("ambiguous workload admission is not reported as a completed mutation", async () => {
  const view = {
    id: "box", imageDigest: "a".repeat(64), resources: { vcpus: 1, memoryMiB: 1, diskBytes: 1, outputBytes: 1, processes: 1 },
    runtimeConfiguration: { network: { rules: [] }, exposures: [], resources: { workloadMemoryBytes: 1, workloadProcesses: 1 } },
    configurationRevision: 1, reservation: "held", lifecycleIntent: {}, machine: { kind: "unavailable", lastKnown: null }, workloadDefaults: { environment: {}, user: "agent", workingDirectory: "/workspace", entrypoint: [], command: [] }, lifetime: { idleStopAfterMillis: null, expiresAtUnixMillis: null, expirationAction: "stop" }, lastActivityUnixMillis: 1,
  };
  for (const delivery of ["unknown", "not-applied"]) {
    const host = { async request() { return { kind: "dispatch", operation: { delivery } }; } };
    const sandbox = new Sandbox(host, view);
    await assert.rejects(
      sandbox.workload({ kind: "write-input" }, "spawn", "stable-input", { expectedRevision: 1, expectedEpoch: 1 }),
      (error) => error instanceof SandsurfHostError && error.category === (delivery === "unknown" ? "ambiguous" : "not-applied") && error.message.includes("stable-input"),
    );
  }
});

test("guest filesystem errors retain their structured category", async () => {
  const sandbox = new Sandbox({ async request() { return { kind: "guest", response: { kind: "error", code: "filesystem.missing", message: "file does not exist" } }; } }, {
    id: "box", imageDigest: "a".repeat(64), resources: { vcpus: 1, memoryMiB: 1, diskBytes: 1, outputBytes: 1, processes: 1 },
    runtimeConfiguration: { network: { rules: [] }, exposures: [], resources: { workloadMemoryBytes: 1, workloadProcesses: 1 } },
    configurationRevision: 1, reservation: "held", lifecycleIntent: {}, machine: { kind: "unavailable", lastKnown: null }, workloadDefaults: { environment: {}, user: "agent", workingDirectory: "/workspace", entrypoint: [], command: [] }, lifetime: { idleStopAfterMillis: null, expiresAtUnixMillis: null, expirationAction: "stop" }, lastActivityUnixMillis: 1,
  });
  await assert.rejects(
    sandbox.guest({ kind: "filesystem-query", request: { kind: "stat" } }, "read-files", { expectedRevision: 1 }),
    (error) => error instanceof SandsurfHostError && error.category === "filesystem.missing",
  );
});

test("workspace publication uploads immutable captured blobs rather than live guest files", async () => {
  const captured = Buffer.from("captured before later edits");
  const fileDigest = createHash("sha256").update(captured).digest("hex");
  const entry = { path: "file.txt", kind: "file", mode: 0o644, size: captured.byteLength, digest: fileDigest, target: null };
  const entryDigest = sandsurfDigest("transfer", ["sandsurf-workspace-entry-v1", entry]);
  const manifestDigest = createHash("sha256").update("SANDSURF-WORKSPACE-MANIFEST-V1\0").update(Buffer.from(entryDigest, "hex")).digest("hex");
  const emptyDigest = createHash("sha256").update("SANDSURF-WORKSPACE-MANIFEST-V1\0").digest("hex");
  const calls = [];
  const uploaded = [];
  let currentCaptureId = "capture-1";
  const view = {
    id: "box", imageDigest: "a".repeat(64), resources: { vcpus: 1, memoryMiB: 1, diskBytes: 1024, outputBytes: 1, processes: 1 },
    runtimeConfiguration: { network: { rules: [] }, exposures: [], resources: { workloadMemoryBytes: 1, workloadProcesses: 1 } },
    configurationRevision: 1, reservation: "held", lifecycleIntent: {}, machine: { kind: "current", value: { epoch: 1 } }, workloadDefaults: { environment: {}, user: "agent", workingDirectory: "/workspace", entrypoint: [], command: [] }, lifetime: { idleStopAfterMillis: null, expiresAtUnixMillis: null, expirationAction: "stop" }, lastActivityUnixMillis: 1,
  };
  const capture = () => ({ sandboxId: "box", operationId: currentCaptureId, requestDigest: "b".repeat(64), manifestDigest, entries: 1, bytes: captured.byteLength });
  const host = {
    async approve() { return "approval"; },
    async request(request) {
      calls.push(request);
      switch (request.kind) {
        case "get-sandbox": return { kind: "sandbox", value: view };
        case "capture-guest-tree": currentCaptureId = request.operationId; return { kind: "host-tree-capture", capture: capture() };
        case "list-host-tree": assert.equal(request.operationId, currentCaptureId); return { kind: "host-tree-entries", capture: capture(), entries: [entry], next: null };
        case "read-host-tree-blob": assert.equal(request.operationId, currentCaptureId); return { kind: "host-blob", digest: fileDigest, offset: request.offset, bytes: [...captured], eof: true };
        case "write-host-blob": uploaded.push(...request.bytes); return { kind: "complete" };
        case "begin-host-blob": case "commit-host-blob": return { kind: "complete" };
        case "apply-host-workspace":
          assert.equal("captureOperationId" in request.changeSet, false);
          return { kind: "host-apply", report: { operationId: request.operationId, changeSetDigest: request.changeSet.digest, applied: 1, recovered: false } };
        default: throw new Error(`Unexpected request ${request.kind}`);
      }
    },
  };
  const sandbox = new Sandbox(host, view);
  const snapshot = await sandbox.workspace.snapshot({ operationId: "capture-1", maximumBytes: 1024 });
  assert.equal(snapshot.digest, manifestDigest);
  assert.equal(snapshot.captureOperationId, "capture-1");
  const changes = await sandbox.workspace.diff({ digest: emptyDigest, entries: [] });
  assert.equal(changes.captureOperationId.startsWith("workspace-capture-"), true);
  const report = await sandbox.workspace.applyToHost({ destination: resolve(root, "captured-publication"), operationId: "publish-1", changeSet: changes });
  assert.equal(report.applied, 1);
  assert.deepEqual(uploaded, [...captured]);
  assert.equal(calls.some((request) => request.kind === "guest"), false);
  assert.equal(calls.filter((request) => request.kind === "capture-guest-tree").length, 2);
});
