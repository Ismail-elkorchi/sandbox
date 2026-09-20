import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { before, test } from "node:test";
import { createSandsurfMutation, encodeSandsurfFrame, SandsurfFrameDecoder, sandsurfDigest, validateSandsurfMutation, validateSandsurfRelease } from "../dist/sandsurf-protocol.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixture = resolve(root, `target/debug/examples/contract_fixture${process.platform === "win32" ? ".exe" : ""}`);
before(() => {
  const built = spawnSync("cargo", ["build", "--locked", "-p", "sandsurf-protocol", "--example", "contract_fixture"], { cwd: root, encoding: "utf8", timeout: 120_000 });
  assert.equal(built.status, 0, built.stderr);
});
function native(mode, input, ...args) { return spawnSync(fixture, [mode, ...args], { input, maxBuffer: 1024 * 1024, timeout: 10_000 }); }

test("Rust and TypeScript encode every Sandsurf digest domain identically", () => {
  const value = { z: 1, a: [true, null, "é", -13, Number.MAX_SAFE_INTEGER], "\u{10000}": "astral", "\ue000": "BMP" };
  for (const domain of ["sandbox", "grant", "operation", "receipt", "output", "release", "image", "checkpoint", "transfer"]) {
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
      user: "agent", stdio: "pipes", terminalSize: null, lifetime: "job", outputBytes: 1024,
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
    const value = { receiptDigest, output, disposition };
    validateSandsurfRelease(value);
    const accepted = native("release", JSON.stringify(value));
    assert.equal(accepted.status, 0, accepted.stderr.toString());
    assert.deepEqual(JSON.parse(accepted.stdout), value);
  }
  for (const value of [{ receiptDigest }, { receiptDigest, output, disposition: { kind: "acknowledged" } }, { receiptDigest, output, disposition: { kind: "complete-capture", reference: "some-url" } }]) {
    assert.throws(() => validateSandsurfRelease(value));
    assert.notEqual(native("release", JSON.stringify(value)).status, 0);
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
