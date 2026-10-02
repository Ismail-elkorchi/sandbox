import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PassThrough, Writable } from "node:stream";
import { NativeHostClient, SandsurfHostError } from "../dist/native-host.js";

// Exercise the transport ordering without a public injection API or a second
// implementation of the bridge. The real native correlation test stays below.
function bridgeFixture(t) {
  const child = new EventEmitter();
  child.stdin = new Writable({ write(_bytes, _encoding, done) { done(); } });
  child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.kill = () => true;
  t.mock.method(childProcess, "spawn", () => child);
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return { child, client: new NativeHostClient("fixture", "fixture") };
}

function replyFrame(id, response) {
  const json = Buffer.from(JSON.stringify([id, 1, response]));
  const frame = Buffer.alloc(8 + json.length);
  frame.writeUInt32LE(4 + json.length); frame.writeUInt32LE(json.length, 4);
  json.copy(frame, 8); return frame;
}

test("bridge drains replies that arrive after process exit and before stdio close", async (t) => {
  const { child, client } = bridgeFixture(t);
  const response = client.request({ kind: "inspect" });
  child.emit("exit", 0, null);
  const frame = replyFrame(1, { kind: "complete" });
  child.stdout.write(frame.subarray(0, 3));
  child.stdout.write(frame.subarray(3));
  child.stdout.end(); child.stderr.end(); child.emit("close", 0, null);
  assert.deepEqual(await response, { kind: "complete" });
  await client.close();
});

test("failed spawn closes the client without requiring an exit event", async (t) => {
  const { child, client } = bridgeFixture(t);
  const failed = assert.rejects(client.request({ kind: "inspect" }), (error) =>
    error instanceof SandsurfHostError && error.category === "transport");
  child.emit("error", new Error("spawn failed"));
  child.stdout.end(); child.stderr.end(); child.emit("close", -2, null);
  await failed; await client.close();
});

test("bridge closure with an incomplete reply is a protocol failure", async (t) => {
  const { child, client } = bridgeFixture(t);
  const failed = assert.rejects(client.request({ kind: "inspect" }), (error) =>
    error instanceof SandsurfHostError && error.category === "protocol");
  child.emit("exit", 0, null);
  child.stdout.write(replyFrame(1, { kind: "complete" }).subarray(0, 9));
  child.stdout.end(); child.stderr.end(); child.emit("close", 0, null);
  await failed; await client.close();
});

test("bridge accepts highly fragmented metadata and coalesced out-of-order replies", async (t) => {
  const { child, client } = bridgeFixture(t);
  const pending = [client.request({ kind: "inspect" }), client.request({ kind: "inspect" }), client.request({ kind: "inspect" })];
  const large = { kind: "complete", padding: "x".repeat(200_000) };
  const fragmented = replyFrame(2, large);
  for (let offset = 0; offset < fragmented.length; offset += 7) child.stdout.write(fragmented.subarray(offset, offset + 7));
  child.stdout.write(Buffer.concat([replyFrame(3, { kind: "complete" }), replyFrame(1, { kind: "complete" })]));
  child.stdout.end(); child.stderr.end(); child.emit("close", 0, null);
  assert.deepEqual(await Promise.all(pending), [{ kind: "complete" }, large, { kind: "complete" }]);
  await client.close();
});

for (const length of [0, 1024 * 1024 + 256 * 1024 + 5]) {
  test(`bridge rejects frame length ${length} before accepting subsequent bytes`, async (t) => {
    const { child, client } = bridgeFixture(t);
    const failed = assert.rejects(client.request({ kind: "inspect" }), (error) =>
      error instanceof SandsurfHostError && error.category === "protocol");
    const header = Buffer.alloc(4); header.writeUInt32LE(length);
    child.stdout.write(header); child.stdout.write(replyFrame(1, { kind: "complete" }));
    child.stdout.end(); child.stderr.end(); child.emit("close", 0, null);
    await failed; await client.close();
  });
}

test("bridge rejects invalid UTF-8 rather than changing response bytes", async (t) => {
  const { child, client } = bridgeFixture(t);
  const failed = assert.rejects(client.request({ kind: "inspect" }), (error) =>
    error instanceof SandsurfHostError && error.category === "protocol");
  const frame = replyFrame(1, { kind: "complete" }); frame[frame.indexOf("complete")] = 0xff;
  child.stdout.write(frame); child.stdout.end(); child.stderr.end(); child.emit("close", 0, null);
  await failed; await client.close();
});

test("native bridge correlates concurrent host responses and bounds admission", async () => {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-bridge-"));
  let client;
  try {
    // The host creates its own private store. A Node-created temporary parent
    // has inherited Windows ACLs and is not itself an admissible host store.
    client = await NativeHostClient.open(join(root, "state"));
    const requests = Array.from({ length: 64 }, (_, index) => client.request(index % 2 === 0
      ? { kind: "inspect" }
      : { kind: "list-machines", after: null, maximum: 1 }));
    await assert.rejects(client.request({ kind: "inspect" }), (error) =>
      error instanceof SandsurfHostError && error.category === "capacity");
    const responses = await Promise.all(requests);
    for (const [index, response] of responses.entries()) {
      assert.equal(response.kind, index % 2 === 0 ? "inspection" : "machines");
    }
    assert.equal((await client.request({ kind: "inspect" })).kind, "inspection");
  } finally {
    if (client !== undefined) { await client.stopService(); await client.stopSupervisor(); }
    await rm(root, { recursive: true, force: true });
  }
});
