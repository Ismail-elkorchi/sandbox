import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { NativeHostClient, SandsurfHostError } from "../dist/native-host.js";

test("native bridge correlates concurrent host responses and bounds admission", async () => {
  const root = await mkdtemp(join(tmpdir(), "sandsurf-bridge-"));
  let client;
  try {
    client = await NativeHostClient.open(root);
    const requests = Array.from({ length: 64 }, (_, index) => client.request(index % 2 === 0
      ? { kind: "inspect" }
      : { kind: "list-sandboxes", after: null, maximum: 1 }));
    await assert.rejects(client.request({ kind: "inspect" }), (error) =>
      error instanceof SandsurfHostError && error.category === "capacity");
    const responses = await Promise.all(requests);
    for (const [index, response] of responses.entries()) {
      assert.equal(response.kind, index % 2 === 0 ? "inspection" : "sandboxes");
    }
    assert.equal((await client.request({ kind: "inspect" })).kind, "inspection");
  } finally {
    if (client !== undefined) await client.stopService();
    await rm(root, { recursive: true, force: true });
  }
});
