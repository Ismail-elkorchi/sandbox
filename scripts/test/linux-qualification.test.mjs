import assert from "node:assert/strict";
import test from "node:test";
import { blockers } from "../qualify-linux-hardware.ts";

test("native NIC policy denial blocks qualification without becoming a passed prerequisite", () => {
  const mechanisms = Object.fromEntries(["namespace-launcher", "network-namespace", "landlock", "seccomp"].map((key) => [key, { state: "available" }]));
  assert.deepEqual(blockers({ mechanisms }), []);
  mechanisms["network-namespace"] = { state: "unavailable", detail: "TUNSETIFF: Operation not permitted" };
  assert.deepEqual(blockers({ mechanisms }), ["network-namespace: unavailable (TUNSETIFF: Operation not permitted)"]);
  delete mechanisms.landlock;
  assert.ok(blockers({ mechanisms }).includes("landlock: missing observation"));
  assert.throws(() => blockers({}), /invalid native containment probe/u);
});
