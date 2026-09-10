import assert from "node:assert/strict";
import test from "node:test";
import { createSandbox } from "../dist/index.js";

const windows = process.platform === "win32";

test("Windows reports its concrete preview implementation without overclaiming eligibility", { skip: !windows }, async () => {
  const sandbox = await createSandbox({ allowExperimentalImplementations: true });
  try {
    const policy = {
      filesystem: { kind: "host", resources: [] },
      network: { mode: "none" },
      process: {
        visibility: "session",
        control: "session",
        termination: { scope: "descendant-tree", graceMs: 100 },
      },
      ipc: { visibility: "session" },
    };
    const support = await sandbox.probe({
      isolation: { kind: "process" },
      policy,
      requirements: { allowExperimentalImplementations: true },
    });
    const implementation = support.implementations.find(
      (candidate) => candidate.identity.id === "windows-appcontainer-v1",
    );
    assert.ok(implementation);
    assert.equal(implementation.stability, "experimental");
    assert.deepEqual(implementation.filesystem, ["host"]);
    assert.equal(implementation.eligibility.state, "ineligible");
    assert.equal(
      implementation.eligibility.unmet.includes("runtime.executable-identity-bound"),
      true,
    );
  } finally {
    await sandbox.dispose();
  }
});
