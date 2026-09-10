import assert from "node:assert/strict";
import test from "node:test";
import {
  SandboxPolicyError,
  SandboxUnsupportedError,
  createSandbox,
} from "../dist/index.js";
import {
  baseOptions,
  hostPath,
  isolatedPath,
  isolatedPolicy,
  linuxImplementationEligible,
  shellProcess,
  withSandbox,
} from "./helpers.mjs";

const linuxHost = process.platform === "linux";
const eligible = await linuxImplementationEligible();

test("probe reports implementation identity, independent mechanisms, and request eligibility", { skip: !linuxHost }, async () => {
  await withSandbox(async (sandbox) => {
    const support = await sandbox.probe({
      isolation: { kind: "process" },
      policy: isolatedPolicy(),
      requirements: {},
    });
    const implementation = support.implementations.find(
      (candidate) => candidate.identity.id === "linux-namespace-v1",
    );
    assert.ok(implementation);
    assert.equal(implementation.boundary, "os-process");
    assert.deepEqual(implementation.filesystem, ["isolated"]);
    assert.match(implementation.identity.conformanceManifestId, /^linux-namespace-v1-/);
    for (const name of [
      "namespace-launcher",
      "network-namespace",
      "landlock",
      "seccomp",
      "cgroup-memory",
      "cgroup-processes",
    ]) {
      assert.ok(implementation.mechanisms[name], name);
      assert.match(implementation.mechanisms[name].state, /^(available|unavailable|error|not-run)$/);
      assert.equal(typeof implementation.mechanisms[name].operation, "string");
    }
    assert.equal(implementation.eligibility.state, eligible ? "eligible" : "ineligible");
  });
});

test("probe evaluates filesystem topology and aggregate limit scope", { skip: !linuxHost }, async () => {
  await withSandbox(async (sandbox) => {
    const hostPolicy = {
      filesystem: { kind: "host", resources: [] },
      network: { mode: "unrestricted", acknowledgement: "network-is-not-restricted" },
      process: {
        visibility: "host",
        control: "host",
        termination: { scope: "process-group", graceMs: 0 },
      },
      ipc: { visibility: "host" },
    };
    const host = await sandbox.probe({ isolation: { kind: "process" }, policy: hostPolicy });
    assert.equal(host.implementations[0].eligibility.state, "ineligible");
    assert.equal(
      host.implementations[0].eligibility.unmet.some((reason) => reason.includes("isolated filesystem")),
      true,
    );

    const aggregate = await sandbox.probe({
      isolation: { kind: "process" },
      policy: isolatedPolicy(),
      resources: { wallTime: { enforcement: "hard", scope: "session", value: 1_000 } },
    });
    assert.equal(aggregate.implementations[0].eligibility.state, "ineligible");
    assert.equal(
      aggregate.implementations[0].eligibility.unmet.some((reason) => reason.includes("session-scoped")),
      true,
    );
  });
});

test("coordinate spaces are validated before execution", { skip: !linuxHost }, async () => {
  await withSandbox(async (sandbox) => {
    await assert.rejects(
      sandbox.prepareRun({
        ...baseOptions(),
        process: {
          executable: hostPath("/bin/true"),
          cwd: isolatedPath("/"),
        },
      }),
      (error) => error instanceof SandboxPolicyError && error.data.targetExecuted === false,
    );
  });
});

test("superseded runtime and grant records are rejected without execution", { skip: !linuxHost }, async () => {
  await withSandbox(async (sandbox) => {
    await assert.rejects(
      sandbox.prepareRun({
        isolation: { kind: "process" },
        policy: {
          filesystem: { runtime: { kind: "system" }, grants: [] },
          network: { mode: "none" },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
        requirements: { boundary: "os-process", required: [] },
        process: { executable: "/bin/true", cwd: "/" },
      }),
      (error) => error instanceof SandboxPolicyError && error.data.targetExecuted === false,
    );
  });
});

test("no eligible implementation rejects preparation before target execution", { skip: !linuxHost }, async () => {
  await withSandbox(async (sandbox) => {
    const options = baseOptions({
      policy: {
        ...isolatedPolicy(),
        process: {
          visibility: "host",
          control: "host",
          termination: { scope: "process-group", graceMs: 0 },
        },
        ipc: { visibility: "host" },
      },
      process: shellProcess(),
    });
    await assert.rejects(
      sandbox.prepareRun(options),
      (error) => error instanceof SandboxUnsupportedError && error.data.targetExecuted === false,
    );
  });
});

test("prepared summaries bind implementation and resource identities", { skip: !eligible }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({ ...baseOptions(), process: shellProcess() });
    assert.equal(prepared.summary.implementation.id, "linux-namespace-v1");
    assert.equal(prepared.summary.filesystem.kind, "isolated");
    assert.equal(prepared.summary.filesystem.resources.length > 0, true);
    assert.equal(
      prepared.summary.filesystem.resources.every((resource) => resource.source.identityDigest.length > 0),
      true,
    );
    assert.deepEqual(prepared.summary.execution.executable.space, "isolated");
    await prepared.cancel();
  });
});
