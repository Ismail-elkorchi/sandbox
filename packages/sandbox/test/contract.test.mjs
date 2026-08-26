import assert from "node:assert/strict";
import { access, mkdtemp, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  SandboxDigestMismatchError,
  SandboxPolicyError,
  SandboxPreparationExpiredError,
  SandboxRequirementError,
  SandboxUnsupportedError,
  createSandbox,
} from "../dist/index.js";
import { baseOptions, withSandbox } from "./helpers.mjs";

const linuxHost = process.platform === "linux";
const linux = linuxHost && await (async () => {
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

test("probe reports Linux backend availability from functional evidence", { skip: !linuxHost }, async () => {
  await withSandbox(async (sandbox) => {
    const support = await sandbox.probe();
    assert.equal(support.protocol.major, 1);
    const backend = support.backends.find((candidate) => candidate.id === "linux-namespace-v1");
    assert.ok(backend);
    assert.equal(backend.stability, "stable");
    assert.equal(backend.available, linux);
    if (backend.available) {
      assert.equal(backend.capabilities.namespaces, true);
      assert.equal(backend.capabilities.landlockAbi >= 1, true);
      assert.equal(backend.capabilities.seccomp, true);
    } else {
      assert.equal(Array.isArray(backend.capabilities.errors), true);
    }
  });
});

test("invalid target paths fail in Rust before target execution", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    await assert.rejects(
      sandbox.prepareRun({
        ...baseOptions(),
        process: { executable: "bin/sh", args: [], cwd: "/" },
      }),
      (error) => error instanceof SandboxPolicyError && error.data.targetExecuted === false,
    );
  });
});

test("digest mismatch consumes preparation and executes no target", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions(),
      process: { executable: "/bin/true", cwd: "/" },
    });
    await assert.rejects(
      prepared.start({ policyDigest: "0".repeat(64), executionDigest: prepared.executionDigest }),
      SandboxDigestMismatchError,
    );
    await assert.rejects(
      prepared.start({ policyDigest: prepared.policyDigest, executionDigest: prepared.executionDigest }),
    );
  });
});

test("hardware VMs fail closed and malformed managed-network rules are rejected", { skip: !linux }, async () => {
  const sandbox = await createSandbox();
  try {
    await assert.rejects(sandbox.probe({ isolation: "hardware-vm" }), SandboxUnsupportedError);
    await assert.rejects(
      sandbox.prepareRun({
        ...baseOptions(),
        policy: {
          filesystem: { runtime: { kind: "system" }, grants: [] },
          network: {
            mode: "managed",
            allow: [{ transport: "tcp", destination: { kind: "dns", name: "*.invalid" }, ports: [443] }],
          },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
        process: { executable: "/bin/true", cwd: "/" },
      }),
      SandboxPolicyError,
    );
  } finally {
    await sandbox.dispose();
  }
});

test("unavailable hard aggregate limits are reported and required atomically", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const support = await sandbox.probe();
    const backend = support.backends[0];
    if (backend?.capabilities.cgroupMemory === false) {
      await assert.rejects(
        sandbox.prepareRun({
          ...baseOptions(),
          requirements: { boundary: "os-process", required: ["resource.memory-hard"] },
          process: { executable: "/bin/true", cwd: "/" },
        }),
        SandboxRequirementError,
      );
    }
  });
});

test("cleanup operations are idempotent", { skip: !linux }, async () => {
  const sandbox = await createSandbox();
  const prepared = await sandbox.prepareRun({
    ...baseOptions(),
    process: { executable: "/bin/true", cwd: "/" },
  });
  await prepared.cancel();
  await prepared.cancel();
  await sandbox.dispose();
  await sandbox.dispose();
});

test("prepared authority expires and cannot execute", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions({ preparedTtlMs: 10 }),
      process: { executable: "/bin/true", cwd: "/" },
    });
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
    await assert.rejects(
      prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      }),
      SandboxPreparationExpiredError,
    );
  });
});

test("unrestricted host networking does not overclaim abstract IPC isolation", { skip: !linux }, async () => {
  await withSandbox(async (sandbox) => {
    const prepared = await sandbox.prepareRun({
      ...baseOptions({
        policy: {
          filesystem: { runtime: { kind: "system" }, grants: [] },
          network: { mode: "unrestricted", acknowledgement: "network-is-not-restricted" },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
        requirements: { boundary: "os-process", required: [] },
      }),
      process: { executable: "/bin/true", cwd: "/" },
    });
    const ipc = prepared.enforcement.guarantees.find((fact) => fact.id === "ipc.host-endpoints-hidden-outside-grants");
    assert.equal(ipc?.status, "unsatisfied");
    await prepared.cancel();
  });
});

test("preparation and cancellation never execute target code", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-never-ran-"));
  const sentinel = join(workspace, "sentinel");
  const sandbox = await createSandbox();
  try {
    const prepared = await sandbox.prepareRun({
      ...baseOptions({
        policy: {
          filesystem: {
            runtime: { kind: "system" },
            grants: [{ hostPath: workspace, targetPath: "/workspace", access: "read-write" }],
          },
          network: { mode: "none" },
          process: { hostProcesses: "deny", hostIpc: "deny" },
        },
      }),
      process: {
        executable: "/bin/sh",
        args: ["-c", "printf executed > /workspace/sentinel"],
        cwd: "/workspace",
      },
    });
    await assert.rejects(access(sentinel, constants.F_OK));
    await prepared.cancel();
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
    await assert.rejects(access(sentinel, constants.F_OK));
  } finally {
    await sandbox.dispose();
    await rm(workspace, { recursive: true, force: true });
  }
});
