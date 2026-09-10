import assert from "node:assert/strict";
import { access, chmod, copyFile, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import test from "node:test";
import { createSandbox, SandboxRuntimeIntegrityError } from "../dist/index.js";
import {
  applyHardwareVmChangeSet,
  hardwareVmExtension,
  minimalHardwareVmImage,
} from "../../sandbox-hardware-vm/dist/index.js";

const targetBinary = process.env.SANDBOX_VM_CONFORMANCE_TARGET
  ?? resolve("target/x86_64-unknown-linux-musl/release/sandbox-conformance-target");
const supported = process.platform === "linux" && process.arch === "x64"
  && await accessible("/dev/kvm", constants.R_OK | constants.W_OK)
  && await accessible(targetBinary, constants.R_OK | constants.X_OK);

test("hardware VM verifies boot, imports explicitly, hides control, exports artifacts, and applies changes explicitly", { skip: !supported, timeout: 60_000 }, async () => {
  const workspace = await workspaceWithTarget("files");
  const recovery = await mkdtemp(join(tmpdir(), "sandbox-vm-recovery-"));
  const hostOnly = await mkdtemp(join(tmpdir(), "sandbox-vm-host-only-"));
  try {
    await writeFile(join(workspace, "input"), "old");
    const hostSecret = join(hostOnly, "must-not-be-visible");
    await writeFile(hostSecret, "host-secret");
    const sandbox = await vmSandbox(workspace);
    let result;
    try {
      result = await sandbox.run(vmOptions(workspace, {
        executable: "/workspace/target",
        args: ["vm-files", hostSecret],
        cwd: "/workspace",
        artifacts: { paths: ["/workspace/output", "/workspace/created"], maxBytes: 1024 * 1024 },
        changeSet: { maxBytes: 4 * 1024 * 1024 },
      }));
    } finally {
      await sandbox.dispose();
    }
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    assert.equal(result.enforcement.boundary.kind, "hardware-virtualized");
    assert.equal(result.cleanup.completed, true);
    assert.equal(result.artifacts?.files.some((entry) => entry.path.path.endsWith("/output") && Buffer.from(entry.contentHex, "hex").toString() === "artifact"), true);
    assert.equal(await readFile(join(workspace, "input"), "utf8"), "old", "VM completion must not mutate the host");
    assert.equal(result.changeSets?.length, 1);
    const report = await applyHardwareVmChangeSet({
      rootPath: workspace,
      recoveryDirectory: recovery,
      changeSet: result.changeSets[0].changeSet,
    });
    assert.equal(report.applied > 0, true);
    assert.equal(await readFile(join(workspace, "renamed"), "utf8"), "old");
    assert.equal(await readFile(join(workspace, "created/nested"), "utf8"), "nested");
    await assert.rejects(
      applyHardwareVmChangeSet({ rootPath: workspace, recoveryDirectory: recovery, changeSet: result.changeSets[0].changeSet }),
      (error) => error?.kind === "conflict",
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(recovery, { recursive: true, force: true });
    await rm(hostOnly, { recursive: true, force: true });
  }
});

test("hardware VM sessions execute sequentially and clean the VMM", { skip: !supported, timeout: 60_000 }, async () => {
  const workspace = await workspaceWithTarget("session");
  const sandbox = await vmSandbox(workspace);
  try {
    const options = vmOptions(workspace);
    const prepared = await sandbox.prepareSession(options);
    const session = await prepared.activate({ policyDigest: prepared.policyDigest });
    try {
      const first = await session.run({ executable: { space: "isolated", path: "/workspace/target" }, args: ["echo", "one two"], cwd: { space: "isolated", path: "/workspace" } });
      const second = await session.run({ executable: { space: "isolated", path: "/workspace/target" }, args: ["echo", "two"], cwd: { space: "isolated", path: "/workspace" } });
      assert.equal(first.stdout?.toString(), "one two");
      assert.equal(second.stdout?.toString(), "two");
      const daemon = await session.run({ executable: { space: "isolated", path: "/workspace/target" }, args: ["daemon-sentinel"], cwd: { space: "isolated", path: "/workspace" } });
      assert.deepEqual(daemon.termination, { reason: "exit", code: 0 });
      const reaped = await session.run({ executable: { space: "isolated", path: "/workspace/target" }, args: ["sentinel-absent"], cwd: { space: "isolated", path: "/workspace" } });
      assert.deepEqual(reaped.termination, { reason: "exit", code: 0 });
    } finally {
      await session.close();
    }
  } finally {
    await sandbox.dispose();
    await rm(workspace, { recursive: true, force: true });
  }
});

test("hardware VM starts before stdin closes and streams binary-safe I/O", { skip: !supported, timeout: 60_000 }, async () => {
  const workspace = await workspaceWithTarget("streams");
  const sandbox = await vmSandbox(workspace);
  try {
    const prepared = await sandbox.prepareRun(vmOptions(workspace, {
      executable: "/workspace/target",
      args: ["interactive"],
      cwd: "/workspace",
      stdin: "pipe",
      stdout: "pipe",
    }));
    const process_ = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
    const output = [];
    process_.stdout.on("data", (chunk) => output.push(Buffer.from(chunk)));
    await waitForOutput(output, "ready", 5_000);
    assert.equal(process_.stdin.write(Buffer.from([0xa5])), true);
    process_.stdin.end();
    const result = await process_.wait();
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    assert.equal(Buffer.concat(output).toString(), "ready-165");
    assert.equal(result.usage.stdoutBytes, 9);
  } finally {
    await sandbox.dispose();
    await rm(workspace, { recursive: true, force: true });
  }
});

test("hardware VM managed networking permits only brokered rules and reports denials", { skip: !supported, timeout: 90_000 }, async () => {
  const workspace = await workspaceWithTarget("network");
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("data", () => socket.end("HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nvm-network-ok"));
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    const port = address.port;
    const sandbox = await vmSandbox(workspace);
    try {
      const allowed = await sandbox.run(vmOptions(workspace, {
        executable: "/workspace/target",
        args: ["proxy-get", `http://127.0.0.1:${port}/`],
        cwd: "/workspace",
      }, [{ transport: "tcp", destination: { kind: "ip", cidr: "127.0.0.1/32" }, ports: [port] }]));
      assert.deepEqual(allowed.termination, { reason: "exit", code: 0 });
      assert.equal(allowed.usage.networkConnections, 1);

      const direct = await sandbox.run(vmOptions(workspace, {
        executable: "/workspace/target",
        args: ["direct-denied", `127.0.0.1:${port}`],
        cwd: "/workspace",
      }, [{ transport: "tcp", destination: { kind: "ip", cidr: "127.0.0.1/32" }, ports: [port] }]));
      assert.deepEqual(direct.termination, { reason: "exit", code: 0 });

      const denied = await sandbox.run(vmOptions(workspace, {
        executable: "/workspace/target",
        args: ["proxy-get", `http://127.0.0.1:${port}/`],
        cwd: "/workspace",
      }, []));
      assert.notDeepEqual(denied.termination, { reason: "exit", code: 0 });
      assert.equal(denied.violations.some((violation) => violation.kind === "network-denied"), true);
    } finally {
      await sandbox.dispose();
    }
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolveClose) => server.close(resolveClose));
    await rm(workspace, { recursive: true, force: true });
  }
});

test("hardware VM extension and image registration fail closed on digest mismatch", { skip: process.platform !== "linux" || process.arch !== "x64" }, async () => {
  const registration = hardwareVmExtension();
  await assert.rejects(
    createSandbox({ extensions: [{ ...registration, descriptorDigest: "0".repeat(64) }] }),
    SandboxRuntimeIntegrityError,
  );
});

test("SIGKILL of the VM runtime terminates the VMM tree and the next probe recovers abandoned state", { skip: !supported, timeout: 90_000 }, async () => {
  const workspace = await workspaceWithTarget("runtime-crash");
  const beforeChildren = new Set(await directChildren(process.pid));
  const beforeState = new Set(await vmStateRoots());
  const sandbox = await vmSandbox(workspace);
  try {
    const prepared = await sandbox.prepareRun(vmOptions(workspace, {
      executable: "/workspace/target",
      args: ["interactive"],
      cwd: "/workspace",
      stdin: "pipe",
      stdout: "pipe",
    }));
    const target = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
    const output = [];
    target.stdout.on("data", (chunk) => output.push(Buffer.from(chunk)));
    await waitForOutput(output, "ready", 5_000);
    const runtimePid = (await directChildren(process.pid)).find((pid) => !beforeChildren.has(pid));
    assert.ok(runtimePid, "VM runtime child PID must be discoverable");
    const ownedTree = await descendants(runtimePid);
    assert.equal(ownedTree.length >= 2, true, "VMM launcher tree must exist");
    process.kill(runtimePid, "SIGKILL");
    await assert.rejects(target.wait());
    await waitUntil(async () => {
      const remaining = await Promise.all(ownedTree.map(processExists));
      return remaining.every((exists) => !exists);
    }, 5_000);
    const abandoned = (await vmStateRoots()).filter((path) => !beforeState.has(path));
    assert.equal(abandoned.length >= 1, true, "the killed runtime must leave recoverable state");
    const recoverySandbox = await vmSandbox(workspace);
    await recoverySandbox.dispose();
    await waitUntil(async () => {
      const remaining = await Promise.all(abandoned.map((path) => accessible(path, constants.F_OK)));
      return remaining.every((exists) => !exists);
    }, 5_000);
  } finally {
    await sandbox.dispose();
    await rm(workspace, { recursive: true, force: true });
  }
});

async function vmSandbox(workspace) {
  const sandbox = await createSandbox({ allowExperimentalImplementations: true, extensions: [hardwareVmExtension()] });
  const probeOptions = vmOptions(workspace);
  const support = await sandbox.probe({
    isolation: probeOptions.isolation,
    policy: probeOptions.policy,
    requirements: probeOptions.requirements,
    resources: probeOptions.resources,
  });
  assert.equal(support.implementations.some((implementation) =>
    implementation.identity.id === "linux-firecracker-v1"
      && implementation.eligibility.state === "eligible"), true);
  return sandbox;
}

function vmOptions(workspace, process, managedRules) {
  return {
    isolation: { kind: "hardware-vm", image: minimalHardwareVmImage(), filesystemTransport: "import" },
    policy: {
      filesystem: {
        kind: "isolated",
        resources: [{
          id: "workspace",
          source: { space: "host", path: workspace },
          target: { space: "isolated", path: "/workspace" },
          access: {
            content: "read-write",
            directoryEntries: "read-write",
            metadata: "read-write",
            execution: "allow",
          },
          purposes: ["executable", "data"],
        }],
      },
      network: managedRules === undefined ? { mode: "none" } : { mode: "managed", allow: managedRules },
      process: {
        visibility: "session",
        control: "session",
        termination: { scope: "descendant-tree", graceMs: 100 },
      },
      ipc: { visibility: "session" },
    },
    requirements: {
      allowExperimentalImplementations: true,
    },
    resources: {
      wallTime: { enforcement: "hard", scope: "process", value: 10_000 },
      memory: { enforcement: "hard", scope: "descendant-tree", value: 256 * 1024 * 1024 },
      processCount: { enforcement: "hard", scope: "descendant-tree", value: 16 },
    },
    ...(process === undefined ? {} : {
      process: {
        ...process,
        executable: { space: "isolated", path: process.executable },
        cwd: { space: "isolated", path: process.cwd },
        ...(process.artifacts === undefined ? {} : {
          artifacts: {
            ...process.artifacts,
            paths: process.artifacts.paths.map((path) => ({ space: "isolated", path })),
          },
        }),
        ...(process.changeSet === undefined ? {} : {
          changeSet: {
            ...process.changeSet,
            root: { space: "isolated", path: "/workspace" },
          },
        }),
      },
    }),
  };
}

async function workspaceWithTarget(name) {
  const workspace = await mkdtemp(join(tmpdir(), `sandbox-vm-${name}-`));
  await copyFile(targetBinary, join(workspace, "target"));
  await chmod(join(workspace, "target"), 0o755);
  return workspace;
}

async function accessible(path, mode) {
  try {
    await access(path, mode);
    return true;
  } catch {
    return false;
  }
}

async function waitForOutput(chunks, expected, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (!Buffer.concat(chunks).toString().includes(expected)) {
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${expected}`);
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 5));
  }
}

async function vmStateRoots() {
  return (await readdir(tmpdir(), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("vm-state-"))
    .map((entry) => join(tmpdir(), entry.name));
}

async function directChildren(pid) {
  try {
    const value = await readFile(`/proc/${pid}/task/${pid}/children`, "utf8");
    return value.trim() === "" ? [] : value.trim().split(/\s+/u).map(Number);
  } catch {
    return [];
  }
}

async function descendants(rootPid) {
  const values = [];
  const pending = [rootPid];
  while (pending.length > 0) {
    const parent = pending.shift();
    if (parent === undefined) break;
    const children = await directChildren(parent);
    values.push(...children);
    pending.push(...children);
  }
  return values;
}

function processExists(pid) {
  return accessible(`/proc/${pid}`, constants.F_OK);
}

async function waitUntil(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
  }
  assert.fail("condition did not become true before its deadline");
}
