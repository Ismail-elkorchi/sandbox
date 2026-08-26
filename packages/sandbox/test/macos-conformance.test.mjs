import assert from "node:assert/strict";
import { access, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createServer } from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";
import { createSandbox } from "../dist/index.js";

const supported = process.platform === "darwin" && await backendAvailable("darwin-seatbelt-v1");
const execFileAsync = promisify(execFile);

test("macOS preview applies Seatbelt before exact argv execution", { skip: !supported }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-macos-"));
  try {
    const executable = await realpath(process.execPath);
    const sandbox = await createSandbox();
    try {
      const prepared = await sandbox.prepareRun(options(executable, workspace, [
        "-e",
        "require('fs').writeFileSync(process.argv[1], process.argv.slice(2).join('|'))",
        join(workspace, "result"),
        "one two",
        "$(not-a-shell)",
      ]));
      assert.equal(prepared.enforcement.boundary.backendId, "darwin-seatbelt-v1");
      assert.equal(fact(prepared, "filesystem.grant-roots-identity-bound"), "unsatisfied");
      assert.equal(fact(prepared, "process.host-enumeration-denied"), "unsatisfied");
      assert.equal(fact(prepared, "ipc.host-endpoints-hidden-outside-grants"), "unsatisfied");
      for (const code of [
        "macos.path-identity",
        "macos.process-namespace",
        "macos.mach-bootstrap-services",
        "macos.desktop-services",
        "macos.local-sockets",
        "macos.process-limit-scope",
      ]) {
        assert.equal(prepared.enforcement.caveats.some((caveat) => caveat.code === code), true, code);
      }
      const process_ = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      assert.deepEqual((await process_.wait()).termination, { reason: "exit", code: 0 });
      assert.equal(await readFile(join(workspace, "result"), "utf8"), "one two|$(not-a-shell)");
    } finally {
      await sandbox.dispose();
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("macOS preview grants only explicit content paths and uses private temporary storage", { skip: !supported }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-macos-fs-"));
  const outside = await mkdtemp(join(tmpdir(), "sandbox-macos-outside-"));
  try {
    const secret = join(outside, "secret");
    const resultPath = join(workspace, "result.json");
    await writeFile(secret, "host-secret");
    const executable = await realpath(process.execPath);
    const sandbox = await createSandbox();
    try {
      const result = await sandbox.run(options(executable, workspace, [
        "-e",
        "const f=require('fs');let denied=false;try{f.readFileSync(process.argv[1])}catch{denied=true}f.writeFileSync(process.argv[2],JSON.stringify({denied,tmp:process.env.TMPDIR,home:process.env.HOME}))",
        secret,
        resultPath,
      ]));
      assert.deepEqual(result.termination, { reason: "exit", code: 0 });
      const observed = JSON.parse(await readFile(resultPath, "utf8"));
      assert.equal(observed.denied, true);
      assert.notEqual(observed.tmp, tmpdir());
      assert.equal(observed.home.includes("sandbox-state-"), true);
      assert.equal(result.cleanup.completed, true);
    } finally {
      await sandbox.dispose();
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("macOS preparation cancellation proves the target never ran", { skip: !supported }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-macos-cancel-"));
  try {
    const executable = await realpath(process.execPath);
    const sentinel = join(workspace, "sentinel");
    const sandbox = await createSandbox();
    try {
      const prepared = await sandbox.prepareRun(options(executable, workspace, [
        "-e",
        "require('fs').writeFileSync(process.argv[1],'ran')",
        sentinel,
      ]));
      await prepared.cancel();
      await assert.rejects(access(sentinel, constants.F_OK));
    } finally {
      await sandbox.dispose();
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("SIGKILL of the macOS Rust runtime revokes the guardian lifeline", { skip: !supported }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-macos-crash-"));
  const before = new Set(await directChildren(process.pid));
  const sandbox = await createSandbox();
  try {
    const executable = await realpath(process.execPath);
    const pidPath = join(workspace, "pid");
    const prepared = await sandbox.prepareRun(options(executable, workspace, [
      "-e",
      "require('fs').writeFileSync(process.argv[1],String(process.pid));setInterval(()=>{},1000)",
      pidPath,
    ], { wallTimeMs: 30_000 }));
    const target = await prepared.start({
      policyDigest: prepared.policyDigest,
      executionDigest: prepared.executionDigest,
    });
    await waitUntil(() => access(pidPath, constants.F_OK).then(() => true, () => false), 5_000);
    const runtimePid = (await directChildren(process.pid)).find((pid) => !before.has(pid));
    assert.ok(runtimePid, "runtime child PID must be discoverable");
    const owned = await descendants(runtimePid);
    assert.equal(owned.length >= 2, true, "guardian and target must exist");
    process.kill(runtimePid, "SIGKILL");
    await assert.rejects(target.wait());
    await waitUntil(
      async () => (await Promise.all(owned.map(processExists))).every((exists) => !exists),
      5_000,
    );
  } finally {
    await sandbox.dispose();
    await rm(workspace, { recursive: true, force: true });
  }
});

test("macOS preview denies loopback and kills the process group on timeout", { skip: !supported }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-macos-tree-"));
  const server = createServer(() => {});
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    const executable = await realpath(process.execPath);
    const sandbox = await createSandbox();
    try {
      const result = await sandbox.run(options(executable, workspace, [
        "-e",
        "const n=require('net');const c=n.connect(+process.argv[1],'127.0.0.1');c.once('connect',()=>process.exit(91));c.once('error',()=>{const p=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:false});require('fs').writeFileSync(process.argv[2],String(p.pid));setInterval(()=>{},1000)})",
        String(address.port),
        join(workspace, "pid"),
      ], { wallTimeMs: 500, terminationGraceMs: 100 }));
      assert.equal(result.termination.reason, "timeout");
      const pid = Number(await readFile(join(workspace, "pid"), "utf8"));
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.throws(() => process.kill(pid, 0));
      assert.equal(result.cleanup.completed, true);
    } finally {
      await sandbox.dispose();
    }
  } finally {
    server.close();
    await rm(workspace, { recursive: true, force: true });
  }
});

function options(executable, workspace, args, resources = {}) {
  return {
    isolation: { kind: "process" },
    policy: {
      filesystem: {
        runtime: { kind: "system" },
        grants: [
          { hostPath: dirname(executable), targetPath: dirname(executable), access: "read", execution: "allow" },
          { hostPath: workspace, targetPath: workspace, access: "read-write" },
        ],
      },
      network: { mode: "none" },
      process: { hostProcesses: "deny", hostIpc: "deny" },
    },
    requirements: {
      boundary: "os-process",
      allowExperimentalBackend: true,
      required: [
        "runtime.setup-before-exec",
        "runtime.no-ambient-environment",
        "runtime.no-ambient-handles",
        "filesystem.content-write-confined",
        "network.no-external-connect",
        "network.no-external-listen",
        "network.no-host-loopback",
        "resource.wall-time-hard",
        "resource.output-hard",
      ],
    },
    resources,
    process: { executable, args, cwd: workspace, environment: { base: "empty" } },
  };
}

function fact(prepared, id) {
  return prepared.enforcement.guarantees.find((value) => value.id === id)?.status;
}

async function backendAvailable(id) {
  const sandbox = await createSandbox();
  try {
    return (await sandbox.probe()).backends.some((backend) => backend.id === id && backend.available);
  } catch {
    return false;
  } finally {
    await sandbox.dispose();
  }
}

async function processTable() {
  const { stdout } = await execFileAsync("/bin/ps", ["-axo", "pid=,ppid="], { encoding: "utf8" });
  return stdout.trim().split("\n").flatMap((line) => {
    const [pid, parent] = line.trim().split(/\s+/u).map(Number);
    return Number.isInteger(pid) && Number.isInteger(parent) ? [{ pid, parent }] : [];
  });
}

async function directChildren(parent) {
  return (await processTable()).filter((entry) => entry.parent === parent).map((entry) => entry.pid);
}

async function descendants(root) {
  const table = await processTable();
  const result = [];
  const pending = [root];
  while (pending.length > 0) {
    const parent = pending.shift();
    for (const entry of table) {
      if (entry.parent === parent) {
        result.push(entry.pid);
        pending.push(entry.pid);
      }
    }
  }
  return result;
}

async function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitUntil(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("condition did not become true before deadline");
}
