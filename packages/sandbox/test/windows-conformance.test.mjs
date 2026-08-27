import assert from "node:assert/strict";
import { access, link, mkdtemp, readFile, readdir, realpath, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createServer } from "node:net";
import test from "node:test";
import { createSandbox } from "../dist/index.js";

const supported = process.platform === "win32" && await backendAvailable("windows-appcontainer-v1");

test("Windows preview assigns an exact-handle AppContainer process to a Job before resume", { skip: !supported }, async () => {
  const workspace = await temporaryDirectory("sandbox-windows-");
  const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith("sandbox-appcontainer-")));
  try {
    const executable = await realpath(process.execPath);
    const sandbox = await createSandbox({ allowExperimentalBackends: true });
    try {
      const prepared = await sandbox.prepareRun(options(executable, workspace, [
        "-e",
        "require('fs').writeFileSync(process.argv[1], JSON.stringify({args:process.argv.slice(2),env:Object.keys(process.env).sort()}))",
        join(workspace, "result.json"),
        "one two",
        "$(not-a-shell)",
      ]));
      assert.equal(prepared.enforcement.boundary.backendId, "windows-appcontainer-v1");
      assert.equal(fact(prepared, "runtime.executable-identity-bound"), "unsatisfied");
      const process_ = await prepared.start({
        policyDigest: prepared.policyDigest,
        executionDigest: prepared.executionDigest,
      });
      const result = await process_.wait();
      assert.deepEqual(
        result.termination,
        { reason: "exit", code: 0 },
        result.stderr?.toString("utf8"),
      );
      const observed = JSON.parse(await readFile(join(workspace, "result.json"), "utf8"));
      assert.deepEqual(observed.args, ["one two", "$(not-a-shell)"]);
      assert.deepEqual(observed.env, ["HOME", "LOCALAPPDATA", "SystemRoot", "TEMP", "TMP"]);
      assert.equal(result.cleanup.completed, true);
    } finally {
      await sandbox.dispose();
    }
    const after = (await readdir(tmpdir())).filter((name) => name.startsWith("sandbox-appcontainer-") && !before.has(name));
    assert.deepEqual(after, []);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("Windows preview denies loopback and Job close kills descendants", { skip: !supported }, async () => {
  const workspace = await temporaryDirectory("sandbox-windows-tree-");
  const server = createServer(() => {});
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    const executable = await realpath(process.execPath);
    const sandbox = await createSandbox({ allowExperimentalBackends: true });
    try {
      const result = await sandbox.run(options(executable, workspace, [
        "-e",
        "const f=require('fs');const p=require('child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});f.writeFileSync(process.argv[2],String(p.pid));p.once('error',e=>f.writeFileSync(process.argv[2],`error:${e.code}:${e.errno}`));p.once('exit',c=>f.writeFileSync(process.argv[2],`exit:${c}`));const n=require('net');const c=n.connect(+process.argv[1],'127.0.0.1');c.once('connect',()=>process.exit(91));setInterval(()=>{},1000)",
        String(address.port),
        join(workspace, "pid"),
      ], { wallTimeMs: 3_000, terminationGraceMs: 100 }));
      const descendant = await readFile(join(workspace, "pid"), "utf8");
      assert.deepEqual(
        result.termination,
        { reason: "timeout" },
        `${JSON.stringify(result.termination)}; descendant state: ${descendant}\n${result.stderr?.toString("utf8") ?? ""}`,
      );
      assert.match(descendant, /^\d+$/, `descendant state: ${descendant}`);
      const pid = Number(descendant);
      await new Promise((resolve) => setTimeout(resolve, 150));
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

test("Windows preview rejects hard links, junctions, case collisions, and device-name ambiguity", { skip: !supported }, async () => {
  const workspace = await temporaryDirectory("sandbox-windows-paths-");
  const outside = await temporaryDirectory("sandbox-windows-outside-");
  const executable = await realpath(process.execPath);
  const sandbox = await createSandbox({ allowExperimentalBackends: true });
  try {
    await writeFile(join(outside, "secret"), "preserved");
    const junction = join(workspace, "junction");
    await symlink(outside, junction, "junction");
    await assert.rejects(
      sandbox.prepareRun(options(executable, workspace, ["-e", "process.exit(0)"])),
      (error) => error?.data?.code === "preparation.writable_grant_reparse",
    );
    await unlink(junction);

    await link(join(outside, "secret"), join(workspace, "hardlink"));
    await assert.rejects(
      sandbox.prepareRun(options(executable, workspace, ["-e", "process.exit(0)"])),
      (error) => error?.data?.code === "preparation.writable_grant_hardlink",
    );
    await unlink(join(workspace, "hardlink"));

    const base = options(executable, workspace, ["-e", "process.exit(0)"]);
    await assert.rejects(sandbox.prepareRun({
      ...base,
      policy: {
        ...base.policy,
        filesystem: {
          ...base.policy.filesystem,
          grants: [
            ...base.policy.filesystem.grants,
            { hostPath: workspace, targetPath: workspace.toUpperCase(), access: "read-write" },
          ],
        },
      },
    }));
    await assert.rejects(sandbox.prepareRun({
      ...base,
      policy: {
        ...base.policy,
        filesystem: {
          ...base.policy.filesystem,
          grants: [{ hostPath: workspace, targetPath: `${workspace}\\NUL`, access: "read-write" }],
        },
      },
    }));
    assert.equal(await readFile(join(outside, "secret"), "utf8"), "preserved");
  } finally {
    await sandbox.dispose();
    await rm(workspace, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("Windows preparation cancellation proves the target never ran", { skip: !supported }, async () => {
  const workspace = await temporaryDirectory("sandbox-windows-cancel-");
  try {
    const executable = await realpath(process.execPath);
    const sentinel = join(workspace, "sentinel");
    const sandbox = await createSandbox({ allowExperimentalBackends: true });
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
        "process.complete-tree-termination",
        "resource.wall-time-hard",
        "resource.output-hard",
        "resource.memory-hard",
      ],
    },
    resources,
    process: {
      executable,
      args,
      cwd: workspace,
      environment: { base: "empty" },
    },
  };
}

function fact(prepared, id) {
  return prepared.enforcement.guarantees.find((value) => value.id === id)?.status;
}

async function temporaryDirectory(prefix) {
  return realpath(await mkdtemp(join(tmpdir(), prefix)));
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
