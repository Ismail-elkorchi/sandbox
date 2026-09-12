import assert from "node:assert/strict";
import { existsSync, realpathSync } from "node:fs";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { createSandbox } from "../dist/index.js";
import {
  hostPath,
  hostPolicy,
  hostResource,
  readAccess,
  readWriteAccess,
} from "./helpers.mjs";

const linux = process.platform === "linux";

test("Linux host layout confines files and networking without user namespaces", { skip: !linux }, async () => {
  const workspace = await mkdtemp(join(tmpdir(), "sandbox-host-layout-"));
  const executable = realpathSync(process.execPath);
  const runtimeRoots = ["/bin", "/usr", "/lib", "/lib64"]
    .filter(existsSync)
    .map((path, index) =>
      hostResource(`runtime-${String(index)}`, path, readAccess("allow"), [
        "executable",
        "interpreter",
        "library",
      ]));
  if (!["/bin", "/usr", "/lib", "/lib64"].some((root) => executable.startsWith(`${root}/`))) {
    runtimeRoots.push(
      hostResource("node-runtime", dirname(executable), readAccess("allow"), ["executable"]),
    );
  }
  if (existsSync("/etc/ssl")) {
    runtimeRoots.push(hostResource("tls-runtime", "/etc/ssl", readAccess(), ["data"]));
  }
  const policy = hostPolicy([
    ...runtimeRoots,
    hostResource("workspace", workspace, readWriteAccess(), ["data"]),
  ]);
  const sandbox = await createSandbox();
  try {
    const support = await sandbox.probe({ isolation: { kind: "process" }, policy, requirements: {} });
    const implementation = support.implementations.find(
      (candidate) => candidate.identity.id === "linux-landlock-v1",
    );
    assert.equal(implementation?.eligibility.state, "eligible");

    const script = [
      "const fs = require('node:fs');",
      "const net = require('node:net');",
      "void (async () => {",
      "  fs.writeFileSync('created.txt', 'created');",
      "  let hostReadDenied = false;",
      "  try { fs.readFileSync('/etc/passwd'); } catch { hostReadDenied = true; }",
      "  const socketDenied = await new Promise((resolve) => {",
      "    const socket = net.connect(9, '127.0.0.1');",
      "    socket.once('error', () => resolve(true));",
      "    socket.once('connect', () => { socket.destroy(); resolve(false); });",
      "  });",
      "  console.log(JSON.stringify({ hostReadDenied, socketDenied }));",
      "})();",
    ].join("\n");
    const result = await sandbox.run({
      isolation: { kind: "process" },
      policy,
      requirements: {},
      process: {
        executable: hostPath(executable),
        args: ["-e", script],
        cwd: hostPath(workspace),
        environment: { set: { PATH: "/usr/bin:/bin" } },
      },
    });
    assert.deepEqual(result.termination, { reason: "exit", code: 0 });
    assert.deepEqual(JSON.parse(result.stdout.toString("utf8")), {
      hostReadDenied: true,
      socketDenied: true,
    });
    assert.equal(await readFile(join(workspace, "created.txt"), "utf8"), "created");
    assert.equal(result.enforcement.implementation.id, "linux-landlock-v1");
    assert.equal(
      result.enforcement.guarantees.find(
        (fact) => fact.id === "filesystem.resource-identities-bound",
      )?.status,
      "unsatisfied",
    );

    const escaped = join(workspace, "escaped.txt");
    const childProgram = `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(escaped)}, 'escaped'), 300)`;
    const terminated = await sandbox.run({
      isolation: { kind: "process" },
      policy,
      requirements: {},
      resources: { wallTime: { enforcement: "hard", scope: "process", value: 100 } },
      process: {
        executable: hostPath(executable),
        args: ["-e", [
          "const { spawn } = require('node:child_process');",
          `const child = spawn(process.execPath, ['-e', ${JSON.stringify(childProgram)}], { detached: true, stdio: 'ignore' });`,
          "child.on('error', () => {});",
          "setInterval(() => {}, 1000);",
        ].join("\n")],
        cwd: hostPath(workspace),
        environment: { set: {} },
      },
    });
    assert.deepEqual(terminated.termination, { reason: "timeout" });
    await delay(400);
    await assert.rejects(access(escaped));

    const stronger = await sandbox.probe({
      isolation: { kind: "process" },
      policy,
      requirements: { additional: ["runtime.executable-identity-bound"] },
    });
    assert.equal(
      stronger.implementations.find((candidate) => candidate.identity.id === "linux-landlock-v1")
        ?.eligibility.state,
      "ineligible",
    );
  } finally {
    await sandbox.dispose();
    await rm(workspace, { recursive: true, force: true });
  }
});
