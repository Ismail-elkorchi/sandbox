import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import { access, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { createSandbox } from "../dist/index.js";
import { hostPath, hostPolicy, hostResource, readAccess, readWriteAccess } from "./helpers.mjs";

const windows = process.platform === "win32";

test("Windows AppContainer confines a native process and owns its descendant tree", { skip: !windows }, async () => {
  const parent = await mkdtemp(join(tmpdir(), "sandbox-windows-"));
  const workspace = join(parent, "workspace");
  const secret = join(parent, "secret.txt");
  await mkdir(workspace);
  await writeFile(secret, "secret");
  const network = await loopbackServer();
  const runtime = join(parent, "runtime");
  await mkdir(runtime);
  const runtimeExecutable = join(runtime, "node.exe");
  await copyFile(realpathSync(process.execPath), runtimeExecutable);
  const executable = realpathSync(runtimeExecutable);
  const systemRoot = process.env.SystemRoot;
  assert.ok(systemRoot);
  const policy = hostPolicy([
    hostResource("node-runtime", runtime, readAccess("allow"), [
      "executable",
      "interpreter",
      "loader",
      "library",
    ]),
    hostResource("windows-runtime", realpathSync(systemRoot), readAccess("allow"), [
      "executable",
      "interpreter",
      "loader",
      "library",
    ]),
    hostResource("workspace", workspace, readWriteAccess(), ["data"]),
  ]);
  const sandbox = await createSandbox();
  try {
    const support = await sandbox.probe({ isolation: { kind: "process" }, policy, requirements: {} });
    const implementation = support.implementations.find(
      (candidate) => candidate.identity.id === "windows-appcontainer-v1",
    );
    assert.equal(implementation?.stability, "stable");
    assert.equal(
      implementation?.eligibility.state,
      "eligible",
      implementation?.eligibility.unmet.join("; "),
    );

    const result = await sandbox.run({
      isolation: { kind: "process" },
      policy,
      requirements: {},
      resources: { wallTime: { enforcement: "hard", scope: "process", value: 3_000 } },
      process: {
        executable: hostPath(executable),
        args: ["-e", [
          "const fs = require('node:fs');",
          "const net = require('node:net');",
          "fs.writeFileSync('created.txt', 'created');",
          `let secretDenied = false; try { fs.readFileSync(${JSON.stringify(secret)}); } catch { secretDenied = true; }`,
          "let reported = false; let timer;",
          "const report = (socketDenied) => { if (reported) return; reported = true; clearTimeout(timer); socket.destroy(); console.log(JSON.stringify({ secretDenied, socketDenied })); };",
          `const socket = net.connect(${network.port}, '127.0.0.1');`,
          "socket.once('error', () => report(true));",
          "socket.once('connect', () => report(false));",
          "timer = setTimeout(() => report(true), 1_000);",
        ].join("\n")],
        cwd: hostPath(workspace),
        environment: { set: {} },
      },
    });
    assert.deepEqual(
      result.termination,
      { reason: "exit", code: 0 },
      result.stderr.toString("utf8"),
    );
    const createdContent = await readFile(join(workspace, "created.txt"), "utf8").catch(() => undefined);
    assert.notEqual(
      result.stdout.length,
      0,
      JSON.stringify({
        usage: result.usage,
        stderr: result.stderr.toString("utf8"),
        createdContent,
      }),
    );
    assert.deepEqual(JSON.parse(result.stdout.toString("utf8")), {
      secretDenied: true,
      socketDenied: true,
    });
    assert.equal(await readFile(join(workspace, "created.txt"), "utf8"), "created");
    assert.equal(result.enforcement.implementation.id, "windows-appcontainer-v1");

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
          `const child = spawn(process.execPath, ['-e', ${JSON.stringify(childProgram)}], { stdio: 'ignore' });`,
          "child.on('error', () => {});",
          "setInterval(() => {}, 1000);",
        ].join("\n")],
        cwd: hostPath(workspace),
        environment: { set: {} },
      },
    });
    assert.deepEqual(
      terminated.termination,
      { reason: "timeout" },
      terminated.stderr.toString("utf8"),
    );
    await delay(400);
    await assert.rejects(access(escaped));

    const stronger = await sandbox.probe({
      isolation: { kind: "process" },
      policy,
      requirements: { additional: ["runtime.executable-identity-bound"] },
    });
    assert.equal(
      stronger.implementations.find((candidate) => candidate.identity.id === "windows-appcontainer-v1")
        ?.eligibility.state,
      "ineligible",
    );
  } finally {
    await sandbox.dispose();
    await network.close();
    await rm(parent, { recursive: true, force: true });
  }
});

async function loopbackServer() {
  const server = createServer((socket) => socket.end());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return {
    port: address.port,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
