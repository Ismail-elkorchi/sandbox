import assert from "node:assert/strict";
import { existsSync, realpathSync } from "node:fs";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { createSandbox } from "../dist/index.js";
import { hostPath, hostPolicy, hostResource, readAccess, readWriteAccess } from "./helpers.mjs";

const macos = process.platform === "darwin";

test("macOS Seatbelt confines a native process and owns its process group", { skip: !macos }, async () => {
  const createdParent = await mkdtemp(join(tmpdir(), "sandbox-macos-"));
  const parent = realpathSync(createdParent);
  const workspace = join(parent, "workspace");
  const secret = join(parent, "secret.txt");
  await mkdir(workspace);
  await writeFile(secret, "secret");
  const network = await loopbackServer();
  const executable = realpathSync(process.execPath);
  const runtimeRoots = minimalRoots([
    dirname(dirname(executable)),
    "/System",
    "/usr",
    "/Library/Apple",
    "/private/etc",
    "/private/var/db/timezone",
    "/dev",
  ]);
  const policy = hostPolicy([
    ...runtimeRoots.map((root, index) =>
      hostResource(`runtime-${String(index)}`, root, readAccess("allow"), [
        "executable",
        "interpreter",
        "loader",
        "library",
      ])),
    hostResource("workspace", workspace, readWriteAccess(), ["data"]),
  ], {
    process: {
      visibility: "host",
      control: "session",
      termination: { scope: "process-group", graceMs: 50 },
    },
  });
  const sandbox = await createSandbox();
  try {
    const support = await sandbox.probe({ isolation: { kind: "process" }, policy, requirements: {} });
    const implementation = support.implementations.find(
      (candidate) => candidate.identity.id === "darwin-seatbelt-v1",
    );
    assert.equal(implementation?.stability, "stable");
    assert.equal(
      implementation?.eligibility.state,
      "eligible",
      JSON.stringify(implementation?.mechanisms),
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
          "let hostControlDenied = false; try { process.kill(1, 0); } catch { hostControlDenied = true; }",
          "let reported = false; let timer;",
          "const report = (socketDenied) => { if (reported) return; reported = true; clearTimeout(timer); socket.destroy(); console.log(JSON.stringify({ secretDenied, hostControlDenied, socketDenied })); };",
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
    assert.deepEqual(JSON.parse(result.stdout.toString("utf8")), {
      secretDenied: true,
      hostControlDenied: true,
      socketDenied: true,
    });
    assert.equal(await readFile(join(workspace, "created.txt"), "utf8"), "created");
    assert.equal(result.enforcement.implementation.id, "darwin-seatbelt-v1");

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
    assert.deepEqual(terminated.termination, { reason: "timeout" });
    await delay(400);
    await assert.rejects(access(escaped));

    const stronger = await sandbox.probe({
      isolation: { kind: "process" },
      policy,
      requirements: { additional: ["filesystem.resource-identities-bound"] },
    });
    assert.equal(
      stronger.implementations.find((candidate) => candidate.identity.id === "darwin-seatbelt-v1")
        ?.eligibility.state,
      "ineligible",
    );
  } finally {
    await sandbox.dispose();
    await network.close();
    await rm(createdParent, { recursive: true, force: true });
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

function minimalRoots(candidates) {
  const roots = [...new Set(candidates.filter(existsSync).map((candidate) => realpathSync(candidate)))];
  return roots.filter((candidate) => !roots.some((other) => {
    if (other === candidate) return false;
    const path = relative(other, candidate);
    return path !== "" && path !== ".." && !path.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`);
  }));
}
