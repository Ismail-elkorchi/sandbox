import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSandbox, openSandboxExecutionRepository } from "@ismail-elkorchi/sandbox";

const host = (path) => ({ space: "host", path });
const isolated = (path) => ({ space: "isolated", path });
const access = (write = false, execution = "deny") => ({
  content: write ? "read-write" : "read",
  directoryEntries: write ? "read-write" : "read",
  metadata: write ? "read-write" : "read",
  execution,
});
const resource = (id, source, target, resourceAccess, purposes) => ({
  id,
  source: host(source),
  target: isolated(target),
  access: resourceAccess,
  purposes,
});
const runtimeResources = [
  ["bin", "/bin", "executable"],
  ["usr-bin", "/usr/bin", "executable"],
  ["lib", "/lib", "library"],
  ["lib64", "/lib64", "loader"],
  ["usr-lib", "/usr/lib", "library"],
  ["usr-lib64", "/usr/lib64", "library"],
].filter((entry) => existsSync(entry[1])).map(([id, path, purpose]) =>
  resource(id, path, path, access(false, "allow"), [purpose, "interpreter"]));

const root = await mkdtemp(join(tmpdir(), "sandbox-packed-consumer-"));
const workspace = join(root, "workspace");
const outside = join(root, "outside");
const repositoryDirectory = join(root, "repository");
await import("node:fs/promises").then(({ mkdir }) => Promise.all([mkdir(workspace), mkdir(outside)]));
await writeFile(join(workspace, "input"), "allowed");
await writeFile(join(outside, "secret"), "host-secret");

const policy = {
  filesystem: {
    kind: "isolated",
    resources: [
      ...runtimeResources,
      resource("workspace", workspace, "/workspace", access(true), ["data"]),
    ],
  },
  network: { mode: "none" },
  process: {
    visibility: "session",
    control: "session",
    termination: { scope: "descendant-tree", graceMs: 100 },
  },
  ipc: { visibility: "session" },
};
const options = {
  isolation: { kind: "process" },
  policy,
  requirements: {},
};
const shell = (script, extra = {}) => ({
  executable: isolated("/bin/sh"),
  args: ["-c", script],
  cwd: isolated("/workspace"),
  ...extra,
});

const sandbox = await createSandbox();
try {
  const support = await sandbox.probe(options);
  const implementation = support.implementations.find((candidate) =>
    candidate.identity.id === "linux-namespace-v1");
  assert.ok(implementation, "packed runtime must report its implementation identity");
  if (implementation.eligibility.state !== "eligible") {
    throw new Error(`packed functional checks unavailable: ${JSON.stringify(implementation.eligibility.unmet)}`);
  } else {
    const allowed = await sandbox.run({
      ...options,
      process: shell(`test "$(cat input)" = allowed && ! cat ${JSON.stringify(join(outside, "secret"))} >/dev/null 2>&1 && printf packed`),
    });
    assert.deepEqual(allowed.termination, { reason: "exit", code: 0 });
    assert.equal(allowed.stdout.toString(), "packed");
    assert.equal(allowed.cleanup.completed, true);

    const bounded = await sandbox.run({
      ...options,
      resources: { output: { enforcement: "hard", scope: "process", value: 1024 } },
      process: shell("while :; do printf 1234567890; done"),
    });
    assert.deepEqual(bounded.termination, { reason: "output-limit" });
    assert.equal(bounded.stdout.byteLength, 1024);
    assert.equal(bounded.usage.stdoutBytes + bounded.usage.stderrBytes > 1024, true);
    assert.equal(bounded.cleanup.completed, true);

    const preparedSession = await sandbox.prepareSession(options);
    const session = await preparedSession.activate({ policyDigest: preparedSession.policyDigest });
    try {
      const first = await session.run(shell("printf one"));
      const second = await session.run(shell("printf two"));
      assert.equal(first.stdout.toString(), "one");
      assert.equal(second.stdout.toString(), "two");
    } finally {
      await session.close();
    }

    let repository = await openSandboxExecutionRepository({ directory: repositoryDirectory });
    const request = {
      executionId: "packed-recovery",
      run: {
        ...options,
        resources: { output: { enforcement: "hard", scope: "process", value: 1024 * 1024 } },
        process: shell("printf detached", { stdout: "pipe" }),
      },
    };
    const prepared = await repository.prepare(request, { waitMs: 5000 });
    assert.equal(prepared.kind, "prepared");
    await repository.activate(request.executionId, prepared);
    const settled = await repository.inspect(request.executionId, { waitMs: 5000 });
    assert.equal(settled.kind, "settled");
    await repository.close();
    repository = await openSandboxExecutionRepository({ directory: repositoryDirectory });
    const recovered = await repository.inspect(request.executionId);
    assert.equal(recovered.kind, "settled");
    assert.equal(recovered.output.chunks.map((chunk) => chunk.data.toString()).join(""), "detached");
    await repository.close();
  }
} finally {
  await sandbox.dispose();
  await rm(root, { recursive: true, force: true });
}
