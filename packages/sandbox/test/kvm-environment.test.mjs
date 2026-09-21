import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Sandsurf } from "../dist/index.js";
import { NativeHostClient } from "../dist/native-host.js";

const enabled = process.env.SANDSURF_KVM_TEST === "1";

test("persistent KVM environment enforces runtime capabilities", { skip: !enabled, timeout: 1_200_000 }, async () => {
  const manifestPath = process.env.SANDSURF_LOCAL_IMAGE_MANIFEST;
  assert.ok(manifestPath, "SANDSURF_LOCAL_IMAGE_MANIFEST is required");
  const state = process.env.SANDSURF_TEST_STATE ?? await mkdtemp(join(tmpdir(), "sandsurf-kvm-environment-"));
  const image = createHash("sha256").update(await readFile(manifestPath)).digest("hex");
  const upstream = createServer((_request, response) => response.end("network-ok\n"));
  await new Promise((resolve, reject) => {
    upstream.once("error", reject);
    upstream.listen(0, "127.0.0.1", resolve);
  });
  const upstreamPort = upstream.address().port;
  const host = await Sandsurf.open({ directory: state, authorizer: () => true });
  let sandbox;
  let forkSandbox;
  try {
    const secret = await host.secrets.put("integration-secret", "environment-secret");
    sandbox = await host.sandboxes.create({
      image,
      resources: {
        vcpus: 1,
        memoryMiB: 512,
        diskBytes: 512 * 1024 * 1024,
        outputBytes: 128 * 1024 * 1024,
        processes: 128,
      },
      capabilities: {
        spawn: true,
        "read-files": true,
        "write-files": true,
        "workload-admin": true,
        network: true,
        "expose-port": true,
        "deliver-secret": true,
      "increase-resources": true,
      checkpoint: true,
      },
    });

    await sandbox.secrets.deliver(secret, { path: "/workspace/file-secret" });
    assert.equal(Buffer.from(await sandbox.fs.readFile("/workspace/file-secret")).toString(), "environment-secret");

    const secretProcessId = "secret-process";
    await sandbox.secrets.deliver(secret, { environment: "SANDSURF_SECRET", processId: secretProcessId });
    assert.equal(await run(sandbox, ["/bin/sh", "-c", "printf %s \"$SANDSURF_SECRET\""], { processId: secretProcessId, user: "root" }), "environment-secret");
    assert.equal(await run(sandbox, ["/bin/sh", "-c", "printf %s \"${SANDSURF_SECRET-unset}\""], { user: "root" }), "unset");

    const secretHolderId = "secret-holder";
    await sandbox.secrets.deliver(secret, { environment: "SANDSURF_SECRET", processId: secretHolderId, lifetime: "process" });
    const secretHolder = await sandbox.processes.spawn({ processId: secretHolderId, argv: ["/bin/sh", "-c", "test \"$SANDSURF_SECRET\" = environment-secret && while :; do sleep 1; done"], user: "root", lifetime: "sandbox" });
    const revocation = await sandbox.secrets.revoke(secret, { operationId: "revoke-integration-secret", terminateRecipients: true });
    assert.equal(revocation.enforced, true);
    assert.equal(revocation.evidence.residualCopiesPossible, true);
    assert.ok(revocation.evidence.recipientsTerminated.includes(secretHolderId));
    await secretHolder.wait();
    await assert.rejects(sandbox.fs.readFile("/workspace/file-secret"));

    await sandbox.network.configure({ rules: [{
      plane: "named-proxy",
      destination: { kind: "dns", name: "localhost", allowPrivateAddresses: true },
      ports: [upstreamPort],
    }] });
    assert.equal(await run(sandbox, ["/bin/busybox", "wget", "-q", "-O", "-", `http://localhost:${upstreamPort}/`], {
      environment: { NO_PROXY: "", no_proxy: "" },
    }), "network-ok\n");
    await sandbox.network.denyAll();
    const denied = await runResult(sandbox, ["/bin/busybox", "wget", "-T", "2", "-q", "-O", "-", `http://localhost:${upstreamPort}/`], {
      environment: { NO_PROXY: "", no_proxy: "" },
    });
    assert.notEqual(exitCode(denied.state), 0);

    await sandbox.workspace.writeFile("index.html", "exposure-ok\n");
    const server = await sandbox.processes.spawn({
      argv: ["/bin/busybox", "httpd", "-f", "-p", "127.0.0.1:18080", "-h", "/workspace"],
      user: "root",
      lifetime: "sandbox",
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    const exposure = await sandbox.ports.expose({ guestPort: 18080 });
    const response = await fetch(`http://127.0.0.1:${exposure.boundPort}/index.html`);
    assert.equal(await response.text(), "exposure-ok\n");
    await sandbox.ports.revoke(exposure.id);
    await assert.rejects(fetch(`http://127.0.0.1:${exposure.boundPort}/index.html`));
    await server.terminate();

    const before = await sandbox.resources.usage();
    assert.equal(before.complete, false);
    assert.equal(before.source, "host-catalog-cumulative(guest-cgroup-v2)");
    const view = await sandbox.inspect();
    await sandbox.resources.update(view.resources, {
      workloadMemoryBytes: 384 * 1024 * 1024,
      workloadProcesses: 96,
      cpuMax: [50_000, 100_000],
    });
    const after = await sandbox.resources.usage();
    assert.ok(after.cpuMicros >= before.cpuMicros);
    assert.ok(after.memoryPeak >= before.memoryPeak);
    assert.ok(after.diskLogicalBytes > 0);
    assert.ok(after.outputRetainedBytes > 0);
    assert.ok(after.networkRxBytes > 0);
    assert.ok(after.networkTxBytes > 0);
    assert.ok(after.networkConnections > 0);

    await sandbox.pause("pause-before-checkpoint");
    await sandbox.resume("resume-before-checkpoint");
    assert.equal(Buffer.from(await sandbox.fs.readFile("/workspace/index.html")).toString(), "exposure-ok\n");

    const restoredProcess = await sandbox.processes.spawn({
      processId: "full-state-service",
      operationId: "start-full-state-service",
      argv: ["/bin/sh", "-c", "trap 'exit 0' TERM; while :; do printf tick; sleep 1; done"],
      user: "root",
      lifetime: "sandbox",
    });
    await waitForOutput(restoredProcess, 4);
    const suspended = await sandbox.suspend("suspend-full-state");
    assert.equal(suspended.machine.value.state, "suspended");
    const restored = await sandbox.resume("restore-full-state");
    assert.equal(restored.machine.value.state, "running");
    const reboundProcess = await sandbox.processes.get("full-state-service");
    const reboundObservation = await reboundProcess.inspect();
    assert.equal(reboundObservation.kind, "current");
    assert.equal(reboundObservation.value.state.kind, "running");
    assert.equal(reboundObservation.value.request.epoch, restored.machine.value.epoch);
    assert.equal(reboundObservation.value.lineage.checkpointId.startsWith("suspend-"), true);
    await waitForOutput(reboundProcess, 8);
    await reboundProcess.terminate();
    await reboundProcess.wait();

    await sandbox.fs.writeFile("/workspace/checkpoint-value", "captured\n");
    const fullCheckpoint = await sandbox.checkpoints.create({
      id: "full-checkpoint",
      operationId: "capture-full-checkpoint",
      kind: "full",
    });
    assert.equal(fullCheckpoint.inspection.phase, "ready");
    assert.equal(fullCheckpoint.inspection.kind, "full");
    assert.equal(fullCheckpoint.inspection.sensitive, true);
    const checkpoint = await sandbox.checkpoints.create({ id: "filesystem-checkpoint" });
    assert.equal(checkpoint.inspection.phase, "ready");
    await assert.rejects(checkpoint.publishImage({ operationId: "reject-implicit-sensitive-publication" }));
    const derived = await checkpoint.publishImage({
      operationId: "publish-derived-image",
      includeWorkspace: true,
      includeHome: true,
      includeSecrets: true,
    });
    assert.equal(derived.inspection.sensitive, true);
    await sandbox.fs.writeFile("/workspace/checkpoint-value", "changed\n");
    forkSandbox = await checkpoint.fork({
      id: "checkpoint-fork",
      capabilities: { spawn: true, "read-files": true, "write-files": true },
    });
    assert.equal(Buffer.from(await forkSandbox.fs.readFile("/workspace/checkpoint-value")).toString(), "captured\n");
    await forkSandbox.stop("stop-checkpoint-fork");
    await sandbox.stop("stop-before-rollback");
    await sandbox.checkpoints.rollback(checkpoint.id, { operationId: "rollback-filesystem-checkpoint" });
    await sandbox.start("start-after-rollback");
    assert.equal(Buffer.from(await sandbox.fs.readFile("/workspace/checkpoint-value")).toString(), "captured\n");
  } finally {
    upstream.close();
    if (forkSandbox !== undefined) {
      try { await forkSandbox.stop("cleanup-checkpoint-fork"); } catch { /* Preserve the primary assertion. */ }
    }
    if (sandbox !== undefined) {
      try { await sandbox.stop("stop-kvm-environment"); } catch { /* Preserve the primary assertion. */ }
    }
    await host.close();
    try { await (await NativeHostClient.open(state)).stopService(); } catch { /* Best effort test cleanup. */ }
  }
});

async function run(sandbox, argv, options = {}) {
  const result = await runResult(sandbox, argv, options);
  assert.equal(exitCode(result.state), 0, Buffer.from(result.output).toString());
  return Buffer.from(result.output).toString();
}

async function runResult(sandbox, argv, options = {}) {
  const process = await sandbox.processes.spawn({ argv, ...options });
  const ended = await process.wait();
  const page = await process.readOutput({ maximum: 256 * 1024 });
  return { state: ended.state, output: Buffer.concat(page.chunks.map((chunk) => Buffer.from(chunk.bytes))) };
}

function exitCode(state) {
  assert.equal(state.kind, "exited");
  return state.outcome.kind === "exit" ? state.outcome.code : null;
}

async function waitForOutput(process, minimum) {
  const deadline = Date.now() + 30_000;
  for (;;) {
    const page = await process.readOutput({ maximum: 64 * 1024 });
    const bytes = page.chunks.reduce((total, chunk) => total + chunk.bytes.byteLength, 0);
    if (bytes >= minimum) return;
    if (Date.now() >= deadline) throw new Error(`process ${process.id} produced fewer than ${minimum} bytes`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}
