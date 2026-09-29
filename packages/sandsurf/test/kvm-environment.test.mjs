import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import test from "node:test";
import { Sandsurf } from "../dist/index.js";
import { NativeHostClient } from "../dist/native-host.js";

const enabled = process.env.SANDSURF_KVM_TEST === "1";

test("KVM provides a persistent administrator-controlled Linux computer", { skip: !enabled, timeout: 1_200_000 }, async (context) => {
  const directory = process.env.SANDSURF_TEST_STATE ?? await mkdtemp("/var/tmp/sandsurf-computer-");
  const destination = await mkdtemp("/var/tmp/sandsurf-publication-");
  const manifestPath = process.env.SANDSURF_LOCAL_IMAGE_MANIFEST ?? resolve("packages/sandsurf/images/development-x64/manifest.json");
  const image = createHash("sha256").update(await readFile(manifestPath)).digest("hex");
  let host = await Sandsurf.open({ directory, authorizer: () => true });
  let machine;
  let fork;
  try {
    machine = await host.machines.create({
      image, resources: { vcpus: 1, memoryMiB: 256, diskBytes: 256 * 1024 ** 2, outputBytes: 64 * 1024 ** 2, managedExecutions: 128 },
    });
    await managementReady(machine);
    context.diagnostic("ordinary Linux boot and administrator access");
    assert.equal((await machine.inspect()).machine.value.state, "running");
    assert.equal(await run(machine, "id -un"), "agent\n");
    assert.equal(await run(machine, "sudo -n id -u"), "0\n");
    assert.ok(Number(await run(machine, "df -k / | tail -1 | awk '{print $2}'")) >= 240_000, "the root filesystem must cover the reserved 256 MiB disk");
    assert.match(await run(machine, "sudo -n readlink /proc/1/exe; rc-status --runlevel"), /busybox[\s\S]*default/u);
    assert.equal(await run(machine, "sudo -n sh -c 'test -w /etc && test -w /usr && test -w /var && test -w /root' && test -w /home/agent"), "");
    await run(machine, "sudo -n sh -c 'printf computer > /etc/sandsurf-test; printf \"#!/bin/sh\\nprintf installed\\n\" > /usr/local/bin/agent-tool; chmod 755 /usr/local/bin/agent-tool'; mkdir -p /home/agent/cache; printf durable > /home/agent/cache/value");
    assert.equal(await run(machine, "/usr/local/bin/agent-tool"), "installed");
    assert.match(await run(machine, "apk info --installed git sudo openrc"), /git[\s\S]*sudo[\s\S]*openrc/u);

    const daemon = await machine.executions.start({ argv: ["/bin/sh", "-c", "(sleep 3; printf descendant) & printf leader"] });
    const leader = await daemon.waitLeader({ signal: AbortSignal.timeout(30_000) });
    assert.equal(leader.state.kind, "draining", "leader exit must not terminate independently running descendants");
    const drained = await daemon.waitCapture({ signal: AbortSignal.timeout(30_000) });
    assert.equal(exitCode(drained), 0);
    assert.equal((await output(daemon)).toString(), "leaderdescendant");

    const dense = Buffer.alloc(131072, 255);
    context.diagnostic("dense binary filesystem and output capture");
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error("dense: write begin");
    await machine.fs.writeFile("/workspace/dense", dense);
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error("dense: write complete, read begin");
    assertSameBytes(await machine.fs.readFile("/workspace/dense"), dense);
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error("dense: read complete, spawn begin");
    let execution = await machine.executions.start({ executionId: "retained-dense", argv: ["/bin/cat", "/workspace/dense"] });
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error("dense: spawned, wait begin");
    assert.equal(exitCode(await execution.waitCapture({ signal: AbortSignal.timeout(30_000) })), 0);
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error("dense: wait complete, output begin");
    assertSameBytes(await output(execution), dense);
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error("dense: output complete, receipt begin");
    const receipt = await execution.receipt();
    assert.ok(receipt);
    await execution.acknowledge(receipt.digest);
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error("dense: acknowledged, output re-read begin");
    assertSameBytes(await output(execution), dense);

    const terminal = await machine.terminals.open({ executionId: "persistent-terminal", argv: ["/bin/sh"] });
    context.diagnostic("persistent PTY and management-service restart");
    await terminal.input.write(Buffer.from("printf terminal-before\n"));
    await terminal.detach();
    const identity = machine.id;
    const generation = machine.generation;
    await host.close();
    host = await Sandsurf.open({ directory, authorizer: () => true, service: "connect" });
    machine = await host.machines.connect(identity);
    execution = await machine.executions.get("retained-dense");
    assert.equal(machine.generation, generation, "SDK reconnect is not a new Linux boot");
    const attached = await machine.terminals.get("persistent-terminal");
    await attached.acquireInput();
    await attached.input.write(Buffer.from("printf terminal-after\n"));

    await run(machine, "sudo -n sh -c '(sleep 4; rc-service sandsurf-management start) > /var/log/sandsurf-restart-test 2>&1 & rc-service sandsurf-management stop'");
    await managementReady(machine);
    await attached.input.write(Buffer.from("printf keeper-survived\nexit\n"));
    assert.equal(exitCode(await attached.waitCapture({ signal: AbortSignal.timeout(30_000) })), 0);
    assert.match((await output(attached.process)).toString(), /terminal-before[\s\S]*terminal-after[\s\S]*keeper-survived/u);
    assert.equal(machine.generation, generation, "management restart must not rebind execution generation");

    const secretBytes = Buffer.alloc(1024 ** 2, 255);
    context.diagnostic("secret disclosure and host-service restart");
    const secret = await host.secrets.put("binary-secret", secretBytes);
    const disclosure = await machine.secrets.deliver(secret, { path: "/root/delivered" });
    assert.equal(disclosure.disclosure, "guest-reported-received");
    await run(machine, "sudo -n cp /root/delivered /root/independent-copy");
    const revoked = await machine.secrets.revoke(secret);
    assert.equal(revoked.futureDeliveryRevoked, true);
    assertSameBytes(await machine.fs.readFile("/root/independent-copy"), secretBytes);
    assert.equal((await machine.inspect()).knownSensitive, true);

    await host.close();
    await (await NativeHostClient.open(directory)).stopService();
    host = await Sandsurf.open({ directory, authorizer: () => true });
    machine = await host.machines.connect(identity);
    execution = await machine.executions.get("retained-dense");
    assert.equal(machine.generation, generation);
    assert.equal((await machine.inspect()).machine.value.state, "running");
    assert.equal(await run(machine, "cat /home/agent/cache/value"), "durable");

    const artifact = await machine.artifacts.capture("/workspace");
    context.diagnostic("disk snapshot, fork and cold-boot persistence");
    const snapshot = await machine.snapshots.create({ kind: "disk" });
    assert.equal(snapshot.inspection.consistency, "crash");
    fork = await snapshot.fork();
    await managementReady(fork);
    assertSameBytes(await fork.fs.readFile("/workspace/dense"), dense);
    assert.equal((await fork.inspect()).knownSensitive, true);
    await fork.fs.writeFile("/workspace/fork-only", "isolated");
    await assert.rejects(machine.fs.readFile("/workspace/fork-only"));
    await fork.destroy();
    fork = undefined;

    await machine.powerOff();
    await machine.start();
    await managementReady(machine);
    assert.notEqual(machine.generation, generation);
    assert.equal(await run(machine, "/usr/local/bin/agent-tool; cat /etc/sandsurf-test /home/agent/cache/value"), "installedcomputerdurable");
    await assert.rejects(execution.input.write(Buffer.from("stale")), /generation/iu);

    await machine.fs.writeFile("/workspace/later", "not in snapshot");
    context.diagnostic("rollback and management-independent native destruction");
    await machine.powerOff();
    await machine.snapshots.rollback(snapshot.id);
    await machine.start();
    await managementReady(machine);
    await assert.rejects(machine.fs.readFile("/workspace/later"));
    assert.equal((await machine.inspect()).knownSensitive, true, "rollback cannot clear disclosure history");

    await machine.executions.start({ argv: ["/bin/sh", "-c", "sudo -n sh -c 'sleep 1; rc-service sandsurf-management stop'"], executionId: "disable-management" });
    await new Promise((done) => setTimeout(done, 2000));
    await assert.rejects(machine.fs.stat("/etc/passwd"));
    assert.equal((await machine.inspect()).machine.value.state, "running", "management absence does not prove native shutdown");
    await machine.pause();
    assert.equal((await machine.inspect()).machine.value.state, "paused");
    context.diagnostic("native destruction supersedes failed host configuration");
    const occupied = createServer();
    await new Promise((resolve, reject) => {
      occupied.once("error", reject);
      occupied.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = occupied.address();
      assert.ok(address !== null && typeof address !== "string");
      await assert.rejects(machine.ports.expose({ guestPort: 22, hostPort: address.port }));
      const pending = await machine.inspect();
      assert.ok(pending.machine.value.appliedRevision < pending.configurationRevision,
        "the failure must leave an admitted but unapplied host revision");
      await machine.destroy();
    } finally {
      await new Promise((done) => occupied.close(done));
    }
    assertSameBytes(await output(execution), dense);
    const archivedReceipt = await execution.receipt();
    assert.ok(archivedReceipt);
    await execution.acknowledge(archivedReceipt.digest);
    const pinned = await execution.pin("archive-copy", archivedReceipt.digest);
    const released = await execution.release(archivedReceipt, { kind: "continuing-retention", pin: pinned.id });
    assert.equal((await execution.cleanupReleased(released.requestDigest)).cleanupPending, false);
    const retainedPage = await pinned.read({ maximum: dense.byteLength });
    assertSameBytes(Buffer.concat(retainedPage.chunks.map((chunk) => Buffer.from(chunk.bytes))), dense);
    const retained = await host.artifacts.get(identity, artifact.id);
    await writeFile(join(destination, "unrelated"), "preserved");
    await retained.applyToHost({ destination });
    assertSameBytes(await readFile(join(destination, "dense")), dense);
    assert.equal(await readFile(join(destination, "unrelated"), "utf8"), "preserved");
    machine = undefined;
  } finally {
    if (fork !== undefined) await fork.destroy();
    if (machine !== undefined) await machine.destroy();
    await host.close();
    await (await NativeHostClient.open(directory)).stopService();
    if (process.env.SANDSURF_TEST_STATE === undefined) await rm(directory, { recursive: true, force: true });
    await rm(destination, { recursive: true, force: true });
  }
});

async function managementReady(machine) {
  const deadline = Date.now() + 60_000;
  let last;
  do {
    try { await machine.fs.stat("/etc/passwd"); return; }
    catch (error) { last = error; await new Promise((done) => setTimeout(done, 250)); }
  } while (Date.now() < deadline);
  throw last;
}
function exitCode(inspection) {
  assert.equal(inspection.state.kind, "exited");
  assert.equal(inspection.state.outcome.kind, "exit");
  return inspection.state.outcome.code;
}
function assertSameBytes(actual, expected) {
  assert.equal(actual.byteLength, expected.byteLength, "binary byte length differs");
  assert.equal(createHash("sha256").update(actual).digest("hex"), createHash("sha256").update(expected).digest("hex"), "binary content differs");
}
async function output(execution) {
  const chunks = [];
  let cursor = 0;
  let pages = 0;
  for (;;) {
    if (++pages > 8) throw new Error("test output reader exceeded its bounded page count");
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error(`output: request after=${cursor}`);
    const page = await execution.output.read({ after: cursor, maximum: 64 * 1024 });
    if (process.env.SANDSURF_TEST_TRACE === "1") console.error(`output: page after=${page.after} available=${page.available} chunks=${page.chunks.length}`);
    for (const chunk of page.chunks) {
      assert.equal(chunk.cursor, cursor);
      chunks.push(Buffer.from(chunk.bytes)); cursor += chunk.bytes.byteLength;
    }
    if (cursor === page.available) return Buffer.concat(chunks);
    assert.ok(page.chunks.length > 0, "capture must not invent a gap");
  }
}
async function run(machine, command) {
  if (process.env.SANDSURF_TEST_TRACE === "1") console.error(`guest shell: ${command}`);
  const execution = await machine.executions.spawnShell(command);
  const inspection = await execution.waitCapture({ signal: AbortSignal.timeout(30_000) });
  const bytes = await output(execution);
  if (process.env.SANDSURF_TEST_TRACE === "1") console.error(`guest shell exit: ${inspection.state.kind} ${bytes.byteLength} bytes`);
  assert.equal(exitCode(inspection), 0, bytes.toString());
  return bytes.toString();
}
