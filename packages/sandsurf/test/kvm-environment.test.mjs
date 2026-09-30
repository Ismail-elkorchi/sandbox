import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { createServer } from "node:net";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageDirectory = process.env.SANDSURF_TEST_PACKAGE_ROOT ?? fileURLToPath(new URL("..", import.meta.url));
const { Sandsurf, ExecutionInterruptedError } = await import(pathToFileURL(join(packageDirectory, "dist/index.js")).href);
const { NativeHostClient } = await import(pathToFileURL(join(packageDirectory, "dist/native-host.js")).href);

const enabled = process.env.SANDSURF_KVM_TEST === "1";

test("KVM provides a persistent administrator-controlled Linux computer", { skip: !enabled, timeout: 1_200_000 }, async (context) => {
  const directory = process.env.SANDSURF_TEST_STATE ?? await mkdtemp("/var/tmp/sandsurf-computer-");
  const destination = await mkdtemp("/var/tmp/sandsurf-publication-");
  const manifestPath = process.env.SANDSURF_LOCAL_IMAGE_MANIFEST ?? resolve(packageDirectory, "images/development-x64/manifest.json");
  const image = createHash("sha256").update(await readFile(manifestPath)).digest("hex");
  let host = await Sandsurf.open({ directory, authorizer: () => true });
  let machine;
  let fork;
  let observer;
  let expiring;
  try {
    const nativeHost = await host.inspect();
    assert.equal(nativeHost.engine, "firecracker");
    assert.equal(nativeHost.guestPower.shutdown.kind, "unsupported");
    assert.match(nativeHost.guestPower.shutdown.reasons.join(" "), /ACPI/u);
    assert.equal(nativeHost.guestPower.reboot.kind, "unsupported");
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

    context.diagnostic("guest commands and retained reads do not inspect native power to identify the guardian");
    const nativeGeneration = machine.generation;
    const guardianRoot = join(directory, "machines", machine.id, "guardian");
    const nativeDirectories = (await readdir(guardianRoot, { withFileTypes: true })).filter((entry) => entry.isDirectory() && entry.name.startsWith(`vm-${nativeGeneration}-`));
    assert.equal(nativeDirectories.length, 1);
    const nativeSocket = join(guardianRoot, nativeDirectories[0].name, "vm-state/firecracker.socket");
    const unavailableSocket = `${nativeSocket}.test-unavailable`;
    await rename(nativeSocket, unavailableSocket);
    try {
      const unavailable = await machine.inspect();
      assert.equal(unavailable.machine.kind, "unavailable");
      assert.equal(unavailable.machine.lastKnown.state, "running");
      assertSameBytes(await output(execution), dense);
      const command = await machine.executions.start({ argv: ["/bin/echo", "native-query-independent"], executionId: "native-query-independent", expectedGeneration: nativeGeneration });
      assert.equal(exitCode(await command.waitCapture({ signal: AbortSignal.timeout(30_000) })), 0);
      assert.equal((await output(command)).toString(), "native-query-independent\n");
    } finally {
      await rename(unavailableSocket, nativeSocket);
      assert.equal((await machine.inspect()).machine.value.state, "running");
    }

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

    observer = await Sandsurf.open({ directory, service: "connect" });
    const observedMachine = await observer.machines.connect(identity);
    const stream = observedMachine.events.follow({ maximum: 8, signal: AbortSignal.timeout(30_000) });
    assert.equal((await stream.next()).value.cursor, 1);
    // This observer owns only a read channel to the guardian. Host catalog
    // restart must not require reconnecting it or replaying a guest command.
    await host.close();
    await (await NativeHostClient.open(directory)).stopService();
    host = await Sandsurf.open({ directory, authorizer: () => true });
    machine = await host.machines.connect(identity);
    execution = await machine.executions.get("retained-dense");
    assert.equal(machine.generation, generation);
    assert.equal((await machine.inspect()).machine.value.state, "running");
    assert.equal(await run(machine, "cat /home/agent/cache/value"), "durable");
    const streamed = await machine.executions.start({ executionId: "stream-after-host-restart", argv: ["/bin/true"] });
    try {
      for (;;) {
        const event = await stream.next();
        assert.equal(event.done, false);
        if (event.value.value.kind === "process" && event.value.value.process.request.executionId === streamed.id) break;
      }
    } finally { await stream.return(); }
    assert.equal(exitCode(await streamed.waitCapture({ signal: AbortSignal.timeout(30_000) })), 0);
    const boundary = await machine.events.read({ maximum: 1 });
    const controller = new AbortController();
    const cancelled = observedMachine.events.follow({ after: boundary.available, signal: controller.signal });
    const waiting = cancelled.next();
    const reason = new Error("detach idle observer");
    controller.abort(reason);
    await assert.rejects(waiting, (error) => error === reason);
    await cancelled.return();
    await observer.close();
    observer = undefined;

    const artifact = await machine.artifacts.capture("/workspace");
    context.diagnostic("disk snapshot, fork and cold-boot persistence");
    // Crash-consistent disk capture does not include dirty guest RAM. Establish
    // ordinary Linux durability before asserting these files survive rollback.
    await run(machine, "sudo -n sync");
    const snapshot = await machine.snapshots.create({ kind: "disk" });
    assert.equal(snapshot.inspection.consistency, "crash");
    fork = await snapshot.fork();
    await managementReady(fork);
    assertSameBytes(await fork.fs.readFile("/workspace/dense"), dense);
    assert.equal(Buffer.from(await fork.fs.readFile("/etc/sandsurf-test")).toString(), "computer");
    assert.equal(Buffer.from(await fork.fs.readFile("/home/agent/cache/value")).toString(), "durable");
    assert.equal((await fork.inspect()).knownSensitive, true);
    await fork.fs.writeFile("/workspace/fork-only", "isolated");
    await assert.rejects(machine.fs.readFile("/workspace/fork-only"));
    await fork.destroy();
    fork = undefined;

    context.diagnostic("snapshot images and native imports share one identity, sensitivity and bootable system seed");
    const publishedImage = await snapshot.publishImage({ allowSensitive: true, operationId: "publish-computer-image" });
    assert.equal(publishedImage.inspection.sensitive, true);
    const reimportedImage = await host.images.importNative({
      manifestPath: join(directory, "images", publishedImage.id, "manifest.json"),
      manifestDigest: publishedImage.id, operationId: "reimport-computer-image",
    });
    assert.deepEqual(reimportedImage.inspection, publishedImage.inspection);
    fork = await host.machines.create({ image: reimportedImage.id,
      resources: { vcpus: 1, memoryMiB: 256, diskBytes: 256 * 1024 ** 2, outputBytes: 1024 ** 2, managedExecutions: 8 } });
    await managementReady(fork);
    assert.equal((await fork.inspect()).knownSensitive, true);
    assert.equal(Buffer.from(await fork.fs.readFile("/etc/sandsurf-test")).toString(), "computer");
    assert.equal(await run(fork, "sudo -n id -u"), "0\n");
    await fork.destroy();
    fork = undefined;

    context.diagnostic("native power-off interrupts waits without fabricating exit or releasing retained output");
    const interrupted = await machine.executions.start({ argv: ["/bin/sh", "-c", "printf before-stop; sleep 300"], executionId: "interrupted-by-native-stop" });
    const slotsBeforeStop = (await machine.resources.usage()).executionsCurrent;
    assert.ok(slotsBeforeStop > 0);
    const captureDeadline = Date.now() + 15_000;
    let beforeStop;
    do {
      beforeStop = await interrupted.output.read();
      if (beforeStop.available >= Buffer.byteLength("before-stop")) break;
      assert.ok(Date.now() < captureDeadline, "running execution output was not captured");
      await new Promise((done) => setTimeout(done, 25));
    } while (true);
    const waits = Promise.allSettled([
      interrupted.waitLeader({ signal: AbortSignal.timeout(15_000) }),
      interrupted.waitCapture({ signal: AbortSignal.timeout(15_000) }),
    ]);
    await machine.powerOff();
    assert.equal((await machine.resources.usage()).executionsCurrent, 0, "native interruption frees managed admission capacity, not output retention");
    for (const result of await waits) {
      assert.equal(result.status, "rejected");
      assert.ok(result.reason instanceof ExecutionInterruptedError);
      assert.equal(result.reason.observation.state, "stopped");
    }
    const interruptedStatus = await interrupted.inspect();
    assert.equal(interruptedStatus.report.kind, "unavailable");
    assert.equal(interruptedStatus.interruption.state, "stopped");
    assert.equal(await interrupted.receipt(), undefined);
    assert.equal(Buffer.concat((await interrupted.output.read()).chunks.map((chunk) => Buffer.from(chunk.bytes))).toString(), "before-stop");
    await assert.rejects((await machine.executions.get(interrupted.id)).waitCapture(), ExecutionInterruptedError);
    await machine.start();
    await managementReady(machine);
    assert.equal((await machine.resources.usage()).executionsCurrent, 0, "cold boot does not resurrect old managed admission slots");
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
    assert.equal(Buffer.from(await machine.fs.readFile("/etc/sandsurf-test")).toString(), "computer");
    assert.equal(Buffer.from(await machine.fs.readFile("/home/agent/cache/value")).toString(), "durable");
    assert.equal((await machine.inspect()).knownSensitive, true, "rollback cannot clear disclosure history");

    // Firecracker x86 lacks ACPI poweroff. Its CPU reset exits the VMM;
    // exercise that actual native termination, without claiming OS reboot.
    context.diagnostic("guest CPU reset terminates the native owner without changing host intent; ordinary reboot remains unsupported");
    const beforeShutdown = await machine.inspect();
    await machine.executions.start({ argv: ["/bin/sh", "-c", "sudo -n sh -c 'sleep 1; reboot'"], executionId: "native-reset-exit" });
    const shutdownDeadline = Date.now() + 30_000;
    let stopped;
    do {
      stopped = await machine.inspect();
      if (stopped.machine.kind === "current" && stopped.machine.value.state === "stopped") break;
      await new Promise((done) => setTimeout(done, 100));
    } while (Date.now() < shutdownDeadline);
    assert.equal(stopped.machine.kind, "current");
    assert.equal(stopped.machine.value.state, "stopped");
    assert.equal(stopped.machine.value.cause.kind, "native");
    assert.equal(stopped.machine.value.generation, beforeShutdown.machine.value.generation);
    assert.equal(stopped.configurationRevision, beforeShutdown.configurationRevision);
    assert.equal(stopped.lifecycleIntent.desired, "running");
    await machine.start();
    await managementReady(machine);
    assert.ok(machine.generation > beforeShutdown.machine.value.generation);
    assert.equal(Buffer.from(await machine.fs.readFile("/etc/sandsurf-test")).toString(), "computer");
    assert.equal(Buffer.from(await machine.fs.readFile("/home/agent/cache/value")).toString(), "durable");
    assert.match(Buffer.from(await machine.fs.readFile("/usr/local/bin/agent-tool")).toString(), /printf installed/u);
    assert.equal(await run(machine, "/usr/local/bin/agent-tool; cat /etc/sandsurf-test /home/agent/cache/value"), "installedcomputerdurable");

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
      const systemDisk = join(directory, "machines", machine.id, "disks/system.ext4");
      await assert.rejects(stat(systemDisk), { code: "ENOENT" });
    } finally {
      await new Promise((done) => occupied.close(done));
    }
    assertSameBytes(await output(execution), dense);
    const archivedReceipt = await execution.receipt();
    assert.ok(archivedReceipt);
    context.diagnostic("retained evidence reconnects without boot images or a native VM owner");
    await host.close();
    await (await NativeHostClient.open(directory)).stopService();
    const retiredEndpoint = join(directory, "machines", identity, "guardian/control.sock");
    const deadline = Date.now() + 10_000;
    while (await stat(retiredEndpoint).then(() => true, (error) => {
      if (error.code === "ENOENT") return false;
      throw error;
    })) {
      assert.ok(Date.now() < deadline, "destroyed guardian did not retire");
      await new Promise((done) => setTimeout(done, 100));
    }
    const installedImage = join(directory, "images", image);
    const unavailableImage = join(directory, "images", `${image}.test-unavailable`);
    await rename(installedImage, unavailableImage);
    try {
      host = await Sandsurf.open({ directory, authorizer: () => true });
      machine = await host.machines.connect(identity);
      execution = await machine.executions.get("retained-dense");
      assert.equal((await machine.inspect()).machine.value.state, "destroyed");
      assertSameBytes(await output(execution), dense);
      await assert.rejects(stat(join(directory, "machines", identity, "disks/system.ext4")), { code: "ENOENT" });
      await execution.acknowledge(archivedReceipt.digest);
      const pinned = await execution.pin("archive-copy", archivedReceipt.digest);
      const released = await execution.release(archivedReceipt, { kind: "continuing-retention", pin: pinned.id });
      assert.equal((await execution.cleanupReleased(released.requestDigest)).cleanupPending, false);
      const retainedPage = await pinned.read({ maximum: dense.byteLength });
      assertSameBytes(Buffer.concat(retainedPage.chunks.map((chunk) => Buffer.from(chunk.bytes))), dense);
    } finally {
      await rename(unavailableImage, installedImage);
    }
    const retained = await host.artifacts.get(identity, artifact.id);
    await writeFile(join(destination, "unrelated"), "preserved");
    await retained.applyToHost({ destination });
    assertSameBytes(await readFile(join(destination, "dense")), dense);
    assert.equal(await readFile(join(destination, "unrelated"), "utf8"), "preserved");
    machine = undefined;
    context.diagnostic("image feature reports and management provenance do not grant or restrict machine authority");
    await qualifyImageBuildReports(manifestPath);
    context.diagnostic("host expiration remains active under continuous SDK traffic");
    const expiresAtUnixMs = Date.now() + 30_000;
    expiring = await host.machines.create({
      image, resources: { vcpus: 1, memoryMiB: 256, diskBytes: 256 * 1024 ** 2, outputBytes: 1024 ** 2, managedExecutions: 8 },
      lifetime: { expiresAtUnixMs, expirationAction: "stop" },
    });
    assert.ok(Date.now() < expiresAtUnixMs, "boot consumed the expiration deadline before client traffic began");
    let sending = true;
    let trafficError;
    const traffic = (async () => {
      while (sending) {
        await host.inspect();
        await new Promise((done) => setTimeout(done, 25));
      }
    })().catch((error) => { trafficError = error; });
    try {
      let stopped = false;
      for await (const event of expiring.events.follow({ signal: AbortSignal.timeout(Math.max(1, expiresAtUnixMs - Date.now() + 15_000)) })) {
        if (event.value.kind === "machine" && event.value.observation.state === "stopped") { stopped = true; break; }
      }
      assert.equal(stopped, true);
      const view = await expiring.inspect();
      assert.equal(view.lifecycleIntent.desired, "stopped");
      assert.equal(view.machine.value.state, "stopped");
    } finally { sending = false; await traffic; }
    assert.ifError(trafficError);
    await expiring.destroy();
    expiring = undefined;
  } finally {
    let cleanupError;
    try {
      if (observer !== undefined) await observer.close();
      for (const remaining of [expiring, fork, machine]) {
        if (remaining === undefined) continue;
        try { await remaining.inspect(); await remaining.destroy(); }
        catch (error) { cleanupError ??= error; }
      }
    } finally {
      // Test failure must not strand bridge handles and hide the TAP result.
      await host.close();
      try { await (await NativeHostClient.open(directory)).stopService(); }
      finally {
        if (process.env.SANDSURF_TEST_STATE === undefined) await rm(directory, { recursive: true, force: true });
        await rm(destination, { recursive: true, force: true });
      }
    }
    if (cleanupError !== undefined) throw cleanupError;
  }
});

async function qualifyImageBuildReports(sourceManifest) {
  const root = await mkdtemp("/var/tmp/sandsurf-image-report-");
  const bundle = join(root, "bundle");
  const directory = join(root, "host");
  let host;
  let machine;
  try {
    await mkdir(bundle);
    const source = JSON.parse(await readFile(sourceManifest, "utf8"));
    const manifest = { ...source, signature: null, platformArtifacts: { windowsX64: null }, bootBundle: {
      ...source.bootBundle,
      capabilities: { overlayfs: false, vsock: false, seccomp: false, cgroupV2: false, devpts: false },
      guestAgent: { ...source.bootBundle.guestAgent, version: "provenance-only", protocolMajor: 99, protocolMinor: 0 },
    } };
    const bytes = Buffer.from(JSON.stringify(manifest));
    const manifestPath = join(bundle, "manifest.json");
    for (const artifact of [manifest.bootBundle.kernel, manifest.system.rootfs]) {
      await copyFile(join(dirname(sourceManifest), artifact.path), join(bundle, artifact.path));
    }
    await writeFile(manifestPath, bytes);
    host = await Sandsurf.open({ directory, authorizer: () => true });
    const manifestDigest = createHash("sha256").update(bytes).digest("hex");
    const importOptions = { manifestPath, manifestDigest, operationId: "import-native-machine" };
    const image = await host.images.importNative(importOptions);
    assert.equal(image.id, manifestDigest);
    await rm(bundle, { recursive: true });
    await host.close();
    await (await NativeHostClient.open(directory)).stopService();
    host = await Sandsurf.open({ directory, authorizer: () => true });
    assert.equal((await host.images.importNative(importOptions)).id, image.id, "published operation reconnects without the source bundle");
    assert.equal((await host.images.get(image.id)).id, image.id);
    machine = await host.machines.create({ image: image.id,
      resources: { vcpus: 1, memoryMiB: 256, diskBytes: 256 * 1024 ** 2, outputBytes: 1024 ** 2, managedExecutions: 8 } });
    assert.equal((await machine.inspect()).machine.value.state, "running");
    await managementReady(machine);
    assert.equal(await run(machine, "sudo -n id -u"), "0\n", "the actual guest handshake, not management provenance, controls API compatibility");
  } finally {
    try {
      if (machine !== undefined) { await machine.inspect(); await machine.destroy(); }
    } finally {
      try {
        if (host !== undefined) {
          await host.close();
          await (await NativeHostClient.open(directory)).stopService();
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  }
}

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
  if (process.env.SANDSURF_TEST_TRACE === "1") console.error(`guest shell exit: ${JSON.stringify(inspection.state)} ${bytes.byteLength} bytes; receipt: ${JSON.stringify(await execution.receipt())}`);
  assert.equal(exitCode(inspection), 0, bytes.toString());
  return bytes.toString();
}
