import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { qualificationDirectory, recordChecks } from "./qualification-storage.mjs";
import { join, resolve } from "node:path";
import { createConnection } from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const enabled = process.env.SANDSURF_KVM_NETWORK_TEST === "1";
const packageRoot = process.env.SANDSURF_TEST_PACKAGE_ROOT ?? fileURLToPath(new URL("..", import.meta.url));
const executeFile = promisify(execFile);

test("the guest raw-packet qualification stimulus is static, bounded and has a non-network self-test", {
  skip: process.platform !== "linux" || process.arch !== "x64", timeout: 30_000,
}, async () => {
  const { directory, program } = await packetStimulus();
  try {
    const { stdout } = await executeFile(program, ["--self-test"], { timeout: 5000, maxBuffer: 4096 });
    assert.equal(stdout, "cases=6 packets=32768 maximumFrameBytes=1514\n");
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("KVM native NIC survives removal of management and inbound revocation closes an existing flow", {
  skip: !enabled, timeout: 240_000,
}, async () => {
  const { Sandsurf } = await import(pathToFileURL(join(packageRoot, "dist/index.js")).href);
  const directory = await qualificationDirectory("network");
  const manifest = process.env.SANDSURF_LOCAL_IMAGE_MANIFEST ?? resolve(packageRoot, "images/development-x64/manifest.json");
  const image = createHash("sha256").update(await readFile(manifest)).digest("hex");
  const host = await Sandsurf.open({ directory, authorizer: () => true });
  let machine;
  let client;
  try {
    await host.images.importNative({ manifestPath: manifest, manifestDigest: image, operationId: "import-network-image" });
    machine = await host.machines.create({
      id: "native-network-hardware", image,
      resources: { vcpus: 1, memoryMiB: 256, diskBytes: 2 * 1024 ** 3, outputBytes: 16 * 1024 ** 2, managedExecutions: 32 },
    });
    await eventually(async () => { await machine.fs.stat("/etc/passwd"); });
    // This fixture exercises ordinary guest OS interface configuration. It
    // deliberately requires no protected guest network task or vsock relay.
    await run(machine, "ip link set eth0 up; ip addr replace 100.64.0.2/30 dev eth0; ip route replace default via 100.64.0.1 dev eth0; ip -6 addr replace fd00::2/64 dev eth0; ip -6 route replace default via fd00::1 dev eth0");
    await run(machine, "test ! -e /sys/class/net/sandsurf0; test -d /sys/class/net/eth0");
    await machine.executions.start({ user: "root", argv: ["/bin/sh", "-c", "exec busybox nc -ll -p 8080 -e /bin/cat"] });
    const exposed = await machine.ports.expose({ guestAddress: "100.64.0.2", guestPort: 8080 });
    const port = exposed.boundPort ?? exposed.spec.hostPort;
    client = await eventually(() => connect(port));
    assert.equal(await echo(client, "before management removal"), "before management removal");
    const beforeDeny = await machine.resources.usage();
    for (const target of ["1.1.1.1", "169.254.169.254", "100.64.0.1", "100.64.0.3"]) {
      await run(machine, `! busybox nc -w 1 ${target} 443 </dev/null`);
    }
    const afterDeny = await machine.resources.usage();
    assert.equal(afterDeny.networkConnections, beforeDeny.networkConnections,
      "default deny, metadata, gateway/host, and another machine address must create no native egress flow");
    await qualifyNetworkBounds(directory, machine, client, port);
    await machine.executions.start({ user: "root", argv: ["/bin/sh", "-c", "sleep 1; rc-service sandsurf-management stop; rm -f /usr/sbin/sandsurf-guest"] });
    await new Promise((done) => setTimeout(done, 2500));
    assert.equal((await machine.inspect()).machine.value.state, "running");
    assert.equal(await echo(client, "after management removal"), "after management removal");
    // Revocation is performed through native host authority with no guest API.
    const closed = new Promise((done, reject) => {
      const deadline = setTimeout(() => reject(new Error("affected flow survived inbound revocation")), 3000);
      client.once("close", () => { clearTimeout(deadline); done(); });
    });
    await machine.ports.revoke(exposed.id);
    await closed;
    await assert.rejects(connect(port));
    await recordChecks(directory, machine, ["management-disabled", "policy-revocation"], { revokedExposure: exposed.id, closedExistingFlow: true });
    await machine.powerOff();
    assert.equal((await machine.inspect()).machine.value.state, "stopped");
    await recordChecks(directory, machine, ["forced-power-off"], { managementRemoved: true, observedState: "stopped" });
  } finally {
    client?.destroy();
    if (machine !== undefined) { await machine.powerOff().catch(() => {}); await machine.destroy(); }
    await host.close();
    // Retain the native journal/state directory as qualification evidence.
  }
});

async function packetStimulus() {
  const directory = await mkdtemp("/var/tmp/sandsurf-nic-stimulus-");
  const program = join(directory, "guest-packet-flood");
  try {
    await executeFile("/usr/bin/cc", ["-std=c11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
      fileURLToPath(new URL("fixtures/guest-packet-flood.c", import.meta.url)), "-o", program],
    { timeout: 20_000, maxBuffer: 64 * 1024 });
    const bytes = await readFile(program);
    // The fixture must not depend on guest libc, a compiler, package downloads,
    // or a guest management implementation to generate the actual NIC traffic.
    const header = bytes.subarray(0, 64);
    assert.equal(header.subarray(0, 4).toString("hex"), "7f454c46");
    assert.equal(header[4], 2); assert.equal(header[5], 1);
    assert.equal(header.readUInt16LE(18), 62);
    const offset = Number(header.readBigUInt64LE(32));
    const width = header.readUInt16LE(54); const count = header.readUInt16LE(56);
    assert.ok(count > 0 && count <= 64 && width === 56 && offset + width * count <= bytes.length);
    for (let index = 0; index < count; index++) {
      assert.notEqual(bytes.readUInt32LE(offset + index * width), 3, "qualification stimulus must have no ELF interpreter");
    }
    return { directory, program };
  } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
}

async function qualifyNetworkBounds(directory, machine, existing, port) {
  // Keep all admitted flows alive: cumulative admission accounting alone does
  // not demonstrate a simultaneous-flow cap. The ordinary guest echo server
  // itself has no Sandsurf admission limit.
  const clients = [];
  const before = await machine.resources.usage();
  try {
    for (let index = 1; index < 128; index++) {
      const client = await connect(port); clients.push(client);
      assert.equal(await echo(client, `flow-${index}`), `flow-${index}`);
    }
    assert.equal((await machine.resources.usage()).networkConnections - before.networkConnections, 127);
    const overflow = await connect(port); clients.push(overflow);
    await assert.rejects(echo(overflow, "over-capacity"), /timed out|closed/u);
    assert.equal((await machine.resources.usage()).networkConnections - before.networkConnections, 127,
      "a backlog handshake must not become an admitted native flow above the cap");
    assert.equal(await echo(existing, "control-at-capacity"), "control-at-capacity");
    await recordChecks(directory, machine, ["network-cap"], {
      concurrentEchoFlows: 128, additionalFlowNotAdmitted: true,
      cumulativeAdmissionsBefore: before.networkConnections,
      cumulativeAdmissionsAtCap: (await machine.resources.usage()).networkConnections,
    });
  } finally { for (const client of clients) client.destroy(); }

  // Closed overflow handshakes can still be in the host listener backlog.
  // Let their teardown finish before measuring an unrelated packet stimulus.
  let lastAdmissions = (await machine.resources.usage()).networkConnections;
  let stable = 0;
  for (let attempt = 0; stable < 4 && attempt < 40; attempt++) {
    await new Promise((done) => setTimeout(done, 100));
    const current = (await machine.resources.usage()).networkConnections;
    stable = current === lastAdmissions ? stable + 1 : 0;
    lastAdmissions = current;
  }
  assert.equal(stable, 4, "native admission accounting did not stabilize after listener backlog teardown");

  const stimulus = await packetStimulus();
  try {
    await machine.fs.writeFile("/root/guest-packet-flood", await readFile(stimulus.program));
    await run(machine, "chmod 700 /root/guest-packet-flood");
    const initial = await machine.resources.usage();
    const flood = await machine.executions.start({ user: "root", argv: ["/root/guest-packet-flood"] });
    await eventually(async () => {
      assert.ok((await machine.resources.usage()).networkTxBytes > initial.networkTxBytes,
        "waiting for actual malformed NIC traffic, not guest command admission");
    });
    const latencies = [];
    for (let index = 0; index < 8; index++) {
      const start = performance.now();
      assert.equal((await machine.inspect()).machine.value.state, "running");
      latencies.push(performance.now() - start);
      assert.ok(latencies.at(-1) < 5000, "native control must remain responsive under root-generated malformed NIC traffic");
    }
    const result = await flood.waitCapture({ signal: AbortSignal.timeout(45_000) });
    assert.equal(result.state.kind, "exited");
    assert.equal(result.state.outcome.kind, "exit"); assert.equal(result.state.outcome.code, 0);
    const page = await flood.output.read({ maximum: 4096 });
    assert.equal(Buffer.concat(page.chunks.map((chunk) => Buffer.from(chunk.bytes))).toString(),
      "cases=6 packets=32768 maximumFrameBytes=1514\n");
    const final = await machine.resources.usage();
    assert.equal(final.networkConnections, initial.networkConnections,
      "malformed/fragmented/VLAN/spoofed/truncated traffic must create no native egress flows");
    assert.ok(final.networkTxBytes > initial.networkTxBytes, "the real native NIC must actually observe the stimulus");
    assert.equal(await echo(existing, "control-after-malformed-traffic"), "control-after-malformed-traffic");
    await recordChecks(directory, machine, ["malformed-packet-bounds", "control-responsiveness"], {
      guestSubmittedPackets: 32768, maximumFrameBytes: 1514, malformedCases: 6,
      hostObservedTxBytes: final.networkTxBytes - initial.networkTxBytes,
      nativeAdmissionIncrease: final.networkConnections - initial.networkConnections,
      nativeControlMillis: latencies,
    });
  } finally { await rm(stimulus.directory, { recursive: true, force: true }); }
}

async function run(machine, command) {
  const execution = await machine.executions.start({ user: "root", argv: ["/bin/sh", "-ec", command] });
  const result = await execution.waitCapture({ signal: AbortSignal.timeout(30_000) });
  assert.equal(result.state.kind, "exited");
  assert.equal(result.state.outcome.kind, "exit");
  assert.equal(result.state.outcome.code, 0, command);
}
async function eventually(action) {
  let last;
  for (let attempt = 0; attempt < 120; attempt++) {
    try { return await action(); }
    catch (error) { last = error; await new Promise((done) => setTimeout(done, 100)); }
  }
  throw last;
}
function connect(port) {
  return new Promise((done, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    socket.setTimeout(2000, () => socket.destroy(new Error("native inbound connection timed out")));
    socket.once("error", reject); socket.once("connect", () => { socket.setTimeout(0); socket.removeListener("error", reject); socket.on("error", () => {}); done(socket); });
  });
}
function echo(socket, message) {
  return new Promise((done, reject) => {
    let received = Buffer.alloc(0);
    const cleanup = () => { clearTimeout(deadline); socket.removeListener("data", data); socket.removeListener("close", closed); };
    const closed = () => { cleanup(); reject(new Error("native NIC echo closed")); };
    const deadline = setTimeout(() => { cleanup(); reject(new Error("native NIC echo timed out")); }, 3000);
    const data = (bytes) => {
      received = Buffer.concat([received, bytes]);
      if (received.length >= Buffer.byteLength(message)) { cleanup(); done(received.toString()); }
    };
    socket.once("close", closed); socket.on("data", data); socket.write(message);
  });
}
