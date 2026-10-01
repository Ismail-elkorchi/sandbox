import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { qualificationDirectory } from "./qualification-storage.mjs";
import { join, resolve } from "node:path";
import { createConnection } from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const enabled = process.env.SANDSURF_KVM_NETWORK_TEST === "1";
const packageRoot = process.env.SANDSURF_TEST_PACKAGE_ROOT ?? fileURLToPath(new URL("..", import.meta.url));

test("KVM native NIC survives removal of management and inbound revocation closes an existing flow", {
  skip: !enabled, timeout: 180_000,
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
    await machine.powerOff();
    assert.equal((await machine.inspect()).machine.value.state, "stopped");
  } finally {
    client?.destroy();
    if (machine !== undefined) { await machine.powerOff().catch(() => {}); await machine.destroy(); }
    await host.close();
    // Retain the native journal/state directory as qualification evidence.
  }
});

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
    const deadline = setTimeout(() => { socket.removeListener("data", data); reject(new Error("native NIC echo timed out")); }, 3000);
    const data = (bytes) => {
      received = Buffer.concat([received, bytes]);
      if (received.length >= Buffer.byteLength(message)) { clearTimeout(deadline); socket.removeListener("data", data); done(received.toString()); }
    };
    socket.on("data", data); socket.write(message);
  });
}
