import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { Sandsurf, type Execution, type Machine } from "../packages/sandsurf/dist/index.js";
import { NativeHostClient } from "../packages/sandsurf/dist/native-host.js";

if (process.platform !== "linux") throw new Error("direct network qualification requires Linux/KVM");
const hostAddress = Object.values(networkInterfaces()).flat().find((value) =>
  value !== undefined && value.family === "IPv4" && !value.internal,
)?.address;
if (hostAddress === undefined) throw new Error("qualification host has no non-loopback IPv4 address");

const upstream = createServer((socket) => {
  socket.end("HTTP/1.1 200 OK\r\nContent-Length: 23\r\nConnection: close\r\n\r\nsandsurf-direct-tcp-ok\n");
});
await new Promise<void>((resolveListen, rejectListen) => {
  upstream.once("error", rejectListen);
  upstream.listen(0, "0.0.0.0", resolveListen);
});
const bound = upstream.address();
if (bound === null || typeof bound === "string") throw new Error("qualification server did not bind TCP");

const directory = await mkdtemp("/var/tmp/sandsurf-direct-network-");
let host: Sandsurf | undefined;
let machine: Machine | undefined;
const executions: Execution[] = [];
let outputReleased = false;
try {
  host = await Sandsurf.open({ directory, authorizer: async () => true });
  const image = (await host.inspect()).defaultImageDigest;
  if (image === null) throw new Error("qualification requires an installed machine image");
  machine = await host.machines.create({
    id: "direct-network",
    operationId: "direct-create",
    image,
    resources: { vcpus: 1, memoryMiB: 512, diskBytes: 1024 * 1024 * 1024, managedExecutions: 64 },
  });
  await machine.network.configure({
    rules: [{
      plane: "direct-tcp",
      destination: { kind: "ip", cidr: `${hostAddress}/32` },
      ports: [bound.port],
    }],
  }, { operationId: "direct-policy" });
  for (const deadline = Date.now() + 30_000; ; ) {
    if ((await machine.inspect()).management.kind === "current") break;
    if (Date.now() >= deadline) throw new Error("guest management did not become available");
    await new Promise<void>((resolveWait) => setTimeout(resolveWait, 100));
  }

  const allowed = await machine.executions.start({
    operationId: "direct-allowed",
    executionId: "direct-allowed",
    argv: ["/bin/busybox", "wget", "-qO-", `http://${hostAddress}:${bound.port}/qualification`],
    cwd: "/",
    user: "root",
  });
  executions.push(allowed);
  const allowedState = (await allowed.waitCapture()).state;
  const allowedOutput = await output(allowed);
  if (exitCode(allowedState) !== 0) {
    throw new Error(`allowlisted direct TCP failed: ${JSON.stringify(allowedState)} ${allowedOutput.toString("utf8")}`);
  }
  if (allowedOutput.toString("utf8") !== "sandsurf-direct-tcp-ok\n") {
    throw new Error(`direct TCP returned unexpected bytes: ${allowedOutput.toString("hex")}`);
  }

  const deniedPort = bound.port === 65_535 ? bound.port - 1 : bound.port + 1;
  const denied = await machine.executions.start({
    operationId: "direct-denied",
    executionId: "direct-denied",
    argv: ["/bin/busybox", "wget", "-T", "3", "-qO-", `http://${hostAddress}:${deniedPort}/denied`],
    cwd: "/",
    user: "root",
  });
  executions.push(denied);
  const deniedState = (await denied.waitCapture()).state;
  if (exitCode(deniedState) === undefined || exitCode(deniedState) === 0) {
    throw new Error(`non-allowlisted direct TCP was not rejected: ${JSON.stringify(deniedState)}`);
  }

  await machine.network.configure({
    rules: [{
      plane: "named-proxy",
      destination: { kind: "dns", name: "example.invalid" },
      ports: [bound.port],
    }],
  }, { operationId: "named-only-policy" });
  const crossPlane = await machine.executions.start({
    operationId: "direct-cross-plane",
    executionId: "direct-cross-plane",
    argv: ["/bin/busybox", "wget", "-T", "3", "-qO-", `http://${hostAddress}:${bound.port}/cross-plane`],
    cwd: "/",
    user: "root",
  });
  executions.push(crossPlane);
  const crossPlaneState = (await crossPlane.waitCapture()).state;
  if (exitCode(crossPlaneState) === undefined || exitCode(crossPlaneState) === 0) {
    throw new Error(`named-proxy authority leaked into direct TCP: ${JSON.stringify(crossPlaneState)}`);
  }

  const usage = await machine.resources.usage();
  if (usage.networkConnections < 1 || usage.networkRxBytes === 0 || usage.networkTxBytes === 0) {
    throw new Error(`direct TCP was not accounted: ${JSON.stringify(usage)}`);
  }
  await machine.powerOff({ operationId: "direct-stop" });
  await machine.destroy({ operationId: "direct-destroy" });
  await releaseTestOutput();
  machine = undefined;
  process.stdout.write(`${JSON.stringify({ hostAddress, port: bound.port, usage }, null, 2)}\n`);
} finally {
  upstream.close();
  if (machine !== undefined) {
    try {
      await machine.powerOff();
      await machine.destroy();
      await releaseTestOutput();
      machine = undefined;
    } catch {
      process.stderr.write(`qualification state retained at ${directory}\n`);
    }
  }
  await host?.close();
  try {
    const native = await NativeHostClient.open(directory);
    await native.stopService();
  } catch {
    // A failed qualification may stop the service before cleanup begins.
  }
  if (machine === undefined && outputReleased) await rm(directory, { recursive: true, force: true });
  else process.stderr.write(`qualification state and output retained at ${directory}\n`);
}

async function releaseTestOutput(): Promise<void> {
  for (const execution of executions) {
    const receipt = await execution.receipt();
    if (receipt === undefined) throw new Error(`output receipt not captured for ${execution.id}`);
    const released = await execution.release(receipt, { kind: "authorized-loss" });
    if ((await execution.cleanupReleased(released.requestDigest)).cleanupPending) {
      throw new Error(`output cleanup is still pending for ${execution.id}`);
    }
  }
  outputReleased = true;
}

async function output(process: Execution): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let cursor = 0;
  for (;;) {
    const page = await process.output.read({ after: cursor });
    for (const chunk of page.chunks) {
      if (chunk.cursor !== cursor) throw new Error("process output is non-contiguous");
      const bytes = Buffer.from(chunk.bytes);
      chunks.push(bytes);
      cursor += bytes.byteLength;
    }
    if (cursor === page.available) return Buffer.concat(chunks);
    if (page.chunks.length === 0) throw new Error("process output page made no progress");
  }
}

function exitCode(state: Readonly<Record<string, unknown>>): number | undefined {
  const outcome = state.outcome;
  if (state.kind !== "exited" || typeof outcome !== "object" || outcome === null) return undefined;
  const value = outcome as Readonly<Record<string, unknown>>;
  return value.kind === "exit" && Number.isSafeInteger(value.code) ? value.code as number : undefined;
}
