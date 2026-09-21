import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { Sandsurf, type SandboxProcess } from "../packages/sandbox/dist/index.js";
import { NativeHostClient } from "../packages/sandbox/dist/native-host.js";

if (process.platform !== "linux") throw new Error("direct network qualification requires Linux/KVM");
const localManifest = process.env.SANDSURF_LOCAL_IMAGE_MANIFEST;
const emptyDisk = process.env.SANDSURF_EMPTY_DISK_IMAGE;
if (localManifest === undefined || !isAbsolute(localManifest) || emptyDisk === undefined || !isAbsolute(emptyDisk)) {
  throw new Error("SANDSURF_LOCAL_IMAGE_MANIFEST and SANDSURF_EMPTY_DISK_IMAGE must be absolute");
}
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

const directory = await mkdtemp(join(tmpdir(), "sandsurf-direct-network-"));
let host: Sandsurf | undefined;
try {
  host = await Sandsurf.open({ directory, authorizer: async () => true });
  const image = await host.images.importOCI({
    source: { kind: "registry", reference: "alpine:3.22" },
    operationId: "direct-image-import",
  });
  const sandbox = await host.sandboxes.create({
    id: "direct-network",
    operationId: "direct-create",
    image: image.id,
    resources: { vcpus: 1, memoryMiB: 512, diskBytes: 1024 * 1024 * 1024, processes: 64 },
    capabilities: { spawn: true, "workload-admin": true },
  });
  await sandbox.network.configure({
    rules: [{
      plane: "direct-tcp",
      destination: { kind: "ip", cidr: `${hostAddress}/32` },
      ports: [bound.port],
    }],
  }, { operationId: "direct-policy" });
  await sandbox.start("direct-start");

  const allowed = await sandbox.processes.spawn({
    operationId: "direct-allowed",
    processId: "direct-allowed",
    argv: ["/bin/busybox", "wget", "-qO-", `http://${hostAddress}:${bound.port}/qualification`],
    cwd: "/",
    user: "root",
  });
  const allowedState = (await allowed.wait()).state;
  const allowedOutput = await output(allowed);
  if (exitCode(allowedState) !== 0) {
    throw new Error(`allowlisted direct TCP failed: ${JSON.stringify(allowedState)} ${allowedOutput.toString("utf8")}`);
  }
  if (allowedOutput.toString("utf8") !== "sandsurf-direct-tcp-ok\n") {
    throw new Error(`direct TCP returned unexpected bytes: ${allowedOutput.toString("hex")}`);
  }

  const deniedPort = bound.port === 65_535 ? bound.port - 1 : bound.port + 1;
  const denied = await sandbox.processes.spawn({
    operationId: "direct-denied",
    processId: "direct-denied",
    argv: ["/bin/busybox", "wget", "-T", "3", "-qO-", `http://${hostAddress}:${deniedPort}/denied`],
    cwd: "/",
    user: "root",
  });
  const deniedState = (await denied.wait()).state;
  if (exitCode(deniedState) === undefined || exitCode(deniedState) === 0) {
    throw new Error(`non-allowlisted direct TCP was not rejected: ${JSON.stringify(deniedState)}`);
  }

  await sandbox.network.configure({
    rules: [{
      plane: "named-proxy",
      destination: { kind: "dns", name: "example.invalid" },
      ports: [bound.port],
    }],
  }, { operationId: "named-only-policy" });
  const crossPlane = await sandbox.processes.spawn({
    operationId: "direct-cross-plane",
    processId: "direct-cross-plane",
    argv: ["/bin/busybox", "wget", "-T", "3", "-qO-", `http://${hostAddress}:${bound.port}/cross-plane`],
    cwd: "/",
    user: "root",
  });
  const crossPlaneState = (await crossPlane.wait()).state;
  if (exitCode(crossPlaneState) === undefined || exitCode(crossPlaneState) === 0) {
    throw new Error(`named-proxy authority leaked into direct TCP: ${JSON.stringify(crossPlaneState)}`);
  }

  const usage = await sandbox.resources.usage();
  if (usage.networkConnections < 1 || usage.networkRxBytes === 0 || usage.networkTxBytes === 0) {
    throw new Error(`direct TCP was not accounted: ${JSON.stringify(usage)}`);
  }
  await sandbox.stop("direct-stop");
  await sandbox.destroy("direct-destroy");
  process.stdout.write(`${JSON.stringify({ hostAddress, port: bound.port, usage }, null, 2)}\n`);
} finally {
  upstream.close();
  await host?.close();
  try {
    const native = await NativeHostClient.open(directory);
    await native.stopService();
  } catch {
    // A failed qualification may stop the service before cleanup begins.
  }
  await rm(directory, { recursive: true, force: true });
}

async function output(process: SandboxProcess): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let cursor = 0;
  for (;;) {
    const page = await process.readOutput({ after: cursor });
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
