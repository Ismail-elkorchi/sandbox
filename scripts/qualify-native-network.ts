import { lookup } from "node:dns/promises";
import { networkInterfaces } from "node:os";
import { isAbsolute } from "node:path";
import { Sandsurf, type Machine } from "../packages/sandsurf/dist/index.js";
import { NativeHostClient } from "../packages/sandsurf/dist/native-host.js";

if (process.platform !== "linux") throw new Error("native NIC qualification requires Linux/KVM");
const directory = process.env.SANDSURF_NATIVE_NETWORK_DIRECTORY;
if (directory === undefined || !isAbsolute(directory)) throw new Error("set SANDSURF_NATIVE_NETWORK_DIRECTORY to a bounded operator-provisioned host volume containing the native-network-hardware storage slot");
const host = await Sandsurf.open({ directory, authorizer: () => true });
let machine: Machine | undefined;
try {
  const image = (await host.inspect()).defaultImageDigest;
  if (image === null) throw new Error("qualification requires an installed machine image");
  machine = await host.machines.create({ id: "native-network-hardware", image, resources: { vcpus: 1, memoryMiB: 512, diskBytes: 2 * 1024 ** 3 } });
  await ready(machine);
  const address = (await lookup("example.com", { family: 4 })).address;
  await machine.network.configure({ rules: [{ plane: "tcp", destination: {
    kind: "ip", cidr: `${address}/32`, allowPrivateAddresses: false,
  }, ports: [80] }] });
  const connected = await execute(machine, `printf 'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n' | nc -w 10 ${address} 80`);
  if (connected.code !== 0 || !connected.output.includes("Example Domain")) throw new Error(`native TCP failed: ${connected.output}`);
  const addresses = Object.values(networkInterfaces()).flat().filter((value) => value?.family === "IPv4" && !value.internal);
  for (const denied of ["169.254.169.254", "127.0.0.1", "100.64.0.3", ...addresses.map((value) => value!.address)]) {
    const result = await execute(machine, `nc -w 2 ${denied} 80 < /dev/null`);
    if (result.code === 0) throw new Error(`guest reached protected destination ${denied}`);
  }
  // Root's guest firewall changes cannot increase the external policy.
  await machine.network.configure({ rules: [] });
  const revoked = await execute(machine, `printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc -w 2 ${address} 80`);
  if (revoked.output.includes("HTTP/")) throw new Error("revoked native TCP still reached the destination");
  const usage = await machine.resources.usage();
  if (usage.networkConnections < 1 || usage.networkRxBytes === 0 || usage.networkTxBytes === 0) throw new Error(`native NIC traffic is not accounted: ${JSON.stringify(usage)}`);
  process.stdout.write(`${JSON.stringify({ directory, address, usage }, null, 2)}\n`);
} finally {
  if (machine !== undefined) await machine.destroy();
  await host.close();
  const admin = await NativeHostClient.open(directory);
  await admin.stopService();
  await admin.stopSupervisor();
  process.stderr.write(`native-network qualification evidence retained at ${directory}\n`);
}

async function ready(value: Machine): Promise<void> {
  const deadline = Date.now() + 60_000;
  while ((await value.inspect()).management.kind !== "current") {
    if (Date.now() > deadline) throw new Error("Linux management did not become available");
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
  }
}

async function execute(value: Machine, command: string): Promise<{ code: number; output: string }> {
  const execution = await value.executions.spawnShell(command);
  const { state } = await execution.waitCapture({ signal: AbortSignal.timeout(30_000) });
  if (state.kind !== "exited" || state.outcome.kind !== "exit") throw new Error(`execution did not exit normally: ${JSON.stringify(state)}`);
  const chunks: Buffer[] = [];
  let cursor = 0;
  for (;;) {
    const page = await execution.output.read({ after: cursor });
    for (const chunk of page.chunks) {
      if (chunk.cursor !== cursor) throw new Error("retained network output has a gap");
      const bytes = Buffer.from(chunk.bytes); chunks.push(bytes); cursor += bytes.length;
    }
    if (cursor === page.available) break;
    if (page.chunks.length === 0) throw new Error("retained output made no progress");
  }
  return { code: state.outcome.code, output: Buffer.concat(chunks).toString() };
}
