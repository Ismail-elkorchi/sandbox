import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Sandsurf } from "../packages/sandbox/dist/index.js";
import { NativeHostClient } from "../packages/sandbox/dist/native-host.js";

if (process.platform !== "linux") throw new Error("Linux qualification ran on another host");
const directory = await mkdtemp(join(tmpdir(), "sandsurf-linux-qualification-"));
try {
  const first = await Sandsurf.open({ directory });
  const inspection = await first.inspect();
  if (inspection.platform !== "linux" || inspection.engine !== "firecracker") {
    throw new Error(`unexpected Linux host contract: ${JSON.stringify(inspection)}`);
  }
  await first.close();
  await (await NativeHostClient.open(directory)).stopService();
  const reconnected = await Sandsurf.open({ directory });
  const afterRestart = await reconnected.inspect();
  if (afterRestart.hostId !== inspection.hostId) throw new Error("host identity changed after reconnect");
  await reconnected.close();
  process.stdout.write(`${JSON.stringify(afterRestart, null, 2)}\n`);
  await (await NativeHostClient.open(directory)).stopService();
} finally {
  await rm(directory, { recursive: true, force: true });
}
