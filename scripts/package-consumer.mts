import {
  Sandsurf,
  SandsurfHostError,
  type AuthorityChange,
  type SandboxInspection,
  type SpawnOptions,
} from "sandsurf";

async function consume(directory: string, image: string): Promise<void> {
  const host = await Sandsurf.open({
    directory,
    authorizer(change: AuthorityChange) {
      return { approvalId: `approval-${change.operationId}` };
    },
  });
  const inspection = await host.inspect();
  const box = await host.sandboxes.create({
    image,
    resources: { vcpus: 2, memoryMiB: 2048, diskBytes: 20 * 1024 ** 3 },
  });
  const current: SandboxInspection = await box.inspect();
  const spawn: SpawnOptions = { argv: ["sh", "-lc", "printf ok"], cwd: "/workspace" };
  try { await box.processes.spawn(spawn); }
  catch (error) { if (!(error instanceof SandsurfHostError)) throw error; }
  void inspection; void current;
  await host.close();
}
void consume;
