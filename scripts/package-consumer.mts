import {
  Sandsurf,
  SandsurfHostError,
  type AuthorityChange,
  type NetworkPolicy,
  type ResourceUsage,
  type SandboxGrant,
  type SandboxInspection,
  type SandboxMutationPrecondition,
  type SandboxRevisionPrecondition,
  type SecretVersion,
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
    workspace: { path: "/workspace" },
    user: "agent",
    environment: { CI: "true" },
    workingDirectory: "/workspace",
    network: { egress: "deny" },
    lifetime: { kind: "persistent" },
  });
  const current: SandboxInspection = await box.inspect();
  const policy: NetworkPolicy = await box.network.inspect();
  const grants: readonly SandboxGrant[] = await box.grants.list();
  const usage: ResourceUsage = await box.resources.usage();
  const operation = await host.operations.get("some-operation");
  const revision: SandboxRevisionPrecondition = { expectedRevision: current.configurationRevision };
  const mutation: SandboxMutationPrecondition = { ...revision, ...(box.epoch === undefined ? {} : { expectedEpoch: box.epoch }) };
  const spawn: SpawnOptions = { argv: ["sh", "-lc", "printf ok"], cwd: "/workspace", ...mutation };
  try { await box.processes.spawn(spawn); }
  catch (error) { if (!(error instanceof SandsurfHostError)) throw error; }
  void inspection; void current; void policy; void grants; void usage; void operation; void revision; void (undefined as SecretVersion | undefined);
  await host.close();
}
void consume;
