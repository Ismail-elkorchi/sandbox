import {
  Sandsurf, SandsurfHostError,
  type Artifact, type AuthorityChange, type ChangeSet, type MachineInspection,
  type MachineGenerationPrecondition, type MachineRevisionPrecondition,
  type NetworkPolicy, type ResourceUsage, type SecretVersion, type SpawnOptions,
} from "sandsurf";

async function consume(directory: string, image: string): Promise<void> {
  const host = await Sandsurf.open({
    directory,
    authorizer(change: AuthorityChange) { return { approvalId: `approval-${change.operationId}` }; },
  });
  try {
    const computer = await host.machines.create({
      image, resources: { vcpus: 2, memoryMiB: 2048, diskBytes: 20 * 1024 ** 3 },
      user: "agent", environment: { CI: "true" }, workingDirectory: "/home/agent",
    });
    const current: MachineInspection = await computer.inspect();
    const policy: NetworkPolicy = await computer.network.inspect();
    const usage: ResourceUsage = await computer.resources.usage();
    const revision: MachineRevisionPrecondition = { expectedRevision: current.configurationRevision };
    const generation: MachineGenerationPrecondition = computer.generation === undefined ? {} : { expectedGeneration: computer.generation };
    const spawn: SpawnOptions = { argv: ["/bin/sh", "-c", "sudo -n id -u"], ...generation };
    const execution = await computer.executions.start(spawn);
    await execution.waitLeader();
    await execution.waitCapture();
    const home = computer.fs.at("/home/agent");
    await home.writeFile("source.txt", new TextEncoder().encode("captured bytes\n"));
    const artifact: Artifact = await computer.artifacts.capture("/home/agent", revision);
    const changes: ChangeSet = artifact.compare();
    for await (const bytes of artifact.readStream("source.txt")) void bytes;
    const retained = await host.artifacts.get(computer.id, artifact.id);
    const snapshot = await computer.snapshots.create({ kind: "disk", ...revision, ...generation });
    const fork = await snapshot.fork();
    await retained.writeTo(fork, "/tmp/captured");
    const operation = await host.operations.get(snapshot.inspection.operationId);
    void policy; void usage; void changes; void operation; void (undefined as SecretVersion | undefined);
  } catch (error) {
    if (!(error instanceof SandsurfHostError)) throw error;
  } finally { await host.close(); }
}
void consume;
