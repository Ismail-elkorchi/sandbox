import {
  openSandboxExecutionRepository,
  SandboxExecutionControlError,
  type SandboxExecutionObservation,
  type SandboxExecutionReceipt,
} from "@ismail-elkorchi/sandbox";

async function consume(directory: string, executionId: string): Promise<void> {
  const repository = await openSandboxExecutionRepository({ directory, maxRetainedExecutions: 10, maxTotalMetadataBytes: 128 * 1024 * 1024 });
  const page = await repository.reconcile({ limit: 5 });
  for (const observation of page.observations) classify(observation);
  const observation = await repository.inspect(executionId, { maxBytes: 1024 });
  if (observation.output.kind === "available") {
    const original: Uint8Array | undefined = observation.output.chunks[0]?.data;
    void original;
  }
  if (observation.kind === "settled" || observation.kind === "rejected") {
    const receipt: SandboxExecutionReceipt = observation.receipt;
    await repository.forget(executionId, { receiptDigest: receipt.digest });
  }
  try { await repository.writeInput(executionId, new Uint8Array()); }
  catch (error) {
    if (error instanceof SandboxExecutionControlError) {
      const delivery: "unknown" | "not-applied" = error.delivery;
      void delivery;
    }
  }
  // @ts-expect-error Release must identify the durably consumed receipt.
  await repository.forget(executionId);
  // @ts-expect-error Output bytes require the independent availability check.
  void observation.output.chunks;
  await repository.close();
}

function classify(observation: SandboxExecutionObservation): string {
  switch (observation.kind) {
    case "preparing": case "prepared": case "running": case "settled":
    case "rejected": case "unknown": case "retired": return observation.kind;
    default: { const exhaustive: never = observation; return exhaustive; }
  }
}
void consume;
