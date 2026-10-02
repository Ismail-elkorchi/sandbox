import assert from "node:assert/strict";
import test from "node:test";
import { parseUsage } from "../dist/observations.js";
import { validateProtocol } from "../dist/protocol-validation.js";

function usage() {
  return { provenance: { cpu: "unavailable", memory: "host-job", io: "host-job", storage: "host-filesystem",
    output: "host-retention", executions: "host-admission", channels: "host-admission", network: "host-network" },
    hostCounterEpoch: "e".repeat(64), channelsCurrent: 1, inflightRequestsCurrent: 0,
    cpuMicros: null, cpuLedgers: { nativeMicros: 10, nativeSource: "host-job", partitionMicros: 100,
      partitionHypervisorMicros: 5, partitionSource: "host-partition" },
    memoryCurrent: 1024, memoryPeak: null, diskLogicalBytes: 100, diskAllocatedBytes: 80,
    ioReadBytes: 1, ioWriteBytes: 2, outputRetainedBytes: 3, networkRxBytes: 4, networkTxBytes: 5,
    networkConnections: 1, executionsCurrent: 1, complete: false, source: "host-catalog-cumulative(host-native-qemu)", observedUnixMillis: 1000 };
}

test("native CPU domains survive SDK parsing without becoming a manufactured total", () => {
  const sample = usage(); validateProtocol("ResourceUsage", sample);
  assert.deepEqual(parseUsage(sample), sample);
  assert.equal(parseUsage(sample).cpuMicros, null);
  sample.cpuLedgers = null;
  assert.equal(parseUsage(sample).cpuLedgers, null);
  sample.provenance.cpu = "host-darwin-task"; sample.provenance.memory = "host-darwin-task";
  sample.provenance.io = "host-darwin-task"; sample.cpuMicros = 12;
  validateProtocol("ResourceUsage", sample);
  assert.equal(parseUsage(sample).provenance.cpu, "host-darwin-task");
});

test("the SDK uses the generated measurement vocabulary and rejects malformed ledgers", () => {
  for (const mutation of [
    (value) => { delete value.cpuLedgers; },
    (value) => { value.cpuLedgers.nativeSource = "guest-attested"; },
    (value) => { value.cpuLedgers.partitionMicros = -1; },
    (value) => { value.cpuLedgers.nativeMicros = Number.MAX_SAFE_INTEGER + 1; },
    (value) => { value.cpuLedgers.partitionHypervisorMicros = Infinity; },
    (value) => { value.cpuLedgers.extraTotal = 115; },
    (value) => { value.provenance.memory = "pid-lookup"; },
    (value) => { value.provenance.extra = "host-job"; },
  ]) {
    const sample = usage(); mutation(sample);
    assert.throws(() => parseUsage(sample));
    assert.throws(() => validateProtocol("ResourceUsage", sample));
  }
});
