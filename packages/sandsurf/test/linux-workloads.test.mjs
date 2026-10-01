import assert from "node:assert/strict";
import { lookup } from "node:dns/promises";
import { qualificationDirectory } from "./qualification-storage.mjs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = process.env.SANDSURF_TEST_PACKAGE_ROOT ?? fileURLToPath(new URL("..", import.meta.url));
const { Sandsurf } = await import(pathToFileURL(join(root, "dist/index.js")));
const { NativeHostClient } = await import(pathToFileURL(join(root, "dist/native-host.js")));
const enabled = process.env.SANDSURF_LINUX_QUALIFICATION === "1";

// No mock, prerequisite probe, or compilation result substitutes for this test.
test("installed Linux computer runs package scripts, builds, databases and containers", { skip: !enabled, timeout: 1_200_000 }, async (context) => {
  const directory = await qualificationDirectory("workloads");
  const host = await Sandsurf.open({ directory, authorizer: () => true });
  let machine;
  try {
    const image = (await host.inspect()).defaultImageDigest;
    assert.ok(image);
    machine = await host.machines.create({ id: "linux-workloads", image, resources: {
      vcpus: 1, memoryMiB: 768, diskBytes: 2 * 1024 ** 3,
      outputBytes: 16 * 1024 ** 2, managedExecutions: 64,
    } });
    await ready(machine);
    // Public repository addresses are authorized, not a blanket private-host
    // grant. Pin the repository name so the test does not rely on host-local DNS.
    const addresses = await lookup("dl-cdn.alpinelinux.org", { all: true, family: 4 });
    assert.ok(addresses.length);
    await machine.network.configure({ rules: [
      { plane: "tcp", destination: { kind: "ip", cidr: "0.0.0.0/0", allowPrivateAddresses: false }, ports: [80, 443] },
      { plane: "udp", destination: { kind: "ip", cidr: "1.1.1.1/32", allowPrivateAddresses: false }, ports: [53] },
    ] });
    const hosts = Buffer.from(await machine.fs.readFile("/etc/hosts")).toString();
    await machine.fs.writeFile("/etc/hosts", `${hosts}\n${addresses[0].address} dl-cdn.alpinelinux.org\n`);
    await machine.fs.writeFile("/etc/resolv.conf", "nameserver 1.1.1.1\n");
    context.diagnostic("normal guest package installation, including maintainer scripts");
    await run(machine, "sudo -n apk add --no-cache build-base python3 sqlite docker docker-openrc openssh", 240_000);
    assert.match(await run(machine, "getent passwd sshd; test -d /var/lib/docker; apk info --installed python3 sqlite docker"), /sshd[\s\S]*python3/u);
    await run(machine, "mkdir -p /home/agent/project; printf '#include <stdio.h>\\nint main(void){puts(\"real-build\");}\\n' > /home/agent/project/main.c; cc /home/agent/project/main.c -o /home/agent/project/main; /home/agent/project/main");
    assert.equal(await run(machine, "python3 -c 'import sqlite3; c=sqlite3.connect(\"/home/agent/database\"); c.execute(\"create table durable(value text)\"); c.execute(\"insert into durable values(?)\", (\"retained\",)); c.commit(); print(c.execute(\"pragma integrity_check\").fetchone()[0])'"), "ok\n");
    context.diagnostic("guest namespaces, cgroups, mounts and Docker bridge networking");
    await run(machine, "sudo -n rc-update add docker default; sudo -n rc-service docker start", 120_000);
    await run(machine, "sudo -n sh -c 'tar -C / -cf - bin/busybox lib | docker import - sandsurf-qualification'", 120_000);
    assert.equal(await run(machine, "sudo -n docker run --rm --network bridge --entrypoint /bin/busybox sandsurf-qualification sh -c 'test -e /proc/self/ns/net && test -d /sys/fs/cgroup && echo container-ok'", 120_000), "container-ok\n");
    // The agent can change its Linux firewall and cgroups, but the external
    // gateway still denies a metadata destination and ungranted private hosts.
    await run(machine, "sudo -n sh -c 'iptables -F; iptables -P OUTPUT ACCEPT; ip route show'", 30_000);
    const denial = await execute(machine, "sudo -n /bin/busybox wget -T 3 -qO- http://169.254.169.254/latest/meta-data/", 15_000);
    assert.notEqual(denial.code, 0);
    context.diagnostic("ordinary reboot preserves installed software and service configuration");
    await run(machine, "sudo -n sync");
    const identity = machine.id;
    const generation = machine.generation;
    await machine.executions.spawnShell("sudo -n sh -c 'sleep 1; reboot'");
    await ready(machine, generation);
    assert.equal(machine.id, identity);
    assert.ok(machine.generation > generation);
    assert.equal(await run(machine, "/home/agent/project/main; sqlite3 /home/agent/database 'pragma integrity_check; select value from durable;'"), "real-build\nok\nretained\n");
    assert.match(await run(machine, "sudo -n docker info --format '{{.ServerVersion}}'; rc-status default"), /docker/u);
    context.diagnostic("database recovery after forced native power loss");
    await run(machine, "sqlite3 /home/agent/database \"pragma journal_mode=WAL; insert into durable values('power-loss');\"");
    await machine.powerOff();
    await machine.start();
    await ready(machine);
    assert.equal(await run(machine, "sqlite3 /home/agent/database 'pragma integrity_check; select value from durable order by rowid;'"), "ok\nretained\npower-loss\n");
    context.diagnostic(`Linux workload evidence: ${JSON.stringify(await machine.resources.usage())}`);
  } finally {
    // Retained command output is evidence, not disposable fixture bytes. Leave
    // the private catalog/archive available after machine destruction.
    if (machine !== undefined) await machine.destroy();
    await host.close();
    const admin = await NativeHostClient.open(directory);
    await admin.stopService();
    await admin.stopSupervisor();
    context.diagnostic(`qualification evidence retained at ${directory}`);
  }
});

async function ready(machine, afterGeneration) {
  const deadline = Date.now() + 90_000;
  for (;;) {
    const value = await machine.inspect();
    if (value.management.kind === "current" && (afterGeneration === undefined || machine.generation > afterGeneration)) return;
    assert.ok(Date.now() < deadline, `Linux management did not become available: ${JSON.stringify(value.management)}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}
async function execute(machine, command, timeout) {
  const execution = await machine.executions.spawnShell(command);
  const { state } = await execution.waitCapture({ signal: AbortSignal.timeout(timeout) });
  const chunks = [];
  let cursor = 0;
  for (;;) {
    const page = await execution.output.read({ after: cursor });
    for (const chunk of page.chunks) {
      assert.equal(chunk.cursor, cursor);
      const bytes = Buffer.from(chunk.bytes); chunks.push(bytes); cursor += bytes.length;
    }
    if (cursor === page.available) break;
    assert.ok(page.chunks.length, "retained output made no progress");
  }
  assert.equal(state.kind, "exited");
  assert.equal(state.outcome.kind, "exit");
  return { code: state.outcome.code, output: Buffer.concat(chunks).toString() };
}
async function run(machine, command, timeout = 30_000) {
  const result = await execute(machine, command, timeout);
  assert.equal(result.code, 0, result.output);
  return result.output;
}
