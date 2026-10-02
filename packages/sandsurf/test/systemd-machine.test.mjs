import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { qualificationDirectory, recordChecks } from "./qualification-storage.mjs";

const packageRoot = process.env.SANDSURF_TEST_PACKAGE_ROOT ?? fileURLToPath(new URL("..", import.meta.url));
const { Sandsurf, renderSandsurfServiceDefinition } = await import(pathToFileURL(join(packageRoot, "dist/index.js")).href);
const { resolveSandsurfNativeHost } = await import(pathToFileURL(join(packageRoot, "dist/native-host.js")).href);

test("installed systemd host restart leaves the independently supervised Linux machine running", {
  skip: process.env.SANDSURF_SERVICE_MANAGER_TEST !== "1", timeout: 180_000,
}, async (context) => {
  assert.equal(process.platform, "linux");
  // Explicit qualification prerequisite: fail when requested but unavailable.
  // This test never installs a system-wide unit, changes AppArmor, or enables linger.
  await command("systemctl", ["--user", "show-environment"]);
  const root = await mkdtemp("/var/tmp/sandsurf-systemd-");
  const directory = await qualificationDirectory("systemd");
  const binary = await resolveSandsurfNativeHost();
  const definition = renderSandsurfServiceDefinition({ directory, binary, platform: "linux" });
  const [supervisorUnit, hostUnit] = definition.files;
  let host;
  let machine;
  try {
    for (const file of definition.files) {
      // Separate service groups must have separate memory caps: they do not
      // inherit the test command's resource scope. No guest limits are relaxed.
      await writeFile(join(root, file.name), file.contents);
      await command("systemctl", ["--user", "link", join(root, file.name)]);
    }
    await command("systemctl", ["--user", "daemon-reload"]);
    await command("systemctl", ["--user", "start", supervisorUnit.name, hostUnit.name]);
    host = await ready(directory);
    const manifest = process.env.SANDSURF_LOCAL_IMAGE_MANIFEST ?? join(packageRoot, "images/development-x64/manifest.json");
    const image = createHash("sha256").update(await readFile(manifest)).digest("hex");
    await host.images.importNative({ manifestPath: manifest, manifestDigest: image, operationId: "import-independent-image" });
    machine = await host.machines.create({ id: "independent-machine", image,
      resources: { vcpus: 1, memoryMiB: 256, diskBytes: 2 * 1024 ** 3, outputBytes: 4 * 1024 ** 2, managedExecutions: 8 } });
    await managementReady(machine);
    const generation = machine.generation;
    const execution = await machine.executions.start({ executionId: "surviving-process",
      argv: ["/bin/sh", "-c", "printf before; read value; printf 'after:%s' \"$value\""], stdio: "terminal" });
    const supervisorPid = (await command("systemctl", ["--user", "show", supervisorUnit.name, "--property=MainPID", "--value"])).trim();
    const apiPid = (await command("systemctl", ["--user", "show", hostUnit.name, "--property=MainPID", "--value"])).trim();
    assert.match(supervisorPid, /^[1-9][0-9]*$/u);
    const machinePath = join(directory, "machines", "id-" + createHash("sha256").update(machine.id).digest("hex"));
    const machineUnit = "sandsurf-machine-id-" + createHash("sha256").update(machinePath).digest("hex") + ".service";
    const guardianPid = (await command("systemctl", ["--user", "show", machineUnit, "--property=MainPID", "--value"])).trim();
    assert.match(guardianPid, /^[1-9][0-9]*$/u);
    assert.match(await readFile(`/proc/${guardianPid}/cgroup`, "utf8"), new RegExp(machineUnit.replaceAll(".", "\\."), "u"));
    assert.doesNotMatch(await readFile(`/proc/${guardianPid}/cgroup`, "utf8"), new RegExp(supervisorUnit.name.replaceAll(".", "\\."), "u"));
    assert.doesNotMatch(await readFile(`/proc/${guardianPid}/cgroup`, "utf8"), new RegExp(hostUnit.name.replaceAll(".", "\\."), "u"));
    await host.close(); host = undefined;
    await command("systemctl", ["--user", "restart", hostUnit.name]);
    host = await ready(directory);
    assert.notEqual((await command("systemctl", ["--user", "show", hostUnit.name, "--property=MainPID", "--value"])).trim(), apiPid);
    assert.equal((await command("systemctl", ["--user", "show", supervisorUnit.name, "--property=MainPID", "--value"])).trim(), supervisorPid);
    machine = await host.machines.connect("independent-machine");
    assert.equal(machine.generation, generation);
    assert.equal((await machine.inspect()).machine.value.state, "running");
    assert.equal((await command("systemctl", ["--user", "show", machineUnit, "--property=MainPID", "--value"])).trim(), guardianPid);
    const terminal = await machine.terminals.get(execution.id);
    await terminal.acquireInput();
    await terminal.input.write(new TextEncoder().encode("continued\n"));
    const completion = await terminal.process.waitCapture({ signal: AbortSignal.timeout(30_000) });
    assert.equal(completion.state.outcome.code, 0);
    const page = await terminal.process.output.read({ maximum: 65536 });
    const output = Buffer.concat(page.chunks.map((chunk) => Buffer.from(chunk.bytes))).toString();
    assert.match(output, /before[\s\S]*after:continued/u);
    context.diagnostic("real KVM machine, keeper and PTY survive a default-cgroup systemd API-service restart");
    await recordChecks(directory, machine, ["installed-package", "service-restart", "host-service-restart"], { generation, guardianPid, supervisorPid,
      machineUnit, apiUnit: hostUnit.name, continuedTerminal: output });
  } finally {
    try { if (machine !== undefined) { await machine.inspect(); await machine.destroy(); } }
    finally {
      if (host !== undefined) await host.close();
      // Exact units produced by this fixture only; no broad manager shutdown.
      for (const file of [...definition.files].reverse()) {
        await command("systemctl", ["--user", "stop", file.name]).catch(() => {});
        await command("systemctl", ["--user", "disable", file.name]).catch(() => {});
        await command("systemctl", ["--user", "reset-failed", file.name]).catch(() => {});
      }
      await command("systemctl", ["--user", "daemon-reload"]);
      await rm(root, { recursive: true, force: true });
    }
  }
});

async function ready(directory) {
  const deadline = Date.now() + 30_000;
  let last;
  do {
    try { return await Sandsurf.open({ directory, service: "connect", authorizer: () => true }); }
    catch (error) { last = error; await new Promise((done) => setTimeout(done, 50)); }
  } while (Date.now() < deadline);
  throw last;
}
async function managementReady(machine) {
  const deadline = Date.now() + 60_000;
  let last;
  do {
    try { await machine.fs.stat("/etc/passwd"); return; }
    catch (error) { last = error; await new Promise((done) => setTimeout(done, 100)); }
  } while (Date.now() < deadline);
  throw last;
}
function command(binary, arguments_) {
  return new Promise((done, reject) => {
    const child = spawn(binary, arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    let output = ""; let error = "";
    child.stdout.on("data", (bytes) => { output = (output + bytes).slice(-65536); });
    child.stderr.on("data", (bytes) => { error = (error + bytes).slice(-4096); });
    child.once("error", reject);
    child.once("exit", (code) => code === 0 ? done(output) : reject(new Error(`${binary} failed (${code}): ${error}`)));
  });
}
