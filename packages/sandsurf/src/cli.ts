#!/usr/bin/env node
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { resolveSandsurfNativeHost } from "./native-host.js";
import { Sandsurf } from "./sandsurf.js";
import type { HostInspection } from "./contracts.js";
import {
  sandsurfServiceDefinition,
  type SandsurfServicePlatform,
} from "./service.js";

export async function main(arguments_: readonly string[]): Promise<number> {
  const [command, ...argumentsRest] = arguments_;
  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(help());
    return 0;
  }
  const allowed = {
    "qualification-config": ["--machine"], "qualification-requirements": [],
    "qualification-accept": ["--run", "--evidence", "--operator"],
    "storage-path": ["--machine"], "storage-volume": ["--machine"],
    inspect: ["--json"], setup: ["--platform", "--json"],
  } as const;
  if (!Object.hasOwn(allowed, command)) throw new TypeError(`Unknown Sandsurf command: ${command}`);
  const options = parse(argumentsRest, allowed[command as keyof typeof allowed]);
  if (["qualification-config", "qualification-requirements", "qualification-accept"].includes(command)) {
    const args = [command, "--directory", options.directory];
    if (command === "qualification-config") {
      if (options.machine === undefined) throw new TypeError("qualification-config requires --machine");
      args.push("--machine", options.machine);
    }
    if (command === "qualification-accept") {
      if (options.run === undefined || options.evidence === undefined || options.operator === undefined) throw new TypeError("qualification-accept requires --run, --evidence and --operator");
      args.push("--run", options.run, "--evidence", options.evidence, "--operator", options.operator);
    }
    return runNative(args);
  }
  if (command === "storage-path" || command === "storage-volume") {
    if (command === "storage-path" && options.machine === undefined) throw new TypeError("storage-path requires --machine");
    return runNative([command, "--directory", options.directory, ...(options.machine === undefined ? [] : ["--machine", options.machine])]);
  }
  if (command === "inspect") {
    const host = await Sandsurf.open({ directory: options.directory });
    try {
      const inspection = await host.inspect();
      process.stdout.write(
        options.json ? `${JSON.stringify(inspection, null, 2)}\n` : inspectionText(inspection),
      );
      return 0;
    } finally {
      await host.close();
    }
  }
  if (command === "setup") {
    const definition = await sandsurfServiceDefinition({
      directory: options.directory,
      ...(options.platform === undefined ? {} : { platform: options.platform }),
    });
    process.stdout.write(
      options.json
        ? `${JSON.stringify(definition, null, 2)}\n`
        : `${definition.files.map((file) => `# ${file.name}\n${file.contents}`).join("\n")}\n# ${definition.installHint}\n`,
    );
    return 0;
  }
  throw new TypeError(`Unknown Sandsurf command: ${command}`);
}

async function runNative(arguments_: string[]): Promise<number> {
  const binary = await resolveSandsurfNativeHost();
  return new Promise<number>((resolveRun, rejectRun) => {
    execFile(binary, arguments_, { timeout: 30_000, maxBuffer: 64 * 1024 }, (error, stdout, stderr) => {
      process.stdout.write(stdout); process.stderr.write(stderr);
      if (error === null) resolveRun(0);
      else if (typeof error.code === "number") resolveRun(error.code);
      else rejectRun(error);
    });
  });
}

function parse(arguments_: readonly string[], allowed: readonly string[]): {
  readonly directory: string;
  readonly json: boolean;
  readonly platform?: SandsurfServicePlatform;
  readonly machine?: string;
  readonly run?: string;
  readonly evidence?: string;
  readonly operator?: string;
} {
  let directory: string | undefined;
  let json = false;
  let platform: SandsurfServicePlatform | undefined;
  let machine: string | undefined;
  let run: string | undefined;
  let evidence: string | undefined;
  let operator: string | undefined;
  const seen = new Set<string>();
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === undefined || seen.has(argument)) throw new TypeError("duplicate or absent Sandsurf option");
    if (argument !== "--directory" && !allowed.includes(argument)) throw new TypeError(`Invalid option for this Sandsurf command: ${argument}`);
    seen.add(argument);
    if (argument === "--json") json = true;
    else if (argument === "--directory") directory = requiredValue(arguments_, ++index, argument);
    else if (argument === "--run") run = resolve(requiredValue(arguments_, ++index, argument));
    else if (argument === "--evidence") evidence = resolve(requiredValue(arguments_, ++index, argument));
    else if (argument === "--operator") operator = requiredValue(arguments_, ++index, argument);
    else if (argument === "--machine") {
      machine = requiredValue(arguments_, ++index, argument);
      if (!/^[A-Za-z0-9_-]{1,128}$/u.test(machine)) throw new TypeError("invalid machine identity");
    }
    else if (argument === "--platform") {
      const supplied = requiredValue(arguments_, ++index, argument);
      if (supplied !== "linux" && supplied !== "macos" && supplied !== "windows")
        throw new TypeError("--platform must be linux, macos, or windows");
      platform = supplied;
    } else throw new TypeError(`Unknown Sandsurf option: ${String(argument)}`);
  }
  if (directory === undefined) throw new TypeError("--directory is required");
  return {
    directory: resolve(directory),
    json,
    ...(platform === undefined ? {} : { platform }),
    ...(machine === undefined ? {} : { machine }),
    ...(run === undefined ? {} : { run }),
    ...(evidence === undefined ? {} : { evidence }),
    ...(operator === undefined ? {} : { operator }),
  };
}

function requiredValue(arguments_: readonly string[], index: number, option: string): string {
  const value = arguments_[index];
  if (value === undefined || value.startsWith("--"))
    throw new TypeError(`${option} requires a value`);
  return value;
}

function inspectionText(inspection: HostInspection): string {
  const line = (name: string, value: HostInspection["lifecycle"]): string =>
    value.kind === "qualified"
      ? `${name}: qualified (${value.evidence})`
      : `${name}: unqualified (${value.reasons.join("; ")})`;
  return [
    `host: ${inspection.hostId}`,
    `engine: ${inspection.engine} (${inspection.platform}/${inspection.architecture} -> ${inspection.guestPlatform})`,
    line("lifecycle", inspection.lifecycle),
    line("images", inspection.images),
    inspection.fullState.kind === "unsupported"
      ? `full-state: unsupported (${inspection.fullState.reasons.join("; ")})`
      : line("full-state", inspection.fullState.qualification),
    ...inspection.qualificationRecords.map((record) =>
      `accepted ${record.run.scope}: ${record.recordDigest} (build ${record.run.configuration.buildDigest}, hardware ${record.run.configuration.hardwareDigest})`,
    ),
    ...inspection.qualificationIssues.map((issue) => `qualification issue: ${issue}`),
    "",
  ].join("\n");
}

function help(): string {
  return "Usage:\n  sandsurf inspect --directory <absolute-state-directory> [--json]\n  sandsurf setup --directory <absolute-state-directory> [--platform linux|macos|windows] [--json]\n  sandsurf storage-path --directory <absolute-state-directory> --machine <identity>\n  sandsurf storage-volume --directory <absolute-state-directory> [--machine <identity>]\n  sandsurf qualification-config --directory <state-directory> --machine <identity>\n  sandsurf qualification-requirements --directory <state-directory>\n  sandsurf qualification-accept --directory <state-directory> --run <private-run.json> --evidence <private-evidence-file> --operator <identity>\n\ninspect reports capabilities and retained configuration-scoped evidence; it does not perform qualification. setup renders explicit service definitions; storage commands locate or inspect operator volumes. Neither installs services, mounts volumes or enables privileged features. Qualification acceptance retains verified evidence bytes and explicit operator attestation; probes and test execution cannot perform acceptance.\n";
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    },
  );
}
