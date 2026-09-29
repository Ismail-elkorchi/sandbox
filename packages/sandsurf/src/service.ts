import { createHash } from "node:crypto";
import { isAbsolute, posix, resolve, win32 } from "node:path";
import { resolveSandsurfNativeHost } from "./native-host.js";

export type SandsurfServicePlatform = "linux" | "macos" | "windows";

export interface SandsurfServiceDefinition {
  readonly platform: SandsurfServicePlatform;
  readonly format: "systemd-user" | "launchd-agent" | "windows-scm-powershell";
  readonly name: string;
  readonly contents: string;
  readonly installHint: string;
}

export interface SandsurfServiceDefinitionOptions {
  readonly directory: string;
  readonly binary?: string;
  readonly platform?: SandsurfServicePlatform;
}

/** Render a service definition without installing it or changing host privileges. */
export async function sandsurfServiceDefinition(
  options: SandsurfServiceDefinitionOptions,
): Promise<SandsurfServiceDefinition> {
  const directory = resolve(options.directory);
  if (!isAbsolute(directory)) throw new TypeError("Sandsurf service directory must be absolute");
  const binary =
    options.binary === undefined ? await resolveSandsurfNativeHost() : resolve(options.binary);
  if (!isAbsolute(binary)) throw new TypeError("Sandsurf service binary must be absolute");
  return renderSandsurfServiceDefinition({
    directory,
    binary,
    platform: options.platform ?? currentPlatform(),
  });
}

export function renderSandsurfServiceDefinition(options: {
  readonly directory: string;
  readonly binary: string;
  readonly platform: SandsurfServicePlatform;
}): SandsurfServiceDefinition {
  if (
    !servicePathIsAbsolute(options.directory, options.platform) ||
    !servicePathIsAbsolute(options.binary, options.platform)
  )
    throw new TypeError("Sandsurf service paths must be absolute");
  const suffix = createHash("sha256").update(options.directory).digest("hex").slice(0, 12);
  const serviceName = `sandsurf-${suffix}`;
  switch (options.platform) {
    case "linux":
      return Object.freeze({
        platform: "linux",
        format: "systemd-user",
        name: `${serviceName}.service`,
        contents: `[Unit]\nDescription=Sandsurf host service (${options.directory})\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=${systemdArgument(options.binary)} serve --directory ${systemdArgument(options.directory)}\nRestart=on-failure\nRestartSec=1\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n`,
        installHint: `Write this unit to ~/.config/systemd/user/${serviceName}.service, then run systemctl --user daemon-reload and systemctl --user enable --now ${serviceName}.service.`,
      });
    case "macos": {
      const label = `dev.sandsurf.host.${suffix}`;
      return Object.freeze({
        platform: "macos",
        format: "launchd-agent",
        name: `${label}.plist`,
        contents: `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n  <key>Label</key><string>${xml(label)}</string>\n  <key>ProgramArguments</key><array>\n    <string>${xml(options.binary)}</string><string>serve</string><string>--directory</string><string>${xml(options.directory)}</string>\n  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ProcessType</key><string>Interactive</string>\n</dict></plist>\n`,
        installHint: `Write this plist to ~/Library/LaunchAgents/${label}.plist, then run launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/${label}.plist. The packaged VM owner still requires the Apple virtualization entitlement/signature to qualify.`,
      });
    }
    case "windows": {
      const windowsName = `Sandsurf-${suffix}`;
      const command = `\"${options.binary}\" service --directory \"${options.directory}\" --service-name \"${windowsName}\"`;
      return Object.freeze({
        platform: "windows",
        format: "windows-scm-powershell",
        name: windowsName,
        contents: `$binaryPath = '${powershell(command)}'\n$serviceUser = \"$env:USERDOMAIN\\$env:USERNAME\"\n$credential = Get-Credential -UserName $serviceUser -Message 'Account for the unprivileged Sandsurf host service'\nNew-Item -ItemType Directory -Force -Path '${powershell(options.directory)}' | Out-Null\nicacls '${powershell(options.directory)}' /inheritance:r /grant:r \"$($serviceUser):(OI)(CI)F\" 'SYSTEM:(OI)(CI)F' | Out-Null\nNew-Service -Name '${windowsName}' -DisplayName 'Sandsurf Host (${powershell(options.directory)})' -BinaryPathName $binaryPath -Credential $credential -StartupType Automatic\nStart-Service -Name '${windowsName}'\n`,
        installHint:
          "Run this PowerShell definition from an elevated shell after enabling and rebooting into Hyper-V. The selected unprivileged account needs the Log on as a service right and access to the qualified HCS helper.",
      });
    }
  }
}

function currentPlatform(): SandsurfServicePlatform {
  if (process.platform === "linux") return "linux";
  if (process.platform === "darwin") return "macos";
  if (process.platform === "win32") return "windows";
  throw new TypeError(`Sandsurf has no service definition for ${process.platform}`);
}

function servicePathIsAbsolute(value: string, platform: SandsurfServicePlatform): boolean {
  return platform === "windows" ? win32.isAbsolute(value) : posix.isAbsolute(value);
}

function systemdArgument(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function xml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function powershell(value: string): string {
  return value.replaceAll("'", "''");
}
