export type SandboxEnvironmentValue =
  | string
  | { value: string; sensitive: true };

export interface SandboxEnvironment {
  inherit?: readonly string[];
  set?: Readonly<Record<string, SandboxEnvironmentValue>>;
  unset?: readonly string[];
}
