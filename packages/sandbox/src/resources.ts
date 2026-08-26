export interface ResourceLimits {
  wallTimeMs: number;
  cpuTimeMs?: number;
  memoryBytes: number;
  maxProcesses: number;
  maxOpenFilesPerProcess?: number;
  maxSingleFileBytes?: number;
  maxOutputBytes: number;
  terminationGraceMs: number;
}
