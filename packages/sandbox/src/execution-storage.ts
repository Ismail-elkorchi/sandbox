import { constants, lstatSync } from "node:fs";
import { chmod, lstat, open, readdir } from "node:fs/promises";
import { join } from "node:path";
import { createRequire } from "node:module";
import type { DatabaseSync } from "node:sqlite";

const require = createRequire(import.meta.url);

// The catalog is the sole admission/state/retirement authority. Output is kept
// separately; publishing its final boundary and result is one SQL transaction.
const CATALOG = "executions.sqlite";
export const BASE_RECORD_BYTES = 8 * 1024 * 1024;
export const MAX_RECORD_BYTES = BASE_RECORD_BYTES + 2 * 128 * 1024 * 1024;

export interface StorageLimits {
  maxRetainedOutputBytes: number;
  maxTotalOutputBytes: number;
  maxTotalMetadataBytes: number;
  maxRetainedExecutions: number;
  maxRetainedIdentities: number;
}

export async function initializeStorage(root: string, limits: StorageLimits): Promise<void> {
  const path = join(root, CATALOG);
  try {
    const file = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    await file.close();
  } catch (error) {
    if (nodeCode(error) !== "EEXIST") throw error;
  }
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error("Execution catalog must be a regular, non-symbolic file.");
  if (process.platform !== "win32") await chmod(path, 0o600);
  const existing = withStorage(root, (db) => {
    const table = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'configuration'").get();
    if (table === undefined) return false;
    if (db.prepare("SELECT value FROM configuration WHERE id = 1").get()?.value !== JSON.stringify(limits)) {
      throw new Error("Execution repository storage limits differ from its committed configuration.");
    }
    return true;
  });
  if (existing) return;
  // Only first initialization checks for incompatible legacy directories.
  // Reopening a catalog and inspecting an identity never enumerate executions.
  const hasExistingRecords = (await readdir(root)).some((entry) => entry.startsWith("execution-"));
  withStorage(root, (db) => {
    transaction(db, () => {
      const initialized = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'configuration'").get();
      if (initialized === undefined) {
        if (hasExistingRecords) {
          throw new Error("Incompatible stored execution repository; existing records have been left intact.");
        }
        db.exec(`
          CREATE TABLE configuration (id INTEGER PRIMARY KEY CHECK (id = 1), value TEXT NOT NULL) STRICT;
          CREATE TABLE executions (
            sequence INTEGER PRIMARY KEY,
            execution_id TEXT NOT NULL UNIQUE,
            request_digest TEXT NOT NULL,
            reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
            reserved_metadata INTEGER NOT NULL CHECK (reserved_metadata >= 0),
            retained INTEGER NOT NULL CHECK (retained IN (0, 1)),
            state TEXT NOT NULL,
            control TEXT
          ) STRICT;
        `);
        db.prepare("INSERT INTO configuration VALUES (1, ?)").run(JSON.stringify(limits));
      } else {
        const stored = db.prepare("SELECT value FROM configuration WHERE id = 1").get();
        if (stored?.value !== JSON.stringify(limits)) throw new Error("Execution repository storage limits differ from its committed configuration.");
      }
    });
  });
}

export function withStorage<T>(root: string, operation: (db: DatabaseSync) => T): T {
  const metadata = lstatSync(join(root, CATALOG));
  if (!metadata.isFile() || metadata.isSymbolicLink()) throw new TypeError("Execution catalog must be a regular, non-symbolic file.");
  const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");
  const db = new DatabaseSync(join(root, CATALOG), { timeout: 2_000, allowExtension: false });
  try {
    // DELETE journaling avoids an accumulating WAL when long-lived clients exist.
    db.exec("PRAGMA synchronous = FULL; PRAGMA trusted_schema = OFF;");
    return operation(db);
  } finally {
    db.close();
  }
}

export function transaction<T>(db: DatabaseSync, operation: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = operation();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

export function nodeCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : undefined;
}
