import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { rm } from "node:fs/promises";
import { admitExecution, digestRun, executionDirectory, retireExecution, writeRecord } from "../../dist/execution-record.js";

const input = [];
for await (const chunk of process.stdin) input.push(chunk);
const { root, action, record, limits } = JSON.parse(Buffer.concat(input).toString());
let heldDatabase;
if (action === "admit") {
  try { process.stdout.write(JSON.stringify({ admitted: admitExecution(root, record, limits) })); }
  catch (error) { process.stdout.write(JSON.stringify({ error: error.message })); }
} else {
  const directory = executionDirectory(root, record.executionId);
  if (action === "uncommitted-publication") {
    const db = new DatabaseSync(join(root, "executions.sqlite")); heldDatabase = db;
    db.exec("BEGIN IMMEDIATE");
    db.prepare("UPDATE executions SET state = ? WHERE execution_id = ?")
      .run(JSON.stringify({ schemaVersion: 1, sha256: digestRun(record), value: record }), record.executionId);
  } else if (action === "committed-publication") {
    await writeRecord(directory, record);
  } else {
    retireExecution(root, record.executionId, record.receipt.digest);
    if (action === "deleted-output") await rm(directory, { recursive: true, force: true });
  }
  process.stdout.write("ready\n");
  setInterval(() => { void heldDatabase; }, 1000);
}
