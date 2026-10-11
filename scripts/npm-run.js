#!/usr/bin/env node
/**
 * Dispatch an npm script to the right platform launcher.
 *
 * `npm start` should work identically on a Windows laptop and a Linux server,
 * and neither run.cmd nor run.sh runs on both. This picks one, forwards stdio
 * so Ctrl+C and colours behave normally, and passes the exit code through so
 * `npm run health` can gate a deploy.
 *
 * Deliberately dependency-free — it must work before anything is installed.
 */

"use strict";

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "..");
const isWindows = process.platform === "win32";
const task = process.argv[2] || "start";
const extra = process.argv.slice(3);

// health is a separate script from run; everything else is a run mode.
const HEALTH = task === "health";
const script = HEALTH
  ? isWindows ? "health.cmd" : "health.sh"
  : isWindows ? "run.cmd" : "run.sh";

const scriptPath = path.join(ROOT, script);
if (!fs.existsSync(scriptPath)) {
  console.error(`[nexguard] missing launcher: ${script}`);
  console.error(`[nexguard] expected it at ${scriptPath}`);
  process.exit(1);
}

const args = HEALTH ? extra : [task, ...extra];

let command, commandArgs;
if (isWindows) {
  // cmd /c so the .cmd is interpreted, and the quoted path survives spaces —
  // this project lives under "D:\NexGuard july Version\...".
  command = process.env.COMSPEC || "cmd.exe";
  commandArgs = ["/c", scriptPath, ...args];
} else {
  // bash explicitly rather than relying on the execute bit, which does not
  // survive a zip download or a Windows-side checkout.
  command = "bash";
  commandArgs = [scriptPath, ...args];
}

const child = spawn(command, commandArgs, {
  cwd: ROOT,
  stdio: "inherit",
  windowsHide: false,
});

child.on("error", (err) => {
  console.error(`[nexguard] could not run ${script}: ${err.message}`);
  if (!isWindows && err.code === "ENOENT") {
    console.error("[nexguard] bash not found — install it, or run ./run.sh directly.");
  }
  process.exit(1);
});

// Forward the real exit code; a signal-terminated child reports 0 because
// Ctrl+C is how you stop the server, not a failure.
child.on("exit", (code, signal) => {
  process.exit(signal ? 0 : code === null ? 1 : code);
});
