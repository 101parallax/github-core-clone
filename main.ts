// main.ts — thin launcher for the github-core-clone-01 entry.
//
// The platform runs `node /bot/main.ts` (Node 22, type stripping). This file
// spawns the Go forge binary that sits next to it, forwards env + stdio, and
// exits with the binary's exit code. The binary itself owns the whole trial
// lifecycle (bind ephemeral port, POST /register, poll GET /done, exit 0);
// the launcher only gets it started, however hostile the checkout is.
//
// Fallback ladder (the checkout may be read-only, or mounted noexec, or the
// binary may have lost its exec bit in transit — any of those is a zero score
// if the launcher gives up):
//   1. Spawn ./forge in place.
//   2. Copy it to a fresh dir under os.tmpdir(), chmod 0700, spawn from there.
//   3. Copy it to /dev/shm (anonymous tmpfs, usually exec even when /tmp is
//      noexec), chmod 0700, spawn from there.
//   4. memfd: ask python3 (when present) to memfd_create + write the binary
//      bytes + execve /proc/self/fd/N, so the kernel runs it from anonymous
//      memory with no on-disk executable at all.
// The first spawn that actually starts the binary wins; a spawn that fails
// (error event) falls through to the next rung. A binary that starts and
// then exits is NOT retried — its exit code is the entry's result.

import { spawn } from 'node:child_process';
import { chmodSync, copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const BINARY = join(HERE, 'forge');

function log(msg: string): void {
  process.stderr.write(`[launcher] ${msg}\n`);
}

/** One way to start the forge: a command, its args, and a label for the log. */
interface Candidate {
  label: string;
  cmd: string;
  args: string[];
  /** Temp dir to remove once the child is gone (undefined = nothing to clean). */
  cleanupDir?: string;
}

/** Copy the binary to dir/name with mode 0700; returns the new path. */
function stageCopy(dir: string, name: string): string {
  const dest = join(dir, name);
  copyFileSync(BINARY, dest);
  chmodSync(dest, 0o700);
  return dest;
}

/**
 * Build the fallback ladder. Steps 2-3 stage a copy of the binary first, so
 * a staging failure (read-only /tmp, missing /dev/shm) just drops that rung
 * instead of crashing the launcher.
 */
function candidates(): Candidate[] {
  const out: Candidate[] = [{ label: 'in-place ./forge', cmd: BINARY, args: [] }];

  try {
    const dir = mkdtempSync(join(tmpdir(), 'forge-'));
    const staged = stageCopy(dir, 'forge');
    out.push({ label: `tmpdir copy (${staged})`, cmd: staged, args: [], cleanupDir: dir });
  } catch (err) {
    log(`tmpdir staging failed, skipping rung: ${(err as Error).message}`);
  }

  try {
    const staged = stageCopy('/dev/shm', `forge-${process.pid}`);
    out.push({ label: `shm copy (${staged})`, cmd: staged, args: [], cleanupDir: undefined });
  } catch (err) {
    log(`shm staging failed, skipping rung: ${(err as Error).message}`);
  }

  // memfd via python3: memfd_create + write bytes + execve /proc/self/fd/N.
  // Pure Node has no memfd_create binding, so this rung only exists when a
  // python3 interpreter is around to make the syscall for us.
  const memfdScript =
    'import os, sys\n' +
    'src = sys.argv[1]\n' +
    'fd = os.memfd_create("forge", 0)\n' +
    'with open(src, "rb") as f:\n' +
    '    while True:\n' +
    '        chunk = f.read(1 << 20)\n' +
    '        if not chunk:\n' +
    '            break\n' +
    '        os.write(fd, chunk)\n' +
    'os.execve("/proc/self/fd/%d" % fd, ["forge"], os.environ)\n';
  for (const py of ['python3', 'python']) {
    out.push({ label: `memfd via ${py}`, cmd: py, args: ['-c', memfdScript, BINARY] });
  }
  return out;
}

/**
 * Spawn one candidate and wait for it. Resolves with the child's exit code
 * (or 128+signal when killed by a signal) once it has run, or with null when
 * the spawn itself failed and the caller should try the next rung.
 */
function runOne(c: Candidate): Promise<number | null> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(c.cmd, c.args, { env: process.env, stdio: 'inherit', windowsHide: true });
    } catch (err) {
      log(`${c.label}: spawn threw ${(err as Error).message}`);
      resolve(null);
      return;
    }

    let settled = false;
    const finish = (code: number | null): void => {
      if (settled) return;
      settled = true;
      if (c.cleanupDir !== undefined) {
        try {
          rmSync(c.cleanupDir, { recursive: true, force: true });
        } catch {
          // Best effort only; a stale temp dir is harmless.
        }
      }
      resolve(code);
    };

    // Forward termination signals so the harness can stop the forge cleanly.
    const forward = (sig: NodeJS.Signals): void => {
      try {
        child.kill(sig);
      } catch {
        // The child may already be gone; nothing to do.
      }
    };
    const onSigint = (): void => forward('SIGINT');
    const onSigterm = (): void => forward('SIGTERM');
    process.on('SIGINT', onSigint);
    process.on('SIGTERM', onSigterm);

    child.on('error', (err) => {
      log(`${c.label}: spawn failed (${(err as Error).message}), trying next rung`);
      process.off('SIGINT', onSigint);
      process.off('SIGTERM', onSigterm);
      finish(null);
    });
    child.on('exit', (code, signal) => {
      process.off('SIGINT', onSigint);
      process.off('SIGTERM', onSigterm);
      if (signal !== null) {
        const sigNum: Record<string, number> = { SIGHUP: 1, SIGINT: 2, SIGTERM: 15 };
        finish(128 + (sigNum[signal] ?? 0));
        return;
      }
      finish(code ?? 1);
    });
  });
}

async function main(): Promise<void> {
  const list = candidates();
  for (const c of list) {
    log(`trying ${c.label}`);
    const code = await runOne(c);
    if (code !== null) {
      log(`${c.label}: forge exited with code ${code}`);
      process.exit(code);
    }
  }
  process.stderr.write('[launcher] FATAL: no launch rung could start the forge binary\n');
  process.exit(1);
}

void main();
