#!/usr/bin/env node
// Port of ../run_wine.py (same command line, output and exit codes). Node built-ins only.
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import * as L from './lib/rwlib.mjs'

const PROG = 'run_wine'
const DOC = "Run a Windows program from a fresh copy of the game folder and collect its log (Python stdlib only).\nUsed for the toolchain's hello programs and for trying a rewrite build by hand.\n\n  python3 -I run_wine.py EXE [--game DIR] [--extra FILE]... [--extra-dir DIR]... [--title TEXT] [--log NAME]\n         [--log-out PATH] [--expect TEXT] [--timeout S] [--tries N] [--workdir DIR] [--keep]\n         [--runner wine|native] [--project DIR] [-- program args...]\n\n  --game       folder to copy (default: decomp.json rewrite.game, else paths.game, else work/game); never\n               modified. The copy goes to a new temporary folder (or --workdir); files are cloned on macOS.\n  --extra / --extra-dir   more files to put next to the exe (e.g. the library DLLs of the \"dll\" flavour)\n  --title      wait for an on-screen window with exactly this title (macOS window list, or Windows' own)\n  --log        file (relative to the copy) to collect after the run; printed and saved to --log-out\n               (default: next to EXE, same name)\n  --expect     the run only succeeds if the log contains TEXT\n  --timeout    give up after S seconds (default 60); the process is killed\n  --tries      start again when a run does not succeed (no window, --expect missing from the log, or a\n               non-zero exit without --expect), up to N runs (default 3): Wine on macOS sometimes ends or\n               crashes a starting process\n  --runner     wine (default on macOS/Linux; env WINE, WINEPREFIX) or native (default on Windows)\nExit 0 when the title was seen (if asked), the process exited by itself and --expect matched."
const out = s => process.stdout.write(s + '\n')

export async function main (argv) {
  let progArgs = []
  const sep = argv.indexOf('--')
  if (sep >= 0) { progArgs = argv.slice(sep + 1); argv = argv.slice(0, sep) }
  const a = L.parseArgs(PROG, DOC, argv, [
    ['--game', 'str', null], ['--extra', 'list', null], ['--extra-dir', 'list', null], ['--title', 'str', null],
    ['--log', 'str', null], ['--log-out', 'str', null], ['--expect', 'str', null], ['--timeout', 'float', new L.PyFloat(60)],
    ['--tries', 'int', 3], ['--workdir', 'str', null], ['--keep', 'flag', false], ['--runner', 'str', null],
    ['--project', 'str', '.']], [['exe', '1']])
  const project = a.project
  const [cfg, rw] = L.loadConfig(project)
  const mode = L.runnerMode(rw, a.runner)
  const game = a.game || L.projectPath(project, rw.game || L.get(cfg, 'paths.game', 'work/game'))
  const exe = L.abspath(a.exe)
  const work = a.workdir ? L.abspath(a.workdir) : L.mkdtemp('rewrite_wine_')
  const env = L.runEnv(project, rw, mode)
  let ok = false; let good = false
  const timeout = L.num(a.timeout)
  try {
    L.copyTree(L.abspath(game), work)
    const extras = [...a.extra]
    for (const d of a.extra_dir) for (const f of L.listdirSorted(d)) if (L.isfile(L.join(d, f))) extras.push(L.join(d, f))
    for (const f of [exe, ...extras]) L.clone(L.abspath(f), L.join(work, L.basename(f)))
    const name = L.basename(exe)
    const logPath = a.log ? L.join(work, a.log) : null
    const outPath = L.join(work, '.run-output.txt')
    let haveLog = false; let text = ''
    for (let attempt = 1; attempt <= Math.max(1, a.tries); attempt++) {
      if (logPath && fs.existsSync(logPath)) fs.rmSync(logPath)
      const t0 = Date.now()
      const fd = fs.openSync(outPath, 'w')
      const cmd = L.exeCommand(mode, name, work, progArgs)
      const proc = spawn(cmd[0], cmd.slice(1), { cwd: work, env, stdio: ['ignore', fd, fd] })
      fs.closeSync(fd)
      let rc = null; let exited = false
      const done = new Promise(resolve => {
        proc.on('exit', (code, sig) => { exited = true; rc = code !== null ? code : -L.signalNumber(sig); resolve() })
        proc.on('error', () => { exited = true; rc = 127; resolve() })
      })
      let seen = null
      while (!exited && (Date.now() - t0) / 1000 < timeout) {
        if (a.title && seen === null && (L.windowTitles() || []).includes(a.title)) {
          seen = (Date.now() - t0) / 1000
          out(`[run_wine] window "${a.title}" on screen after ${L.f1(seen)} s`)
        }
        await Promise.race([done, L.sleep(250)])
      }
      const timedOut = !exited
      if (timedOut) { proc.kill('SIGKILL'); await done }
      haveLog = Boolean(logPath && fs.existsSync(logPath))
      text = haveLog ? fs.readFileSync(logPath).toString('utf8').replace(/\r\n?/g, '\n') : ''
      out(`[run_wine] try ${attempt}: exit ${L.pyStr(rc)} after ${L.f1((Date.now() - t0) / 1000)} s${timedOut ? ' (timeout, killed)' : ''}`)
      const crash = fs.readFileSync(outPath).toString('utf8').replace(/\r\n?/g, '\n').split(/(?<=\n)/)
        .filter(l => l.includes('Unhandled') || l.includes('page fault')).map(l => l.trim())
      for (const l of crash.slice(0, 3)) out(`[run_wine]   wine: ${l}`)
      good = !timedOut && (a.title === null || seen !== null) && (a.expect ? text.includes(a.expect) : rc === 0)
      if (!good && attempt < a.tries) {
        out('[run_wine] run did not succeed (Wine sometimes ends or crashes a starting process): starting again')
        continue
      }
      break
    }
    if (haveLog) {
      const dst = a.log_out || L.join(L.dirname(exe), L.basename(a.log))
      L.makedirs(L.dirname(L.abspath(dst)))
      L.copy2(logPath, dst)
      out(`[run_wine] log ${a.log} (saved to ${dst}):`)
      out(text.trimEnd())
    } else if (a.log) {
      out(`[run_wine] no log file ${a.log}; program output:`)
      out(fs.readFileSync(outPath).toString('utf8').replace(/\r\n?/g, '\n').slice(-4000))
    }
    ok = good
    if (a.title && L.windowTitles() === null) out('[run_wine] (window titles cannot be read on this system)')
    out(`[run_wine] ${ok ? 'PASS' : 'FAIL'}`)
  } finally {
    if (a.keep) out(`[run_wine] kept ${work}`)
    else if (!a.workdir) L.rmtree(work)
  }
  return ok ? 0 : 1
}

if (L.isMain(import.meta.url)) process.exitCode = await main(process.argv.slice(2))
