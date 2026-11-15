#!/usr/bin/env node

// Extract Apple's bundled skills using only Node.js built-ins.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

const TEMPLATE_SUFFIX = '.idechatprompttemplate';
const DEFAULT_OUTPUT = fileURLToPath(new URL('../skills/apple', import.meta.url));

// Command-line options and installation detection.
function readOptions() {
  return parseArgs({
    options: {
      xcode: { type: 'string' },
      output: { type: 'string', default: DEFAULT_OUTPUT },
      skill: { type: 'string', multiple: true },
      list: { type: 'boolean', default: false },
      'dry-run': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: false,
  }).values;
}

function printHelp() {
  console.log(`Usage: node scripts/xcode-skills.mjs [options]

Extract Apple's bundled Xcode skills without changing their contents.

  --xcode PATH              Xcode.app path (default: selected Xcode)
  --output PATH             Destination (default: skills/apple in this repo)
  --skill NAME              Select a skill; repeat for multiple skills
  --list                    List available skills without copying
  --dry-run                 Show planned copies without writing
  -h, --help                Show this help`);
}

function selectedXcode() {
  try {
    const developer = execFileSync('xcode-select', ['-p'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (developer.endsWith('/Contents/Developer')) {
      return path.resolve(developer, '../..');
    }
  } catch {
    // Command Line Tools or an unavailable selector: use the standard location.
  }
  return '/Applications/Xcode.app';
}

function absolutePath(value) {
  if (value === '~') return os.homedir();
  return path.resolve(value.startsWith('~/') ? path.join(os.homedir(), value.slice(2)) : value);
}

// Discovery skips symlinks, including duplicate framework aliases.
function entries(directory) {
  return fs.readdirSync(directory, { withFileTypes: true })
    .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
}

function* walk(directory) {
  const children = entries(directory);
  yield { directory, files: children.filter(entry => entry.isFile()) };
  for (const entry of children) {
    if (entry.isDirectory()) yield* walk(path.join(directory, entry.name));
  }
}

function discover(source) {
  const skills = new Map();
  function register(name, entry, kind) {
    if (skills.has(name)) throw new Error(`Duplicate skill name: ${name} (${entry})`);
    skills.set(name, { entry, kind });
  }

  for (const { directory, files } of walk(path.join(source, 'Contents/PlugIns'))) {
    const directoryEntry = ['SKILL.md', 'SKILL.md.packaged']
      .find(name => files.some(file => file.name === name));
    if (directoryEntry) {
      register(path.basename(directory), path.join(directory, directoryEntry), 'directory');
    }
    for (const file of files) {
      if (!file.name.endsWith(TEMPLATE_SUFFIX)) continue;
      const entry = path.join(directory, file.name);
      const header = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(fs.readFileSync(entry, 'utf8'));
      if (!header) continue;
      const name = /^name: *([a-z0-9-]+) *\r?$/m.exec(header[1]);
      if (name && /^description:/m.test(header[1])) register(name[1], entry, 'template');
    }
  }
  return skills;
}

// Restore Xcode's flattened resources and validate collisions before copying.
function unpacked(filename) {
  return filename.replace(/\.packaged$/, '');
}

function copyPlan(skills, names, destination) {
  const plan = new Map();
  function add(original, target) {
    if (plan.has(target)) throw new Error(`Files map to the same output: ${target}`);
    plan.set(target, original);
  }

  for (const name of names) {
    const { entry, kind } = skills.get(name);
    const root = path.join(destination, name);
    const parent = path.dirname(entry);
    if (kind === 'directory') {
      for (const { directory, files } of walk(parent)) {
        for (const file of files) {
          const original = path.join(directory, file.name);
          add(original, path.join(root, unpacked(path.relative(parent, original))));
        }
      }
      continue;
    }
    add(entry, path.join(root, 'SKILL.md'));
    const stem = path.basename(entry, TEMPLATE_SUFFIX);
    for (const file of entries(parent)) {
      if (!file.isFile()) continue;
      for (const [suffix, folder] of [['ref', 'references'], ['script', 'scripts']]) {
        const prefix = `${stem}-${suffix}-`;
        if (file.name.startsWith(prefix)) {
          add(path.join(parent, file.name), path.join(root, folder, unpacked(file.name.slice(prefix.length))));
        }
      }
    }
  }
  return plan;
}

// Execute only after discovery, selection, and copy planning succeed.
function main() {
  const options = readOptions();
  if (options.help) return printHelp();
  const source = absolutePath(options.xcode ?? selectedXcode());
  const destination = absolutePath(options.output);
  if (!fs.existsSync(path.join(source, 'Contents/PlugIns'))) {
    throw new Error(`Xcode plug-ins not found: ${source}`);
  }
  const skills = discover(source);
  if (!skills.size) throw new Error(`No bundled skills found in ${source}`);
  const names = [...new Set(options.skill ?? skills.keys())].sort();
  const unknown = names.filter(name => !skills.has(name));
  if (unknown.length) {
    throw new Error(`Unknown skill(s): ${unknown.join(', ')}. Use --list to see available names.`);
  }
  if (options.list) return console.log(names.join('\n'));

  const plan = copyPlan(skills, names, destination);
  for (const [target, original] of plan) {
    if (options['dry-run']) {
      console.log(`${original} -> ${target}`);
    } else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(original, target);
    }
  }
  const verb = options['dry-run'] ? 'Would save' : 'Saved';
  console.log(`${verb} ${names.length} skills (${plan.size} files) to ${destination}`);
}

try {
  main();
} catch (error) {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
}
