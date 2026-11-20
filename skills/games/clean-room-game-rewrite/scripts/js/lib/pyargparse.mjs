// The parsing half of Python 3.9's argparse, for ports whose command lines must behave identically
// (Node built-ins only). Same algorithm as argparse._parse_known_args: option/positional classification,
// unique-prefix abbreviations (--verb), --opt=value, combined short flags (-vq), '--', greedy positional
// matching with nargs None/'?'/'+'/PARSER, subcommands, required-argument and unrecognized-argument errors,
// and the same error texts. Help and usage texts are not generated: each parser is given the exact text
// Python prints (captured at the default 80-column width), so -h and errors print the same bytes.
//
//   const p = new ArgumentParser({ prog: 'tool.py', usage: 'usage: tool.py [-h] x\n', help: '...full -h text...' })
//   p.add_argument('x')
//   p.add_argument('--count', { type: 'int', default: 20 })
//   p.add_argument('--verbose', '-v', { action: 'store_true' })
//   const sub = p.add_subparsers({ dest: 'cmd' }); const c = sub.add_parser('compare', { usage, help })
//   const args = p.parse_args(argv)     // throws ArgExit(code) after printing help (0) or an error (2)
//
// Actions: 'store' (default), 'store_true', 'append', 'help' (added automatically as -h/--help).
// Types: 'int' (Python int(): whitespace, sign, underscores) or a function throwing on bad input.

export class ArgExit extends Error {
  constructor(code) { super(`exit ${code}`); this.code = code }
}

class ArgumentError extends Error {
  constructor(action, message) {
    super(message)
    this.argumentName = action ? actionName(action) : null
  }
  toString() { return this.argumentName === null ? this.message : `argument ${this.argumentName}: ${this.message}` }
}

function actionName(a) {
  if (a.option_strings.length) return a.option_strings.join('/')
  if (a.metavar !== undefined && a.metavar !== null) return a.metavar
  if (a.dest !== undefined && a.dest !== null) return a.dest
  return null
}

// Python repr() of a str (as argparse prints it with %r)
export function reprStr(s) {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'"
  let out = q
  for (const ch of s) {
    const c = ch.codePointAt(0)
    if (ch === q || ch === '\\') out += '\\' + ch
    else if (ch === '\t') out += '\\t'
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (c < 0x20 || c === 0x7f) out += '\\x' + c.toString(16).padStart(2, '0')
    else if (c < 0x7f) out += ch
    else if (/^[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]$/u.test(ch)) {
      out += c <= 0xff ? '\\x' + c.toString(16).padStart(2, '0')
        : c <= 0xffff ? '\\u' + c.toString(16).padStart(4, '0') : '\\U' + c.toString(16).padStart(8, '0')
    } else out += ch
  }
  return out + q
}

const PY_WS = /^[\t\n\x0b\x0c\r\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\x0b\x0c\r\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g

// int(s) for a str (base 10): surrounding whitespace, sign, single underscores between digits
export function pyIntBase10(s) {
  const t = s.replace(PY_WS, '')
  const m = /^([+-]?)(\d(?:_?\d)*)$/.exec(t)
  if (!m) throw new Error(`invalid literal for int() with base 10: ${reprStr(s)}`)
  const v = Number(m[2].replace(/_/g, ''))
  return m[1] === '-' ? -v : v
}

const NARGS_PATTERN = { null: '(-*A-*)', '?': '(-*A?-*)', '*': '(-*[A-]*)', '+': '(-*A[A-]*)', PARSER: '(-*A[-AO]*)', 0: '(-*-*)' }

function nargsPattern(a) {
  let p = NARGS_PATTERN[a.nargs === undefined ? null : a.nargs]
  if (a.option_strings.length) p = p.replace(/-\*/g, '').replace(/-/g, '')
  return p
}

export class ArgumentParser {
  constructor({ prog, usage, help }) {
    this.prog = prog
    this.usage = usage
    this.help = help
    this.actions = []
    this.optionStringActions = new Map()      // insertion order = argparse's _option_string_actions
    this.add_argument('-h', '--help', { action: 'help' })
  }

  add_argument(...spec) {
    const opts = typeof spec[spec.length - 1] === 'object' ? spec.pop() : {}
    const a = { option_strings: [], ...opts }
    a.action = opts.action || 'store'
    if (spec[0].startsWith('-')) {
      a.option_strings = spec
      const long = spec.find((s) => s.startsWith('--')) || spec[0]
      a.dest = opts.dest || long.replace(/^-+/, '').replace(/-/g, '_')
      a.required = !!opts.required
    } else {
      a.dest = spec[0]
      a.required = opts.nargs !== '?' && opts.nargs !== '*'
    }
    if (a.action === 'store_true' || a.action === 'help') a.nargs = 0
    if (a.action === 'store_true' && a.default === undefined) a.default = false
    if (a.default === undefined) a.default = null
    this.actions.push(a)
    for (const s of a.option_strings) this.optionStringActions.set(s, a)
    return a
  }

  add_subparsers({ dest }) {
    const a = { option_strings: [], dest, nargs: 'PARSER', action: 'parsers', required: false, default: null,
                parsers: new Map() }
    a.choices = a.parsers
    this.actions.push(a)
    const self = this
    return {
      add_parser(name, { usage, help }) {
        const p = new ArgumentParser({ prog: `${self.prog} ${name}`, usage, help })
        a.parsers.set(name, p)
        return p
      },
    }
  }

  print_help() { process.stdout.write(this.help) }

  error(message) {
    process.stderr.write(this.usage + `${this.prog}: error: ${message}\n`)
    throw new ArgExit(2)
  }

  parse_args(argv) {
    const [ns, extras] = this.parse_known_args(argv)
    if (extras.length) this.error(`unrecognized arguments: ${extras.join(' ')}`)
    return ns
  }

  parse_known_args(argv, ns = {}) {
    for (const a of this.actions) {
      if (a.action === 'help') continue
      if (!(a.dest in ns)) ns[a.dest] = a.default
    }
    let extras
    try {
      extras = this._parse(argv, ns)
    } catch (e) {
      if (e instanceof ArgumentError) this.error(e.toString())
      throw e
    }
    if (ns.__unrecognized) {
      extras.push(...ns.__unrecognized)
      delete ns.__unrecognized
    }
    return [ns, extras]
  }

  _optionTuples(s) {
    const result = []
    if (s[0] === '-' && s[1] === '-') {
      let prefix = s, explicit = null
      if (s.includes('=')) { const i = s.indexOf('='); prefix = s.slice(0, i); explicit = s.slice(i + 1) }
      for (const [os, a] of this.optionStringActions) if (os.startsWith(prefix)) result.push([a, os, explicit])
    } else if (s[0] === '-') {
      const shortPrefix = s.slice(0, 2), shortExplicit = s.slice(2)
      for (const [os, a] of this.optionStringActions) {
        if (os === shortPrefix) result.push([a, os, shortExplicit])
        else if (os.startsWith(s)) result.push([a, os, null])
      }
    }
    return result
  }

  _parseOptional(s) {
    if (!s) return null
    if (s[0] !== '-') return null
    if (this.optionStringActions.has(s)) return [this.optionStringActions.get(s), s, null]
    if (s.length === 1) return null
    if (s.includes('=')) {
      const i = s.indexOf('=')
      const os = s.slice(0, i)
      if (this.optionStringActions.has(os)) return [this.optionStringActions.get(os), os, s.slice(i + 1)]
    }
    const tuples = this._optionTuples(s)
    if (tuples.length > 1) this.error(`ambiguous option: ${s} could match ${tuples.map((t) => t[1]).join(', ')}`)
    if (tuples.length === 1) return tuples[0]
    if (/^-\d+$|^-\d*\.\d+$/.test(s)) return null       // no option looks like a negative number
    if (s.includes(' ')) return null
    return [null, s, null]
  }

  _getValue(a, s) {
    if (!a.type) return s
    try {
      return a.type === 'int' ? pyIntBase10(s) : a.type(s)
    } catch (e) {
      const tname = a.type === 'int' ? 'int' : (a.type.name || String(a.type))
      throw new ArgumentError(a, `invalid ${tname} value: ${reprStr(s)}`)
    }
  }

  _checkValue(a, v) {
    if (a.choices && !a.choices.has(v)) {
      throw new ArgumentError(a, `invalid choice: ${reprStr(v)} (choose from ${[...a.choices.keys()].map(reprStr).join(', ')})`)
    }
  }

  _getValues(a, strings) {
    strings = strings.slice()
    if (a.nargs !== 'PARSER') { const i = strings.indexOf('--'); if (i >= 0) strings.splice(i, 1) }
    if (!strings.length && a.nargs === '?') {
      const v = a.option_strings.length ? (a.const ?? null) : a.default
      if (typeof v === 'string') { const x = this._getValue(a, v); this._checkValue(a, x); return x }
      return v
    }
    if (strings.length === 1 && (a.nargs === null || a.nargs === undefined || a.nargs === '?')) {
      const v = this._getValue(a, strings[0])
      this._checkValue(a, v)
      return v
    }
    if (a.nargs === 'PARSER') {
      const v = strings.map((s) => this._getValue(a, s))
      this._checkValue(a, v[0])
      return v
    }
    const v = strings.map((s) => this._getValue(a, s))
    for (const x of v) this._checkValue(a, x)
    return v
  }

  _matchArgument(a, pattern) {
    const m = new RegExp('^' + nargsPattern(a)).exec(pattern)
    if (!m) {
      const n = a.nargs === undefined ? null : a.nargs
      const msg = n === null ? 'expected one argument' : n === '?' ? 'expected at most one argument'
        : n === '+' ? 'expected at least one argument' : `expected ${n} argument${n === 1 ? '' : 's'}`
      throw new ArgumentError(a, msg)
    }
    return m[1].length
  }

  _matchPartial(actions, pattern) {
    for (let i = actions.length; i > 0; i--) {
      const re = new RegExp('^' + actions.slice(0, i).map(nargsPattern).join(''))
      const m = re.exec(pattern)
      if (m) return m.slice(1).map((g) => g.length)
    }
    return []
  }

  _parse(args, ns) {
    const optionIdx = new Map()
    const pat = []
    let dd = false
    args.forEach((s, i) => {
      if (dd) { pat.push('A'); return }
      if (s === '--') { pat.push('-'); dd = true; return }
      const t = this._parseOptional(s)
      if (t === null) pat.push('A')
      else { optionIdx.set(i, t); pat.push('O') }
    })
    const pattern = pat.join('')
    const seen = new Set()
    const extras = []
    const positionals = this.actions.filter((a) => !a.option_strings.length)

    const takeAction = (a, strings, optionString = null) => {
      seen.add(a)
      const v = this._getValues(a, strings)
      if (a.action === 'help') { this.print_help(); throw new ArgExit(0) }
      if (a.action === 'store_true') ns[a.dest] = true
      else if (a.action === 'append') ns[a.dest] = [...(ns[a.dest] || []), v]
      else if (a.action === 'parsers') {
        const [name, ...rest] = v
        ns[a.dest] = name
        // a fresh namespace, then copied over (argparse: setattr for each key)
        const [subns, sub] = a.parsers.get(name).parse_known_args(rest, {})
        Object.assign(ns, subns)
        if (sub.length) (ns.__unrecognized ||= []).push(...sub)
      } else ns[a.dest] = v
    }

    const consumeOptional = (start) => {
      let [a, optionString, explicit] = optionIdx.get(start)
      const tuples = []
      let stop
      for (;;) {
        if (a === null) { extras.push(args[start]); return start + 1 }
        if (explicit !== null) {
          const count = this._matchArgument(a, 'A')
          if (count === 0 && optionString[1] !== '-') {
            tuples.push([a, [], optionString])
            optionString = optionString[0] + explicit[0]
            const nextExplicit = explicit.slice(1) || null
            if (this.optionStringActions.has(optionString)) {
              a = this.optionStringActions.get(optionString)
              explicit = nextExplicit
            } else throw new ArgumentError(a, `ignored explicit argument ${reprStr(explicit)}`)
          } else if (count === 1) {
            stop = start + 1
            tuples.push([a, [explicit], optionString])
            break
          } else throw new ArgumentError(a, `ignored explicit argument ${reprStr(explicit)}`)
        } else {
          const s = start + 1
          const count = this._matchArgument(a, pattern.slice(s))
          stop = s + count
          tuples.push([a, args.slice(s, stop), optionString])
          break
        }
      }
      for (const [x, strs, os] of tuples) takeAction(x, strs, os)
      return stop
    }

    const consumePositionals = (start) => {
      const counts = this._matchPartial(positionals, pattern.slice(start))
      for (let k = 0; k < counts.length; k++) {
        const strs = args.slice(start, start + counts[k])
        start += counts[k]
        takeAction(positionals[k], strs)
      }
      positionals.splice(0, counts.length)
      return start
    }

    let start = 0
    const maxOpt = optionIdx.size ? Math.max(...optionIdx.keys()) : -1
    while (start <= maxOpt) {
      const nextOpt = Math.min(...[...optionIdx.keys()].filter((i) => i >= start))
      if (start !== nextOpt) {
        const end = consumePositionals(start)
        if (end > start) { start = end; continue }
        start = end
      }
      if (!optionIdx.has(start)) {
        extras.push(...args.slice(start, nextOpt))
        start = nextOpt
      }
      start = consumeOptional(start)
    }
    const stop = consumePositionals(start)
    extras.push(...args.slice(stop))

    const missing = []
    for (const a of this.actions) if (!seen.has(a) && a.required) missing.push(actionName(a))
    if (missing.length) this.error(`the following arguments are required: ${missing.join(', ')}`)
    return extras
  }
}
