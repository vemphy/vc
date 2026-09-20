// JSON Schema says a `pattern` is an ECMA-262 regular expression. Go uses RE2.
// The two disagree about lookarounds and backreferences, and more quietly about
// `\s`, `\w`, `\b` and `.`. A Vemphy claim schema may only use syntax that means
// the same in both, which this file checks. vc-go/schema/pattern.go is the same
// code in Go.

const ESCAPES = '\\./()[]{}*+?|^$'
const CONTROL = 'tnr'
const MAX_REPEAT = 1000

/** Returns why a pattern is not allowed, or undefined when it is. */
export function patternProblem(pattern: string): string | undefined {
  const chars = Array.from(pattern)
  if (chars.length === 0 || chars.length > 200) return 'must be 1-200 characters'

  let i = 0
  let depth = 0
  // Whether the previous token is something a quantifier can repeat.
  let atom = false

  while (i < chars.length) {
    const c = chars[i]!
    if (c === '\\') {
      const next = chars[i + 1]
      if (next === undefined) return 'ends with a backslash'
      if (next !== 'd' && !ESCAPES.includes(next) && !CONTROL.includes(next)) return `\\${next} is not allowed`
      i += 2
      atom = true
    } else if (c === '[') {
      const end = classEnd(chars, i)
      if (typeof end === 'string') return end
      i = end
      atom = true
    } else if (c === '(') {
      if (chars[i + 1] === '?') {
        if (chars[i + 2] !== ':') return 'only (?:...) groups are allowed'
        i += 3
      } else {
        i += 1
      }
      depth += 1
      if (depth > 10) return 'groups are nested too deeply'
      atom = false
    } else if (c === ')') {
      if (depth === 0) return 'unmatched )'
      depth -= 1
      i += 1
      atom = true
    } else if (c === '*' || c === '+' || c === '?' || c === '{') {
      if (!atom) return `nothing for ${c} to repeat`
      if (c === '{') {
        const end = repeatEnd(chars, i)
        if (typeof end === 'string') return end
        i = end
      } else {
        i += 1
      }
      // A second quantifier would be lazy (`+?`), possessive (`++`) or an error.
      atom = false
    } else if (c === '^' || c === '$' || c === '|') {
      i += 1
      atom = false
    } else if (c === '.') {
      return '. is not allowed; use a character class'
    } else if (c === ']' || c === '}') {
      return `${c} must be escaped`
    } else {
      i += 1
      atom = true
    }
  }
  return depth === 0 ? undefined : 'unmatched ('
}

// Returns the index after the closing bracket, or a problem.
function classEnd(chars: string[], start: number): number | string {
  let i = start + 1
  if (chars[i] === '^') i += 1
  let members = 0
  // The previous member when it could start a range, as a code point.
  let low: number | undefined
  while (i < chars.length) {
    const c = chars[i]!
    if (c === ']') return members > 0 ? i + 1 : 'empty character class'
    if (c === '[') return '[ must be escaped inside a character class'
    if (c === '^') return '^ must be escaped inside a character class'

    if (c === '-') {
      const next = chars[i + 1]
      if (low === undefined || next === undefined || next === ']') return '- must be escaped unless it forms a range'
      const high = member(chars, i + 1)
      if (typeof high === 'string') return high
      if (high.point === undefined) return '\\d cannot end a range'
      if (high.point < low) return 'range is out of order'
      i = high.next
      low = undefined
      continue
    }

    const m = member(chars, i)
    if (typeof m === 'string') return m
    i = m.next
    low = m.point
    members += 1
  }
  return 'unmatched ['
}

function member(chars: string[], i: number): { next: number; point: number | undefined } | string {
  const c = chars[i]!
  if (c !== '\\') return { next: i + 1, point: c.codePointAt(0) }
  const next = chars[i + 1]
  if (next === undefined) return 'ends with a backslash'
  if (next === 'd') return { next: i + 2, point: undefined }
  if (next === '-' || ESCAPES.includes(next)) return { next: i + 2, point: next.codePointAt(0) }
  if (CONTROL.includes(next)) return { next: i + 2, point: { t: 9, n: 10, r: 13 }[next as 't' | 'n' | 'r'] }
  return `\\${next} is not allowed`
}

// Returns the index after the closing brace, or a problem.
function repeatEnd(chars: string[], start: number): number | string {
  const close = chars.indexOf('}', start)
  if (close < 0) return '{ must be escaped'
  const m = /^(\d{1,4})(,(\d{0,4}))?$/.exec(chars.slice(start + 1, close).join(''))
  if (!m) return 'a repeat must be {n}, {n,} or {n,m}'
  const min = Number(m[1])
  const max = m[3] === undefined || m[3] === '' ? min : Number(m[3])
  if (min > MAX_REPEAT || max > MAX_REPEAT) return `a repeat may be at most ${MAX_REPEAT}`
  if (max < min) return 'repeat is out of order'
  return close + 1
}
