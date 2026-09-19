// Vemphy claim codes: <SLUG>-<XXXX>-<XXXX>
//
// SLUG is 2-4 letters. The eight characters that follow are seven Crockford
// base32 characters and one Crockford mod-37 check character. The check
// character covers the slug as well as the body, so a mistyped slug is caught
// the same way a mistyped body character is.
//
// This module has no dependencies and is safe to ship in a browser bundle.

export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
export const CHECK_ALPHABET = ALPHABET + '*~$=U'

const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const SLUG_PATTERN = /^[A-Z]{2,4}$/
const BODY_LENGTH = 7
const LINK_PATTERN = /^(?:https?:\/\/)?(?:www\.)?vemphy\.com\/v\/([^/?#]+)/i
// 2^35 mod 37. The body is 35 bits, so the slug is weighted by this.
const SLUG_WEIGHT = 19

export type Candidate = {
  /** 1-based position in the code with separators removed. */
  position: number
  /** The character that was typed there. */
  typed: string
  /** The character that would make the check character agree. */
  repair: string
}

export type ParseFailure =
  | { ok: false; error: 'format'; position?: number }
  /** `suspects` holds 1-based positions worth re-checking, best first. It may be empty. */
  | { ok: false; error: 'check'; suspects: number[] }

export type ParseSuccess = { ok: true; code: string; slug: string; body: string; check: string }

export type ParseResult = ParseSuccess | ParseFailure

/** Crockford mod-37 check symbol for a non-negative integer. */
export function checkChar(n: bigint): string {
  return CHECK_ALPHABET[Number(n % 37n)]!
}

/** Check character for a slug and a seven-character body. Both must already be normalised. */
export function checkCharFor(slug: string, body: string): string {
  return CHECK_ALPHABET[checkValue(slug, body)]!
}

function checkValue(slug: string, body: string): number {
  let s = 0
  for (const c of slug) s = (s * 26 + LETTERS.indexOf(c)) % 37
  let n = 0
  for (const c of body) n = (n * 32 + ALPHABET.indexOf(c)) % 37
  return (SLUG_WEIGHT * s + n) % 37
}

function fold(c: string): string {
  if (c === 'O') return '0'
  if (c === 'I' || c === 'L') return '1'
  return c
}

export function formatCode(slug: string, body: string): string {
  const s = slug.toUpperCase()
  const b = [...body.toUpperCase()].map(fold).join('')
  const check = checkCharFor(s, b)
  return `${s}-${b.slice(0, 4)}-${b.slice(4)}${check}`
}

/** False when the check character is a symbol that chat applications treat as formatting. */
export function isIssuable(code: string): boolean {
  const parsed = parseCode(code)
  return parsed.ok && ALPHABET.includes(parsed.check)
}

/** Accepts a bare code in any case, with or without separators, or a vemphy.com/v/<code> link. */
export function parseCode(input: string): ParseResult {
  let text = input.trim()
  const link = LINK_PATTERN.exec(text)
  if (link) {
    try {
      text = decodeURIComponent(link[1]!)
    } catch {
      return { ok: false, error: 'format' }
    }
  }
  text = text.toUpperCase()

  const split = splitSlug(text)
  if (!split) return { ok: false, error: 'format' }
  const { slug, rest } = split
  if (rest.length !== BODY_LENGTH + 1) return { ok: false, error: 'format' }
  if (!SLUG_PATTERN.test(slug)) {
    const stray = [...slug].findIndex((c) => !LETTERS.includes(c))
    return stray >= 0 && slug.length <= 4 ? { ok: false, error: 'format', position: stray + 1 } : { ok: false, error: 'format' }
  }

  const folded = [...rest].map(fold)
  for (let i = 0; i < folded.length; i++) {
    const allowed = i < BODY_LENGTH ? ALPHABET : CHECK_ALPHABET
    if (!allowed.includes(folded[i]!)) return { ok: false, error: 'format', position: slug.length + i + 1 }
  }
  const body = folded.slice(0, BODY_LENGTH).join('')
  const check = folded[BODY_LENGTH]!

  if (checkCharFor(slug, body) !== check) {
    return { ok: false, error: 'check', suspects: rankSuspects(repairs(slug, body, check), slug.length) }
  }
  return { ok: true, code: `${slug}-${body.slice(0, 4)}-${body.slice(4)}${check}`, slug, body, check }
}

// With separators the slug is whatever precedes the first one. Without them
// it is whatever is left after the last eight characters.
function splitSlug(text: string): { slug: string; rest: string } | undefined {
  const parts = text.split(/[\s-]+/).filter(Boolean)
  if (parts.length === 0) return undefined
  if (parts.length === 1) {
    const only = parts[0]!
    if (only.length <= BODY_LENGTH + 1) return undefined
    return { slug: only.slice(0, -(BODY_LENGTH + 1)), rest: only.slice(-(BODY_LENGTH + 1)) }
  }
  return { slug: parts[0]!, rest: parts.slice(1).join('') }
}

// A mod-37 check detects a wrong character but cannot say which one it is.
// For each position this finds the single replacement, if any, that would make
// the check character agree.
function repairs(slug: string, body: string, check: string): Candidate[] {
  const out: Candidate[] = []
  const target = CHECK_ALPHABET.indexOf(check)

  for (let i = 0; i < slug.length; i++) {
    for (const c of LETTERS) {
      if (c === slug[i]) continue
      if (checkValue(slug.slice(0, i) + c + slug.slice(i + 1), body) === target) {
        out.push({ position: i + 1, typed: slug[i]!, repair: c })
      }
    }
  }
  for (let i = 0; i < body.length; i++) {
    for (const c of ALPHABET) {
      if (c === body[i]) continue
      if (checkValue(slug, body.slice(0, i) + c + body.slice(i + 1)) === target) {
        out.push({ position: slug.length + i + 1, typed: body[i]!, repair: c })
      }
    }
  }
  out.push({ position: slug.length + body.length + 1, typed: check, repair: checkCharFor(slug, body) })
  return out
}

// Pairs that are easy to confuse when a code is read from print, a photocopy
// or a photo. Order within a pair does not matter.
const LOOKALIKES = [
  '0D', '0Q', '17', '1T', '2Z', '38', '4A', '5S', '6G', '68', '8B', '9G', '9Q',
  'CG', 'EF', 'HN', 'KX', 'MN', 'PR', 'UV', 'VY', 'VW', 'OQ', 'OD', 'IL', 'IJ',
]
// Keyboard rows. Neighbours in a row are one slip of the thumb apart, on a phone or a desktop.
const KEY_ROWS = ['1234567890', 'QWERTYUIOP', 'ASDFGHJKL', 'ZXCVBNM']
const LOOKALIKE_SCORE = 3
const ADJACENT_SCORE = 2
const MAX_SUSPECTS = 3

function slipScore(a: string, b: string): number {
  let score = 0
  if (LOOKALIKES.includes(a + b) || LOOKALIKES.includes(b + a)) score += LOOKALIKE_SCORE
  for (const row of KEY_ROWS) {
    const i = row.indexOf(a)
    const j = row.indexOf(b)
    if (i >= 0 && j >= 0 && Math.abs(i - j) === 1) score += ADJACENT_SCORE
  }
  return score
}

/**
 * Picks the positions a person should re-check, most likely first.
 *
 * Every candidate is a position where changing `typed` to `repair` would make
 * the code consistent. Usually there are several and only one is the real slip,
 * so a candidate is only reported when the two characters look alike or sit
 * next to each other on a keyboard. An empty result means there is nothing
 * worth pointing at and the caller should ask for the whole code to be checked.
 *
 * Ties go to the body over the slug (slugs are known words, rarely mistyped)
 * and then to the later position.
 */
export function rankSuspects(candidates: Candidate[], slugLength: number): number[] {
  return candidates
    .map((c) => ({ position: c.position, score: slipScore(c.typed, c.repair), inSlug: c.position <= slugLength }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score || Number(a.inSlug) - Number(b.inSlug) || b.position - a.position)
    .slice(0, MAX_SUSPECTS)
    .map((c) => c.position)
}
