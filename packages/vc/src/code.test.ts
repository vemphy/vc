import { describe, expect, it } from 'vitest'
import {
  ALPHABET,
  CHECK_ALPHABET,
  checkChar,
  checkCharFor,
  formatCode,
  isIssuable,
  parseCode,
} from './code.js'

describe('checkChar', () => {
  it('matches Crockford mod-37 check symbols', () => {
    expect(checkChar(0n)).toBe('0')
    expect(checkChar(31n)).toBe('Z')
    expect(checkChar(32n)).toBe('*')
    expect(checkChar(33n)).toBe('~')
    expect(checkChar(34n)).toBe('$')
    expect(checkChar(35n)).toBe('=')
    expect(checkChar(36n)).toBe('U')
    expect(checkChar(37n)).toBe('0')
    expect(checkChar(1234n)).toBe('D')
  })
})

describe('checkCharFor', () => {
  it('covers the slug as well as the body', () => {
    expect(checkCharFor('GCB', '0000000')).toBe('1')
    expect(checkCharFor('UG', '0000000')).toBe('4')
    expect(checkCharFor('GCB', '7K2M9QX')).toBe('D')
  })

  it('equals the plain Crockford check of slug * 2^35 + body', () => {
    // GCB read as base 26 is 4109; 7K2M9QX read as base 32 is the body value.
    const body = [...'7K2M9QX'].reduce((n, c) => n * 32n + BigInt(ALPHABET.indexOf(c)), 0n)
    expect(checkCharFor('GCB', '7K2M9QX')).toBe(checkChar(4109n * 2n ** 35n + body))
  })
})

describe('parseCode', () => {
  const expected = { ok: true, code: 'GCB-7K2M-9QXD', slug: 'GCB', body: '7K2M9QX', check: 'D' }

  it.each([
    'GCB-7K2M-9QXD',
    'gcb 7k2m 9qxd',
    'GCB7K2M9QXD',
    ' gcb-7k2m-9qxd\n',
    'https://vemphy.com/v/GCB-7K2M-9QXD',
    'https://vemphy.com/v/gcb-7k2m-9qxd?utm=x',
    'vemphy.com/v/GCB-7K2M-9QXD',
  ])('accepts %j', (input) => {
    expect(parseCode(input)).toEqual(expected)
  })

  it('folds O, I and L in the body and check character', () => {
    expect(parseCode('GCB-OOOO-OOOI')).toMatchObject({ ok: true, code: 'GCB-0000-0001' })
    expect(parseCode('gcb-oooo-oool')).toMatchObject({ ok: true, code: 'GCB-0000-0001' })
  })

  it('never folds the slug', () => {
    expect(parseCode('G0B-0000-0001')).toMatchObject({ ok: false, error: 'format' })
    // A slug may legitimately contain I, L, O or U.
    const check = checkCharFor('LOU', '0000000')
    expect(parseCode(`LOU-0000-000${check}`)).toMatchObject({ ok: true, slug: 'LOU' })
  })

  it.each(['', 'GCB-7K2M-9QX', 'TOOLONG-0000-0001', 'G-0000-0001', 'GCB-7K2M-9QXDD', 'GCB-7U2M-9QXD'])(
    'rejects %j as a format error',
    (input) => {
      expect(parseCode(input)).toMatchObject({ ok: false, error: 'format' })
    },
  )

  it('points at an invalid character', () => {
    expect(parseCode('GCB-7U2M-9QXD')).toEqual({ ok: false, error: 'format', position: 5 })
    expect(parseCode('GC8-7K2M-9QXD')).toEqual({ ok: false, error: 'format', position: 3 })
  })

  it('catches a mistyped slug', () => {
    expect(parseCode('GCD-7K2M-9QXD')).toMatchObject({ ok: false, error: 'check' })
  })

  it('catches every single-character substitution', () => {
    const chars = [...'GCB7K2M9QXD']
    let tried = 0
    chars.forEach((original, i) => {
      const pool = i < 3 ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : i < 10 ? ALPHABET : CHECK_ALPHABET
      for (const replacement of pool) {
        if (replacement === original) continue
        const typed = chars.map((c, j) => (j === i ? replacement : c)).join('')
        const result = parseCode(typed)
        expect(result, typed).toMatchObject({ ok: false, error: 'check' })
        if (!result.ok && result.error === 'check') {
          expect(result.suspects, typed).toContain(i + 1)
        }
        tried++
      }
    })
    expect(tried).toBe(3 * 25 + 7 * 31 + 36)
  })
})

describe('formatCode / isIssuable', () => {
  it('formats with the computed check character', () => {
    expect(formatCode('GCB', '7K2M9QX')).toBe('GCB-7K2M-9QXD')
    expect(formatCode('gcb', '7k2m9qx')).toBe('GCB-7K2M-9QXD')
  })

  it('marks symbol check characters as not issuable but still parses them', () => {
    expect(isIssuable('GCB-0000-0001')).toBe(true)
    // GCB adds 1 to the body value mod 37, so body 31 ('000000Z') gives check value 32 = '*'.
    const code = formatCode('GCB', '000000Z')
    expect(code).toBe('GCB-0000-00Z*')
    expect(parseCode(code)).toMatchObject({ ok: true })
    expect(isIssuable(code)).toBe(false)
  })
})
