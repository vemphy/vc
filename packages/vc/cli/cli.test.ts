import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { type Io, run } from './run.js'

const vectors = fileURLToPath(new URL('../../../vectors/', import.meta.url))
const claim = (name: string) => join(vectors, 'claims', `${name}.json`)

// Any attempt to use the network is recorded and refused.
function offline() {
  const out: string[] = []
  const err: string[] = []
  const requests: string[] = []
  const io: Io = {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    fetch: async (input) => {
      requests.push(String(input))
      throw new Error('offline')
    },
  }
  return { io, out, err, requests }
}

describe('vemphy-vc verify', () => {
  it('prints valid for gcb-001 without touching the network', async () => {
    const t = offline()
    expect(await run(['verify', claim('gcb-001')], t.io)).toBe(0)
    expect(t.out).toEqual(['valid'])
    expect(t.requests).toEqual([])
  })

  it.each([
    ['gcb-004', 'revoked'],
    ['gcb-005', 'expired'],
    ['gcb-002', 'unknown'],
  ])('prints the result for %s and exits 1', async (name, word) => {
    const t = offline()
    expect(await run(['verify', claim(name)], t.io)).toBe(1)
    expect(t.out).toEqual([word])
    expect(t.err).toEqual([])
  })

  it('explains itself only with --verbose, and only on stderr', async () => {
    const t = offline()
    await run(['verify', claim('gcb-002'), '--verbose'], t.io)
    expect(t.out).toEqual(['unknown'])
    expect(t.err).toContain('reason: signature_failure')
    expect(t.err).toContain('stop signature')
  })

  it('honours --now', async () => {
    const t = offline()
    expect(await run(['verify', claim('gcb-001'), '--now', '2027-01-01T00:00:00Z'], t.io)).toBe(1)
    // The committed status list is not current at that instant, so nothing can be said.
    expect(t.out).toEqual(['unknown'])
  })

  it('takes the DID document and status list from files', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vemphy-vc-'))
    const copy = join(dir, 'claim.json')
    writeFileSync(copy, execFileSync('cat', [claim('gcb-001')]))
    const t = offline()
    const code = await run(
      ['verify', copy, '--now', '2026-06-01T12:00:00Z',
        '--did-doc', join(vectors, 'keys', 'gcb.did.json'), '--status-list', join(vectors, 'status', 'gcb-1.json')],
      t.io,
    )
    expect([code, t.out, t.requests]).toEqual([0, ['valid'], []])
  })

  it('falls back to vemphy.com when nothing local is available', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vemphy-vc-'))
    const copy = join(dir, 'claim.json')
    writeFileSync(copy, execFileSync('cat', [claim('gcb-001')]))
    const t = offline()
    expect(await run(['verify', copy], t.io)).toBe(1)
    expect(t.out).toEqual(['unknown'])
    expect(t.requests).toEqual(['https://vemphy.com/i/gcb/did.json'])
  })

  it.each([[[]], [['verify']], [['check', 'x.json']], [['verify', 'a.json', 'b.json']], [['verify', '/nonexistent.json']],
    [['verify', claim('gcb-001'), '--now', 'yesterday']], [['verify', claim('gcb-001'), '--bogus']]])(
    'exits 2 for %j',
    async (argv) => {
      const t = offline()
      expect(await run(argv, t.io)).toBe(2)
      expect(t.out).toEqual([])
    },
  )

  it('runs as a program', () => {
    const main = fileURLToPath(new URL('./main.ts', import.meta.url))
    const stdout = execFileSync(process.execPath, ['--import', 'tsx', main, 'verify', claim('gcb-001')], { encoding: 'utf8' })
    expect(stdout).toBe('valid\n')
  })
})
