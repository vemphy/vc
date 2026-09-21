import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { formats, isDate, isDateTime, isEmail, isUri } from './formats.js'

// This walks the *source* graph of src/formats.ts, resolving relative
// specifiers against the source tree rather than dist/. It needs no build,
// so it runs the same way for `pnpm test` in CI (which runs before `pnpm
// build`) and for a contributor on a clean checkout. It catches the failure
// most likely to happen day to day: someone adding an import to
// src/formats.ts or to src/schema/formats.ts that reaches Ajv.
//
// It does not catch Ajv arriving through a bundler's own machinery — tsup
// shares code between entries as chunks, so dist/formats.js could in
// principle end up importing a chunk that also serves ./schema. That case is
// covered separately by scripts/check-formats-graph.mjs, which walks the
// *built* dist/formats.js after `pnpm build` in CI. Two different failures,
// so both checks exist.
const src = dirname(fileURLToPath(import.meta.url))

const IMPORT_PATTERN = /(?:from|import)\s+["']([^"']+)["']/g

function importsOf(source: string): string[] {
  return [...source.matchAll(IMPORT_PATTERN)].map((m) => m[1]!)
}

// Source imports use the `./foo.js` spelling required by NodeNext resolution
// even though the file on disk is `foo.ts`, so a specifier is resolved
// against the source tree by swapping the extension back.
function resolveSpecifier(fromFile: string, specifier: string): string {
  const joined = resolve(dirname(fromFile), specifier)
  return joined.endsWith('.js') ? joined.slice(0, -3) + '.ts' : joined
}

function moduleGraph(entry: string): Map<string, string> {
  const files = new Map<string, string>()
  const seen = new Set<string>()
  const queue = [entry]
  while (queue.length > 0) {
    const path = queue.pop()!
    if (seen.has(path)) continue
    seen.add(path)
    const source = readFileSync(path, 'utf8')
    files.set(path, source)
    for (const specifier of importsOf(source)) {
      if (specifier.startsWith('.')) queue.push(resolveSpecifier(path, specifier))
    }
  }
  return files
}

describe('the formats entry point', () => {
  it('exports the four predicates and the formats record', () => {
    expect(isDate('2026-01-01')).toBe(true)
    expect(isDateTime('2026-01-01T00:00:00Z')).toBe(true)
    expect(isEmail('a@example.com')).toBe(true)
    expect(isUri('https://example.com')).toBe(true)
    expect(formats.date).toBe(isDate)
  })

  it('has no import reaching Ajv anywhere in its source module graph', () => {
    // Checked against import specifiers, not the full source text: a source
    // file is allowed to mention Ajv in a comment (this file's own doc
    // comment does, explaining exactly this), so scanning prose would give a
    // false positive. What must never appear is an import naming it.
    const graph = moduleGraph(resolve(src, 'formats.ts'))
    expect(graph.size).toBeGreaterThan(0)
    for (const [path, source] of graph) {
      expect(importsOf(source).join(' '), path).not.toMatch(/ajv/i)
    }
  })
})
