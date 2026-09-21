import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { formats, isDate, isDateTime, isEmail, isUri } from './formats.js'

// This exercises the built output, not the source: tsup gives each entry its
// own file but shares code between entries as chunks (see tsup.config.ts), so
// the only honest way to know what `@vemphy/vc/formats` drags into a bundle
// is to read dist/formats.js and follow its imports, the way a bundler would.
// A test that only called isDate() would still pass if Ajv were reachable
// from this entry — it would just never be exercised — so it would not catch
// the regression this file exists to prevent.
const dist = resolve(dirname(fileURLToPath(import.meta.url)), '../dist')

// Matches both `from "./x.js"` and bare `import "./x.js"`, which is all tsup
// emits for ESM output: relative chunk references and, in principle, bare
// package specifiers (which is exactly what must not appear here).
const IMPORT_PATTERN = /(?:from|import)\s+["']([^"']+)["']/g

function importsOf(source: string): string[] {
  return [...source.matchAll(IMPORT_PATTERN)].map((m) => m[1]!)
}

// Walks the real, on-disk module graph reachable from dist/formats.js,
// returning every file's path and contents. A cycle is impossible for
// tsup's chunk output, but the `seen` guard costs nothing and keeps this
// correct if that ever changes.
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
      // A relative specifier is a chunk on disk to keep walking; a bare one
      // (a package name) has nothing to resolve locally, so it is judged by
      // its name alone, which the assertion below already does for every
      // specifier, relative or not.
      if (specifier.startsWith('.')) queue.push(resolve(dirname(path), specifier))
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

  it('has no reference to Ajv anywhere in its built module graph', () => {
    const graph = moduleGraph(resolve(dist, 'formats.js'))
    expect(graph.size).toBeGreaterThan(0)
    for (const [path, source] of graph) {
      expect(importsOf(source).join(' '), path).not.toMatch(/ajv/i)
      expect(source, path).not.toMatch(/ajv/i)
    }
  })
})
