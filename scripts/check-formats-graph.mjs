#!/usr/bin/env node
// Complements the source-level graph walk in packages/vc/src/formats.test.ts.
// That test proves nobody *wrote* an import reaching Ajv; this proves the
// bundler didn't *merge* one in regardless. tsup gives @vemphy/vc/formats its
// own dist/formats.js but shares code across entries as chunks (see
// packages/vc/tsup.config.ts), so a shared chunk is the one way Ajv could
// reach this entry without any source file importing it directly. Run after
// `pnpm build`, once dist/ exists — that's why this lives here and not in
// `pnpm test`, which must pass on a clean checkout with no build output.
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

const entry = resolve(import.meta.dirname, '../packages/vc/dist/formats.js')

// Matches both `from "./x.js"` and bare `import "./x.js"`, which is all tsup
// emits for ESM output: relative chunk references and, in principle, bare
// package specifiers (which is exactly what must not appear here).
const IMPORT_PATTERN = /(?:from|import)\s+["']([^"']+)["']/g

function importsOf(source) {
  return [...source.matchAll(IMPORT_PATTERN)].map((m) => m[1])
}

// Walks the real, on-disk module graph reachable from dist/formats.js. A
// cycle is impossible for tsup's chunk output, but the `seen` guard costs
// nothing and keeps this correct if that ever changes.
function moduleGraph(start) {
  const files = new Map()
  const seen = new Set()
  const queue = [start]
  while (queue.length > 0) {
    const path = queue.pop()
    if (seen.has(path)) continue
    seen.add(path)
    const source = readFileSync(path, 'utf8')
    files.set(path, source)
    for (const specifier of importsOf(source)) {
      if (specifier.startsWith('.')) queue.push(resolve(dirname(path), specifier))
    }
  }
  return files
}

const graph = moduleGraph(entry)
if (graph.size === 0) throw new Error(`no files found from ${entry}`)

let bad = false
for (const [path, source] of graph) {
  if (/ajv/i.test(source) || importsOf(source).some((s) => /ajv/i.test(s))) {
    console.error(`Ajv reference found in ${path}`)
    bad = true
  }
}

if (bad) process.exit(1)
console.log(`dist/formats.js and its ${graph.size - 1} chunk(s) have no reference to Ajv`)
