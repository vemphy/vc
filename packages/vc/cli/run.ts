import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { didToUrl, slugOf } from '../src/did.js'
import { verifyCredential } from '../src/verify.js'

export type Io = {
  out(line: string): void
  err(line: string): void
  fetch: typeof globalThis.fetch
}

const USAGE = `Usage: vemphy-vc verify <file> [options]

Prints one word: valid, revoked, expired or unknown.
Exit status is 0 for valid, 1 for anything else, 2 for a usage error.

Options:
  --now <iso>            verify as of this instant (default: the current time)
  --did-doc <file>       read the issuer DID document from a file
  --status-list <file>   read the status list credential from a file
  --vectors <dir>        read DID documents and status lists from a vectors directory
  --verbose              also print the reason and the checks made, on stderr
  --help                 show this message

Without --did-doc and --status-list, a vectors directory above <file> is used
when there is one. Otherwise both are fetched over HTTPS from vemphy.com.`

const STATUS_URL = /^https:\/\/vemphy\.com\/i\/([a-z]{2,4})\/status\/([1-9]\d*)$/

export async function run(argv: string[], io: Io): Promise<number> {
  let parsed
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        now: { type: 'string' },
        'did-doc': { type: 'string' },
        'status-list': { type: 'string' },
        vectors: { type: 'string' },
        verbose: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
    })
  } catch (error) {
    io.err((error as Error).message)
    io.err(USAGE)
    return 2
  }
  const { values, positionals } = parsed
  if (values.help) {
    io.out(USAGE)
    return 0
  }
  const [command, file, ...extra] = positionals
  if (command !== 'verify' || !file || extra.length > 0) {
    io.err(USAGE)
    return 2
  }

  let credential: unknown
  try {
    credential = JSON.parse(readFileSync(file, 'utf8'))
  } catch (error) {
    io.err(`cannot read ${file}: ${(error as Error).message}`)
    return 2
  }

  const vectors = values.vectors ? resolve(values.vectors) : findVectors(file)

  let now = new Date()
  if (values.now !== undefined) {
    now = new Date(values.now)
    if (Number.isNaN(now.getTime())) {
      io.err(`--now ${values.now} is not a date`)
      return 2
    }
  } else if (vectors && isInside(file, vectors)) {
    // The bundled vectors are signed around a fixed instant, recorded next to them.
    now = new Date(readJson(join(vectors, 'expected.json')).now)
  }

  const getJson = async (url: string) => {
    const response = await io.fetch(url, { headers: { accept: 'application/json' } })
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`)
    return response.json()
  }

  const outcome = await verifyCredential(credential, {
    now,
    resolveDid: async (did) => {
      if (values['did-doc']) return readJson(values['did-doc'])
      const local = vectors && join(vectors, 'keys', `${slugOf(did)}.did.json`)
      return local && existsSync(local) ? readJson(local) : getJson(didToUrl(did))
    },
    fetchStatusList: async (url) => {
      if (values['status-list']) return readJson(values['status-list'])
      const match = STATUS_URL.exec(url)
      const local = vectors && match && join(vectors, 'status', `${match[1]}-${match[2]}.json`)
      return local && existsSync(local) ? readJson(local) : getJson(url)
    },
  })

  io.out(outcome.result)
  if (values.verbose) {
    if (outcome.reason) io.err(`reason: ${outcome.reason}`)
    for (const check of outcome.checks) io.err(`${check.ok ? 'ok  ' : 'stop'} ${check.name}`)
    io.err(`as of ${now.toISOString()}`)
  }
  return outcome.result === 'valid' ? 0 : 1
}

function readJson(path: string) {
  return JSON.parse(readFileSync(path, 'utf8'))
}

function isInside(file: string, dir: string): boolean {
  return resolve(file).startsWith(dir + '/')
}

// The nearest directory named "vectors" that holds an expected.json, walking up from the file.
function findVectors(file: string): string | undefined {
  let dir = dirname(resolve(file))
  for (;;) {
    for (const candidate of [dir, join(dir, 'vectors')]) {
      if (candidate.endsWith('vectors') && existsSync(join(candidate, 'expected.json'))) return candidate
    }
    const parent = dirname(dir)
    if (parent === dir) return undefined
    dir = parent
  }
}
