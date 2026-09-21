import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { documentLoader, schemaLoader } from '../src/context/loader.js'
import { apexDidUrl, didToUrl, slugOf } from '../src/did.js'
import { DirectoryExpiredError, verifyDirectory } from '../src/directory.js'
import { dirCache } from './cache.js'
import { verifyCredential } from '../src/verify.js'

export type Io = {
  out(line: string): void
  err(line: string): void
  fetch: typeof globalThis.fetch
}

const USAGE = `Usage: vemphy-vc verify <file> [options]
       vemphy-vc verify-directory <file> [options]

verify prints one word: valid, revoked, expired or unknown.
verify-directory prints one word: valid, expired or unknown.
Exit status is 0 for valid, 1 for anything else, 2 for a usage error.

Options:
  --now <iso>            verify as of this instant (default: the current time)
  --did-doc <file>       read the issuer DID document from a file (verify)
  --status-list <file>   read the status list credential from a file (verify)
  --apex-doc <file>      read Vemphy's apex DID document from a file (verify-directory)
  --vectors <dir>        read DID documents, status lists and the apex document
                         from a vectors directory
  --cache <dir>          where contexts and schemas of issuers' own types are kept
                         (default: <vectors>/cache, or ~/.cache/vemphy-vc)
  --offline              make no network request at all
  --verbose              also print the reason (and, for verify, the checks made), on stderr
  --help                 show this message

Without --did-doc/--apex-doc and --status-list, a vectors directory above
<file> is used when there is one. Otherwise everything is fetched over HTTPS
from vemphy.com.

Core claim types verify with nothing but this package. A claim of an issuer's
own type needs that type's context, which is fetched once from
https://vemphy.com/ns/ and kept in the cache for ever: a published context
never changes. No other origin is ever asked for a context.

verify-directory checks Vemphy's own signed issuer directory — the list of
issuers Vemphy recognises — against Vemphy's apex key, resolved from
https://vemphy.com/.well-known/did.json. The directory's own vocabulary is
inline in its @context, so nothing beyond that document is ever fetched.`

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
        'apex-doc': { type: 'string' },
        vectors: { type: 'string' },
        cache: { type: 'string' },
        offline: { type: 'boolean', default: false },
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
  if ((command !== 'verify' && command !== 'verify-directory') || !file || extra.length > 0) {
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

  const cacheDir = values.cache ? resolve(values.cache) : vectors ? join(vectors, 'cache') : defaultCacheDir()
  const documents = { cache: dirCache(cacheDir), ...(!values.offline && { fetch: io.fetch }) }

  const getJson = async (url: string) => {
    if (values.offline) throw new Error(`${url}: offline`)
    const response = await io.fetch(url, { headers: { accept: 'application/json' } })
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`)
    return response.json()
  }

  if (command === 'verify-directory') {
    try {
      const directory = await verifyDirectory(credential, {
        now,
        resolveApex: async () => {
          if (values['apex-doc']) return readJson(values['apex-doc'])
          const local = vectors && join(vectors, 'keys', 'apex.did.json')
          return local && existsSync(local) ? readJson(local) : getJson(apexDidUrl())
        },
      })
      io.out('valid')
      if (values.verbose) {
        io.err(`entries: ${directory.entries.length}`)
        io.err(`validUntil: ${directory.validUntil.toISOString()}`)
        io.err(`as of ${now.toISOString()}`)
      }
      return 0
    } catch (error) {
      io.out(error instanceof DirectoryExpiredError ? 'expired' : 'unknown')
      if (values.verbose) {
        io.err(`reason: ${(error as Error).message}`)
        io.err(`as of ${now.toISOString()}`)
      }
      return 1
    }
  }

  const outcome = await verifyCredential(credential, {
    now,
    documentLoader: documentLoader(documents),
    fetchSchema: schemaLoader(documents),
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
    if (outcome.reason === 'context_unavailable') {
      io.err(`the context of this claim's type is not in ${cacheDir}${values.offline ? ', and --offline was given' : ' and could not be fetched'}`)
    }
    for (const check of outcome.checks) io.err(`${check.ok ? 'ok  ' : 'stop'} ${check.name}`)
    if (outcome.schemaValid !== undefined) io.err(`note the subject ${outcome.schemaValid ? 'matches' : 'does not match'} its schema`)
    io.err(`as of ${now.toISOString()}`)
  }
  return outcome.result === 'valid' ? 0 : 1
}

function defaultCacheDir(): string {
  return join(process.env['XDG_CACHE_HOME'] ?? join(homedir(), '.cache'), 'vemphy-vc')
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
