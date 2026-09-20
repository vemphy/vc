import { CLAIMS_V1 } from '../context/urls.js'

/** One published version of a claim type. `issuer` is the lowercase issuer slug, absent for a core type. */
export type TypeRef = { issuer?: string; name: string; version: number }

const PATH = /^(?:core|i\/([a-z]{2,4}))\/([A-Z][a-zA-Z0-9]{1,39})\/v([1-9]\d{0,5})$/
const NS = 'https://vemphy.com/ns/'
const SCHEMAS = 'https://vemphy.com/schemas/'

const path = (ref: TypeRef) => `${ref.issuer === undefined ? 'core' : `i/${ref.issuer}`}/${ref.name}/v${ref.version}`

/** Where the JSON-LD context of a published type version lives. It never changes. */
export const contextUrl = (ref: TypeRef) => `${NS}${path(ref)}`

/** Where the JSON Schema document of a published type version lives. It never changes. */
export const schemaUrl = (ref: TypeRef) => `${SCHEMAS}${path(ref)}.json`

/** The namespace the fields of a type version are defined under: its context URL and `#`. */
export const namespaceOf = (ref: TypeRef) => `${contextUrl(ref)}#`

function parse(url: string, prefix: string, suffix: string): TypeRef | undefined {
  if (!url.startsWith(prefix) || !url.endsWith(suffix)) return undefined
  const m = PATH.exec(url.slice(prefix.length, url.length - suffix.length))
  if (!m) return undefined
  return { ...(m[1] !== undefined && { issuer: m[1] }), name: m[2]!, version: Number(m[3]) }
}

export const parseContextUrl = (url: string) => parse(url, NS, '')
export const parseSchemaUrl = (url: string) => parse(url, SCHEMAS, '.json')

/** The three types of 0.1.0. Claims issued under `claims/v1` carry one of these and no `credentialSchema`. */
export const LEGACY_TYPES = ['BankReferenceLetter', 'DegreeCertificate', 'EmploymentLetter'] as const
export const LEGACY_CONTEXT = CLAIMS_V1
