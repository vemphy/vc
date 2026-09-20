// Writes vectors/{claims,keys,status,canon} and vectors/expected.json.
//
// Everything here is derived from fixed inputs, and Ed25519 signatures are
// deterministic, so running this twice produces identical files. CI runs it
// and fails if anything under vectors/ changes.
import { mkdirSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { canonicalize } from '../src/canon.js'
import { ALPHABET, formatCode, isIssuable } from '../src/code.js'
import { CLAIMS_V1, CREDENTIALS_V2 } from '../src/context/urls.js'
import { encodeMultikey } from '../src/multibase.js'
import { createProof, memorySigner } from '../src/proof.js'
import { encodeList, LIST_BITS, setBit } from '../src/status.js'

const NOW = '2026-06-01T12:00:00Z'
const root = fileURLToPath(new URL('../../../vectors/', import.meta.url))

type Json = Record<string, unknown>

function write(path: string, value: Json | string) {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n'
  writeFileSync(root + path, text)
}

// ---- keys -----------------------------------------------------------------

const seedFor = (slug: string, kid: string) => sha256(new TextEncoder().encode(`vemphy test key ${slug} ${kid}`))
const did = (slug: string) => `did:web:vemphy.com:i:${slug}`
const signerFor = (slug: string, kid: string) => memorySigner(seedFor(slug, kid), `${did(slug)}#${kid}`)

type KeySpec = { kid: string; active: boolean; revoked?: string }

const issuers: Record<string, KeySpec[]> = {
  gcb: [
    { kid: 'key-1', active: false }, // retired when key-2 took over
    { kid: 'key-2', active: true },
    { kid: 'key-3', active: false, revoked: '2026-03-01T00:00:00Z' },
  ],
  ug: [{ kid: 'key-1', active: true }],
  emp: [{ kid: 'key-1', active: true }],
}

async function didDocument(slug: string): Promise<Json> {
  const id = did(slug)
  const verificationMethod = []
  for (const key of issuers[slug]!) {
    const signer = await signerFor(slug, key.kid)
    verificationMethod.push({
      id: `${id}#${key.kid}`,
      type: 'Multikey',
      controller: id,
      publicKeyMultibase: encodeMultikey(signer.publicKey),
      ...(key.revoked && { revoked: key.revoked }),
    })
  }
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id,
    verificationMethod,
    assertionMethod: issuers[slug]!.filter((k) => k.active).map((k) => `${id}#${k.kid}`),
  }
}

// ---- codes ----------------------------------------------------------------

// A seven-character body derived from the vector name, skipping any whose
// check character is a symbol.
function codeFor(slug: string, name: string): string {
  for (let salt = 0; ; salt++) {
    const hash = sha256(new TextEncoder().encode(`${name}/${salt}`))
    const body = [...hash.slice(0, 7)].map((b) => ALPHABET[b & 31]).join('')
    const code = formatCode(slug, body)
    if (isIssuable(code)) return code
  }
}

// ---- status lists ---------------------------------------------------------

type ListSpec = { slug: string; n: number; kid: string; set: number[]; validFrom: string; validUntil: string }

const lists: ListSpec[] = [
  // A bank's list lives for five minutes.
  { slug: 'gcb', n: 1, kid: 'key-2', set: [4_242, 77_001], validFrom: '2026-06-01T11:58:00Z', validUntil: '2026-06-01T12:03:00Z' },
  // This one was not refreshed: its validity ended before NOW.
  { slug: 'gcb', n: 2, kid: 'key-2', set: [], validFrom: '2026-06-01T11:00:00Z', validUntil: '2026-06-01T11:05:00Z' },
  { slug: 'ug', n: 1, kid: 'key-1', set: [], validFrom: '2026-06-01T11:30:00Z', validUntil: '2026-06-01T12:30:00Z' },
  { slug: 'emp', n: 1, kid: 'key-1', set: [], validFrom: '2026-06-01T11:30:00Z', validUntil: '2026-06-01T12:30:00Z' },
]

const listUrl = (slug: string, n: number) => `https://vemphy.com/i/${slug}/status/${n}`

async function statusList(spec: ListSpec): Promise<Json> {
  const bits = new Uint8Array(LIST_BITS / 8)
  for (const index of spec.set) setBit(bits, index)
  const id = listUrl(spec.slug, spec.n)
  const unsigned = {
    '@context': [CREDENTIALS_V2],
    id,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: did(spec.slug),
    validFrom: spec.validFrom,
    validUntil: spec.validUntil,
    credentialSubject: {
      id: `${id}#list`,
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList: await encodeList(bits),
    },
  }
  return createProof(unsigned, await signerFor(spec.slug, spec.kid), { created: spec.validFrom })
}

// ---- claims ---------------------------------------------------------------

type ClaimSpec = {
  name: string
  slug: string
  type: string
  subject: Json
  kid: string
  created: string
  validFrom: string
  validUntil?: string
  list?: number
  index: number
  /** Applied after signing. */
  alter?: (signed: any) => void
  expect: { result: string; reason?: string }
  note: string
}

const bankSubject = {
  accountHolderName: 'Ama Serwaa Mensah',
  accountType: 'current',
  accountNumberLast4: '0042',
  accountOpenedOn: '2019-03-04',
  branch: 'Accra High Street',
  standing: 'satisfactory',
  addressedTo: 'The Consular Section',
  referenceDate: '2026-05-04',
}

const gcb = (spec: Partial<ClaimSpec> & Pick<ClaimSpec, 'name' | 'index' | 'expect' | 'note'>): ClaimSpec => ({
  slug: 'gcb',
  type: 'BankReferenceLetter',
  subject: bankSubject,
  kid: 'key-2',
  created: '2026-05-04T09:00:00Z',
  validFrom: '2026-05-04T09:00:00Z',
  validUntil: '2026-08-04T09:00:00Z',
  ...spec,
})

const claims: ClaimSpec[] = [
  gcb({ name: 'gcb-001', index: 94_567, expect: { result: 'valid' }, note: 'A bank reference letter in good order.' }),
  {
    name: 'ug-001',
    slug: 'ug',
    type: 'DegreeCertificate',
    subject: {
      graduateName: 'Kwame Boateng',
      studentNumber: '10456789',
      qualification: 'BSc',
      programme: 'Computer Science',
      classification: 'First Class Honours',
      conferredOn: '2024-11-16',
    },
    kid: 'key-1',
    created: '2024-11-18T10:00:00Z',
    validFrom: '2024-11-16T00:00:00Z',
    index: 1_001,
    expect: { result: 'valid' },
    note: 'A degree certificate. It has no validUntil.',
  },
  {
    name: 'emp-001',
    slug: 'emp',
    type: 'EmploymentLetter',
    subject: {
      employeeName: 'Efua Asante',
      staffNumber: 'E-2210',
      jobTitle: 'Senior Accountant',
      employmentType: 'permanent',
      startDate: '2021-02-01',
      currentlyEmployed: true,
    },
    kid: 'key-1',
    created: '2026-05-20T14:30:00Z',
    validFrom: '2026-05-20T14:30:00Z',
    validUntil: '2026-08-20T14:30:00Z',
    index: 58_310,
    expect: { result: 'valid' },
    note: 'An employment letter in good order.',
  },
  gcb({
    name: 'gcb-002',
    index: 94_568,
    alter: (c) => (c.credentialSubject.accountHolderName = 'Ama Serwaa Mensa'),
    expect: { result: 'unknown', reason: 'signature_failure' },
    note: 'One letter of the account holder name was changed after signing.',
  }),
  gcb({
    name: 'gcb-003',
    index: 94_569,
    kid: 'key-9',
    expect: { result: 'unknown', reason: 'key_not_found' },
    note: 'Signed with a key that is not in the issuer DID document.',
  }),
  gcb({ name: 'gcb-004', index: 4_242, expect: { result: 'revoked' }, note: 'Its bit is set in the status list.' }),
  gcb({
    name: 'gcb-005',
    index: 94_570,
    created: '2026-01-10T09:00:00Z',
    validFrom: '2026-01-10T09:00:00Z',
    validUntil: '2026-04-10T09:00:00Z',
    expect: { result: 'expired' },
    note: 'validUntil has passed.',
  }),
  gcb({
    name: 'gcb-006',
    index: 94_571,
    kid: 'key-3',
    created: '2026-04-01T09:00:00Z',
    validFrom: '2026-04-01T09:00:00Z',
    validUntil: '2026-07-01T09:00:00Z',
    expect: { result: 'unknown', reason: 'key_window_violation' },
    note: 'Signed with key-3 a month after key-3 was revoked.',
  }),
  gcb({
    name: 'gcb-007',
    index: 94_572,
    kid: 'key-1',
    created: '2025-11-03T09:00:00Z',
    validFrom: '2025-11-03T09:00:00Z',
    validUntil: '2026-11-03T09:00:00Z',
    expect: { result: 'valid' },
    note: 'Signed with key-1, which has since been retired in favour of key-2. Rotation does not disturb it.',
  }),
  gcb({
    name: 'gcb-008',
    index: 94_573,
    list: 2,
    expect: { result: 'unknown', reason: 'status_list_unverifiable' },
    note: 'Its status list is past its own validUntil, so revocation cannot be ruled out.',
  }),
  gcb({
    name: 'gcb-009',
    index: 94_574,
    alter: (c) => c['@context'].push('https://example.com/extra/v1'),
    expect: { result: 'unknown', reason: 'malformed' },
    note: 'Carries a context that is not one of the two a claim may use.',
  }),
  gcb({
    name: 'gcb-010',
    index: 77_001,
    created: '2026-01-10T09:00:00Z',
    validFrom: '2026-01-10T09:00:00Z',
    validUntil: '2026-04-10T09:00:00Z',
    expect: { result: 'revoked' },
    note: 'Both revoked and past validUntil. Revocation is reported.',
  }),
  gcb({
    name: 'gcb-011',
    index: 94_575,
    kid: 'key-3',
    created: '2026-02-02T09:00:00Z',
    validFrom: '2026-02-02T09:00:00Z',
    validUntil: '2026-08-02T09:00:00Z',
    expect: { result: 'valid' },
    note: 'Signed with key-3 a month before key-3 was revoked.',
  }),
]

async function claim(spec: ClaimSpec): Promise<{ signed: Json; unsigned: Json }> {
  const code = codeFor(spec.slug.toUpperCase(), spec.name)
  const list = listUrl(spec.slug, spec.list ?? 1)
  const unsigned = {
    '@context': [CREDENTIALS_V2, CLAIMS_V1],
    id: `urn:vemphy:claim:${code}`,
    type: ['VerifiableCredential', spec.type],
    issuer: did(spec.slug),
    validFrom: spec.validFrom,
    ...(spec.validUntil && { validUntil: spec.validUntil }),
    credentialSubject: spec.subject,
    credentialStatus: {
      id: `${list}#${spec.index}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(spec.index),
      statusListCredential: list,
    },
  }
  const signed = structuredClone(await createProof(unsigned, await signerFor(spec.slug, spec.kid), { created: spec.created }))
  spec.alter?.(signed)
  return { signed, unsigned }
}

// ---- write ----------------------------------------------------------------

for (const dir of ['claims', 'keys', 'status', 'canon']) mkdirSync(root + dir, { recursive: true })

const seeds: Json = {
  warning: 'TEST KEYS. These seeds are public. Never use them outside tests.',
  seeds: {},
}
for (const [slug, keys] of Object.entries(issuers)) {
  write(`keys/${slug}.did.json`, await didDocument(slug))
  for (const key of [...keys, ...(slug === 'gcb' ? [{ kid: 'key-9' }] : [])]) {
    ;(seeds.seeds as Json)[`${did(slug)}#${key.kid}`] = bytesToHex(seedFor(slug, key.kid))
  }
}
write('keys/test-seeds.json', seeds)

for (const spec of lists) write(`status/${spec.slug}-${spec.n}.json`, await statusList(spec))

const expected: Json = {}
for (const spec of claims) {
  const { signed, unsigned } = await claim(spec)
  write(`claims/${spec.name}.json`, signed)
  write(`canon/${spec.name}.nq`, await canonicalize(unsigned))
  expected[spec.name] = { ...spec.expect, note: spec.note }
}
write('expected.json', { now: NOW, vectors: expected })

console.log(`wrote ${claims.length} claims, ${lists.length} status lists, ${Object.keys(issuers).length} DID documents`)
