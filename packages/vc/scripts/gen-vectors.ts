// Writes vectors/{claims,keys,status,canon,schemas,cache}, vectors/patterns.json and vectors/expected.json.
//
// Everything here is derived from fixed inputs, and Ed25519 signatures are
// deterministic, so running this twice produces identical files. CI runs it
// and fails if anything under vectors/ changes.
//
// The one input not under this script's control is zlib: status lists are
// gzip-compressed, and a Node release with a different zlib may compress them
// differently. If CI reports a diff in vectors/status after a Node upgrade,
// regenerate and commit. Every test still has to pass with the new files.
import { mkdirSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { canonicalize } from '../src/canon.js'
import { ALPHABET, formatCode, isIssuable } from '../src/code.js'
import { CLAIMS_V1, CREDENTIALS_V2 } from '../src/context/urls.js'
import { APEX_DID } from '../src/did.js'
import { encodeMultikey } from '../src/multibase.js'
import { documentLoader } from '../src/context/loader.js'
import { createProof, memorySigner } from '../src/proof.js'
import {
  assertNoDroppedTerms,
  canonicalJson,
  type ClaimSchema,
  contextFromSchema,
  contextUrl,
  coreTypes,
  credentialSchemaDocument,
  namespaceOf,
  schemaUrl,
  type TypeRef,
  validateSchema,
  validateSubject,
} from '../src/schema/index.js'
import { cacheFileName } from '../cli/cache.js'
import { customTypes, invalidSchemas, patterns, subjectFixtures } from './vector-schemas.js'
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

// ---- apex DID and issuer directory -----------------------------------------

// Vemphy's own DID, at the apex. key-1 signs the directory below; key-2 exists
// only so a directory signed with it, after it was revoked, can be refused.
const apexKeys: KeySpec[] = [
  { kid: 'key-1', active: true },
  { kid: 'key-2', active: false, revoked: '2026-05-15T00:00:00Z' },
]
const apexSignerFor = (kid: string) => memorySigner(seedFor('apex', kid), `${APEX_DID}#${kid}`)

async function apexDidDocument(): Promise<Json> {
  const verificationMethod = []
  for (const key of apexKeys) {
    const signer = await apexSignerFor(key.kid)
    verificationMethod.push({
      id: `${APEX_DID}#${key.kid}`,
      type: 'Multikey',
      controller: APEX_DID,
      publicKeyMultibase: encodeMultikey(signer.publicKey),
      ...(key.revoked && { revoked: key.revoked }),
    })
  }
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
    id: APEX_DID,
    verificationMethod,
    assertionMethod: apexKeys.filter((k) => k.active).map((k) => `${APEX_DID}#${k.kid}`),
  }
}

const DIRECTORY_ID = 'https://vemphy.com/.well-known/vemphy-issuers.json'

// The vocabulary is inline, not a URL, so verifying the directory fetches
// nothing beyond the W3C context that every claim already uses.
const DIRECTORY_CONTEXT = [
  CREDENTIALS_V2,
  {
    did: 'vemphy:did',
    slug: 'vemphy:slug',
    status: 'vemphy:status',
    vemphy: 'https://vemphy.com/ns/directory#',
    issuers: { '@id': 'vemphy:issuers', '@container': '@set' },
    legalName: 'vemphy:legalName',
    '@protected': true,
    VemphyIssuerDirectory: 'vemphy:VemphyIssuerDirectory',
    VemphyIssuerDirectoryCredential: 'vemphy:VemphyIssuerDirectoryCredential',
  },
]

const directoryEntries = [
  { slug: 'gcb', legalName: 'GCB Bank PLC', did: did('gcb'), status: 'active' },
  { slug: 'ug', legalName: 'University of Ghana', did: did('ug'), status: 'active' },
  { slug: 'emp', legalName: 'Example Employer Ltd', did: did('emp'), status: 'suspended' },
]

// documentLoader() alone (bundled contexts, nothing cached or fetched) is enough to sign and
// canonicalise the directory: its only string context entry is the bundled W3C one.
const directoryLoader = documentLoader()

type DirectorySpec = {
  name: string
  kid: string
  created: string
  validFrom: string
  validUntil: string
  /** Applied after signing. */
  alter?: (signed: any) => void
  expect: { result: 'valid' | 'expired' | 'not-trustworthy' }
  note: string
}

const directories: DirectorySpec[] = [
  {
    name: 'good',
    kid: 'key-1',
    created: '2026-06-01T11:32:00Z',
    validFrom: '2026-06-01T11:32:00Z',
    validUntil: '2026-06-01T12:32:00Z',
    expect: { result: 'valid' },
    note: 'The issuer directory in good order.',
  },
  {
    name: 'expired',
    kid: 'key-1',
    created: '2026-05-01T09:00:00Z',
    validFrom: '2026-05-01T09:00:00Z',
    validUntil: '2026-05-01T10:00:00Z',
    expect: { result: 'expired' },
    note: 'validUntil has passed by NOW.',
  },
  {
    name: 'altered-status',
    kid: 'key-1',
    created: '2026-06-01T11:32:00Z',
    validFrom: '2026-06-01T11:32:00Z',
    validUntil: '2026-06-01T12:32:00Z',
    alter: (signed) => (signed.credentialSubject.issuers[2].status = 'active'),
    expect: { result: 'not-trustworthy' },
    note: "One issuer's status was changed after signing; the inline vocabulary makes it part of what is signed.",
  },
  {
    name: 'altered-legal-name',
    kid: 'key-1',
    created: '2026-06-01T11:32:00Z',
    validFrom: '2026-06-01T11:32:00Z',
    validUntil: '2026-06-01T12:32:00Z',
    alter: (signed) => (signed.credentialSubject.issuers[0].legalName = 'GCB Holdings PLC'),
    expect: { result: 'not-trustworthy' },
    note: "One issuer's legalName was changed after signing.",
  },
  {
    name: 'key-window-violation',
    kid: 'key-2',
    created: '2026-06-01T11:32:00Z',
    validFrom: '2026-06-01T11:32:00Z',
    validUntil: '2026-06-01T12:32:00Z',
    expect: { result: 'not-trustworthy' },
    note: 'Signed with key-2, revoked over two weeks before this proof was made.',
  },
]

async function directoryCredential(spec: DirectorySpec): Promise<Json> {
  const unsigned = {
    '@context': DIRECTORY_CONTEXT,
    id: DIRECTORY_ID,
    type: ['VerifiableCredential', 'VemphyIssuerDirectoryCredential'],
    issuer: APEX_DID,
    validFrom: spec.validFrom,
    validUntil: spec.validUntil,
    credentialSubject: {
      id: `${DIRECTORY_ID}#issuers`,
      type: 'VemphyIssuerDirectory',
      issuers: directoryEntries,
    },
  }
  const signer = await apexSignerFor(spec.kid)
  const signed = structuredClone(await createProof(unsigned, signer, { created: spec.created }, directoryLoader))
  spec.alter?.(signed)
  return signed
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
  /** The published type version the claim is issued under. Absent for a claims/v1 claim. */
  ref?: TypeRef
  subject: Json
  kid: string
  created: string
  validFrom: string
  validUntil?: string
  list?: number
  index: number
  /** Its context exists nowhere, so it carries a proof made over something else. */
  unsignable?: boolean
  /** Applied after signing. */
  alter?: (signed: any) => void
  expect: { result: string; reason?: string; schemaValid?: boolean }
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

const staffCard = { holderName: 'Ama Serwaa Mensah', staffNumber: 'GCB-00417', grade: 'senior', issuedOn: '2026-01-12' }

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

  // ---- claims under a type's own context, with a credentialSchema ----
  gcb({
    name: 'gcb-012',
    index: 94_576,
    type: 'StaffIdCard',
    ref: { issuer: 'gcb', name: 'StaffIdCard', version: 1 },
    subject: staffCard,
    expect: { result: 'valid' },
    note: "A claim of one of the issuer's own types, version 1. Version 2 of the type exists; this claim is untouched by it.",
  }),
  gcb({
    name: 'gcb-013',
    index: 94_577,
    type: 'StaffIdCard',
    ref: { issuer: 'gcb', name: 'StaffIdCard', version: 2 },
    subject: { ...staffCard, expiresOn: '2028-01-12' },
    expect: { result: 'valid' },
    note: 'The same type at version 2, with the field version 2 added.',
  }),
  gcb({
    name: 'gcb-014',
    index: 94_578,
    type: 'Attestation',
    ref: { name: 'Attestation', version: 1 },
    subject: {
      subjectName: 'Kofi Boateng Enterprise',
      title: 'Letter of introduction',
      statement: 'Kofi Boateng Enterprise has banked with us since 2017.\nThis letter is given at the customer’s request.',
      reference: 'GCB/INT/2026/0412',
    },
    expect: { result: 'valid' },
    note: 'An Attestation: the core type for a one-off statement.',
  }),
  gcb({
    name: 'gcb-015',
    index: 94_579,
    type: 'BankBalanceLetter',
    ref: { name: 'BankBalanceLetter', version: 1 },
    subject: {
      accountHolderName: 'Ama Serwaa Mensah',
      accountType: 'savings',
      accountNumberLast4: '0042',
      balanceAmount: '48210.75',
      currency: 'GHS',
      balanceAsAt: '2026-05-29',
    },
    expect: { result: 'valid' },
    note: 'A core type with an amount, which is a decimal string and never a number.',
  }),
  gcb({
    name: 'gcb-016',
    index: 94_580,
    type: 'StaffIdCard',
    ref: { issuer: 'gcb', name: 'StaffIdCard', version: 1 },
    subject: { ...staffCard, grade: 'principal' },
    expect: { result: 'valid' },
    note: 'Correctly signed, but grade is not a value its schema allows. The answer is still valid; schemaValid reports the mismatch.',
  }),
  gcb({
    name: 'gcb-017',
    index: 94_581,
    type: 'AllKinds',
    ref: { issuer: 'gcb', name: 'AllKinds', version: 1 },
    subject: {
      text: 'Plain',
      short: '😀😀',
      long: 'one\ntwo',
      amount: '12500.50',
      count: -9007199254740991,
      percent: 100,
      flag: false,
      day: '2024-02-29',
      instant: '2026-05-04T09:00:00.123+01:00',
      email: 'ama.mensah@gcb.com.gh',
      link: 'https://vemphy.com/v/GCB-7K2M-9QXP',
      choice: 'a',
    },
    expect: { result: 'valid' },
    note: 'Every kind of field at once, so both languages canonicalise integers, booleans, dates and instants alike.',
  }),
  {
    name: 'emp-002',
    slug: 'emp',
    type: 'SalaryConfirmation',
    ref: { name: 'SalaryConfirmation', version: 1 },
    subject: {
      employeeName: 'Efua Asante',
      jobTitle: 'Senior Accountant',
      grossMonthlySalary: '14500.00',
      currency: 'GHS',
      payFrequency: 'monthly',
      asAt: '2026-05-20',
    },
    kid: 'key-1',
    created: '2026-05-20T14:30:00Z',
    validFrom: '2026-05-20T14:30:00Z',
    validUntil: '2026-08-20T14:30:00Z',
    index: 58_311,
    expect: { result: 'valid' },
    note: 'A salary confirmation, a core type.',
  },
  {
    name: 'emp-003',
    slug: 'emp',
    type: 'StaffIdCard',
    ref: { issuer: 'gcb', name: 'StaffIdCard', version: 1 },
    subject: staffCard,
    kid: 'key-1',
    created: '2026-05-20T14:30:00Z',
    validFrom: '2026-05-20T14:30:00Z',
    index: 58_312,
    expect: { result: 'unknown', reason: 'malformed' },
    note: "Signed by one issuer against another issuer's type. An issuer may use core types and its own, nothing else.",
  },
  {
    name: 'ug-002',
    slug: 'ug',
    type: 'Transcript',
    ref: { issuer: 'ug', name: 'Transcript', version: 1 },
    subject: { graduateName: 'Kwame Boateng' },
    kid: 'key-1',
    created: '2024-11-18T10:00:00Z',
    validFrom: '2024-11-16T00:00:00Z',
    index: 1_002,
    unsignable: true,
    expect: { result: 'unknown', reason: 'context_unavailable' },
    note: 'Its context is not bundled and is not in vectors/cache. Offline, nothing can be said about the signature.',
  },
]

// ---- types ------------------------------------------------------------------

const published = [...coreTypes.map((t) => ({ ...t, file: undefined as string | undefined })), ...customTypes]
const cacheDocuments: Record<string, unknown> = {}
for (const { ref, schema } of published) {
  const problems = validateSchema(schema)
  if (problems.length > 0) throw new Error(`${ref.name} v${ref.version}: ${problems[0]!.field} ${problems[0]!.message}`)
  const context = contextFromSchema(schema, namespaceOf(ref))
  await assertNoDroppedTerms(schema, context, namespaceOf(ref))
  cacheDocuments[contextUrl(ref)] = context
  cacheDocuments[schemaUrl(ref)] = credentialSchemaDocument(schema, schemaUrl(ref))
}
const schemaFor = (spec: ClaimSpec): ClaimSchema | undefined =>
  published.find((t) => t.ref.name === (spec.ref?.name ?? spec.type) && t.ref.version === (spec.ref?.version ?? 1) && t.ref.issuer === spec.ref?.issuer)?.schema

// What a verifier with vectors/cache would have: the bundled contexts and the custom ones.
const loader = documentLoader({ cache: { get: async (url) => cacheDocuments[url], set: async () => {} } })

async function claim(spec: ClaimSpec): Promise<{ signed: Json; unsigned: Json | undefined }> {
  const code = codeFor(spec.slug.toUpperCase(), spec.name)
  const list = listUrl(spec.slug, spec.list ?? 1)
  const unsigned = {
    '@context': [CREDENTIALS_V2, spec.ref ? contextUrl(spec.ref) : CLAIMS_V1],
    id: `urn:vemphy:claim:${code}`,
    type: ['VerifiableCredential', spec.type],
    issuer: did(spec.slug),
    validFrom: spec.validFrom,
    ...(spec.validUntil && { validUntil: spec.validUntil }),
    ...(spec.ref && { credentialSchema: { id: schemaUrl(spec.ref), type: 'JsonSchema' } }),
    credentialSubject: spec.subject,
    credentialStatus: {
      id: `${list}#${spec.index}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(spec.index),
      statusListCredential: list,
    },
  }
  const signer = await signerFor(spec.slug, spec.kid)
  if (spec.unsignable) {
    const stand = await createProof({ ...unsigned, '@context': [CREDENTIALS_V2, CLAIMS_V1], type: ['VerifiableCredential'], credentialSubject: {} }, signer, { created: spec.created })
    return { signed: { ...unsigned, proof: (stand as Json).proof }, unsigned: undefined }
  }
  const signed = structuredClone(await createProof(unsigned, signer, { created: spec.created }, loader))
  spec.alter?.(signed)
  return { signed, unsigned }
}

// ---- write ----------------------------------------------------------------

for (const dir of ['claims', 'keys', 'status', 'canon', 'cache', 'schemas/valid', 'schemas/invalid', 'schemas/subjects', 'directory']) {
  mkdirSync(root + dir, { recursive: true })
}

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
// Appended after the issuers' own keys so their entries keep their existing order and bytes.
write('keys/apex.did.json', await apexDidDocument())
for (const key of apexKeys) {
  ;(seeds.seeds as Json)[`${APEX_DID}#${key.kid}`] = bytesToHex(seedFor('apex', key.kid))
}
write('keys/test-seeds.json', seeds)

for (const spec of lists) write(`status/${spec.slug}-${spec.n}.json`, await statusList(spec))

const expected: Json = {}
for (const spec of claims) {
  const { signed, unsigned } = await claim(spec)
  write(`claims/${spec.name}.json`, signed)
  if (unsigned) write(`canon/${spec.name}.nq`, await canonicalize(unsigned, loader))
  // schemaValid is reported once the signature holds, whatever the answer turns out to be.
  const signatureHolds = spec.expect.result !== 'unknown' || spec.expect.reason === 'status_list_unverifiable'
  const schema = schemaFor(spec)
  expected[spec.name] = {
    ...spec.expect,
    ...(signatureHolds && schema && { schemaValid: validateSubject(schema, spec.subject).length === 0 }),
    note: spec.note,
  }
}
const directoryExpected: Json = {}
for (const spec of directories) {
  write(`directory/${spec.name}.json`, await directoryCredential(spec))
  directoryExpected[spec.name] = { ...spec.expect, note: spec.note }
}

write('expected.json', { now: NOW, vectors: expected, directories: directoryExpected })

// A verifier's cache, as `vemphy-vc verify --cache vectors/cache` reads it: every published context and
// schema document, in canonical JSON. The Go generators must reproduce these bytes.
for (const [url, document] of Object.entries(cacheDocuments)) write(`cache/${cacheFileName(url)}`, canonicalJson(document))

for (const { file, ref, schema } of customTypes) write(`schemas/valid/${file}.json`, { ref, schema })
for (const [name, entry] of Object.entries(invalidSchemas)) {
  if (validateSchema(entry.schema).length === 0) throw new Error(`invalid schema ${name} was accepted`)
  write(`schemas/invalid/${name}.json`, entry)
}
for (const [name, fixture] of Object.entries(subjectFixtures)) write(`schemas/subjects/${name}.json`, fixture)
write('patterns.json', patterns)

console.log(
  `wrote ${claims.length} claims, ${lists.length} status lists, ${Object.keys(issuers).length + 1} DID documents, ${directories.length} directories`,
)
