import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import {
  CLAIM_TYPES,
  credentialSchema,
  defaultDisclosure,
  jsonSchemaFor,
  subjectSchemas,
  unsignedCredentialSchemaFor,
} from './index.js'

const minimal = () =>
  JSON.parse(readFileSync(new URL('../../../../vectors/canon/minimal.json', import.meta.url), 'utf8')) as Record<
    string,
    any
  >

const proof = {
  type: 'DataIntegrityProof',
  cryptosuite: 'eddsa-rdfc-2022',
  created: '2026-01-10T09:00:00Z',
  verificationMethod: 'did:web:vemphy.com:i:gcb#key-1',
  proofPurpose: 'assertionMethod',
  proofValue: 'z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhSePTFehP8c3PGfb6a22gkfUKods5D2UAUL5n2Brbx',
}

const degree = {
  graduateName: 'Kwame Boateng',
  studentNumber: '10456789',
  qualification: 'BSc',
  programme: 'Computer Science',
  classification: 'First Class Honours',
  conferredOn: '2024-11-16',
}

const employment = {
  employeeName: 'Efua Asante',
  jobTitle: 'Senior Accountant',
  employmentType: 'permanent',
  startDate: '2021-02-01',
  currentlyEmployed: true,
}

describe('subject schemas', () => {
  it('accepts a well-formed subject of each type', () => {
    expect(subjectSchemas.BankReferenceLetter.safeParse(minimal().credentialSubject).success).toBe(true)
    expect(subjectSchemas.DegreeCertificate.safeParse(degree).success).toBe(true)
    expect(subjectSchemas.EmploymentLetter.safeParse(employment).success).toBe(true)
  })

  it('returns the input unchanged', () => {
    const subject = minimal().credentialSubject
    expect(subjectSchemas.BankReferenceLetter.parse(subject)).toEqual(subject)
  })

  it.each([
    ['an unknown field', { balance: '1000' }],
    ['a value outside the enum', { accountType: 'offshore' }],
    ['a date that does not exist', { referenceDate: '2026-02-30' }],
    ['a date with a time', { referenceDate: '2026-01-10T00:00:00Z' }],
    ['more than four digits', { accountNumberLast4: '00421' }],
    ['padded text', { branch: ' Accra ' }],
    ['empty text', { branch: '' }],
  ])('rejects a bank reference with %s', (_, patch) => {
    const subject = { ...minimal().credentialSubject, ...patch }
    expect(subjectSchemas.BankReferenceLetter.safeParse(subject).success).toBe(false)
  })

  it('rejects a degree without a required field or with an extra one', () => {
    const { conferredOn: _, ...missing } = degree
    expect(subjectSchemas.DegreeCertificate.safeParse(missing).success).toBe(false)
    expect(subjectSchemas.DegreeCertificate.safeParse({ ...degree, gpa: '3.9' }).success).toBe(false)
    expect(subjectSchemas.DegreeCertificate.safeParse({ ...degree, conferredOn: '16/11/2024' }).success).toBe(false)
  })

  it('applies the employment date rules', () => {
    const parse = (patch: object) => subjectSchemas.EmploymentLetter.safeParse({ ...employment, ...patch }).success
    expect(parse({ currentlyEmployed: false, endDate: '2025-06-30' })).toBe(true)
    expect(parse({ endDate: '2025-06-30' })).toBe(false)
    expect(parse({ currentlyEmployed: false, endDate: '2020-01-01' })).toBe(false)
    expect(parse({ employmentType: 'volunteer' })).toBe(false)
    expect(parse({ currentlyEmployed: 'yes' })).toBe(false)
  })
})

describe('credential schema', () => {
  const signed = (): Record<string, any> => ({ ...minimal(), proof })

  it('accepts a signed claim and an unsigned one', () => {
    expect(credentialSchema.safeParse(signed()).success).toBe(true)
    expect(unsignedCredentialSchemaFor('BankReferenceLetter').safeParse(minimal()).success).toBe(true)
  })

  it('accepts a claim with no validUntil', () => {
    const { validUntil: _, ...open } = signed()
    expect(credentialSchema.safeParse(open).success).toBe(true)
  })

  it.each([
    ['an extra context', (c: any) => c['@context'].push('https://example.com/ctx')],
    ['contexts in the wrong order', (c: any) => c['@context'].reverse()],
    ['an extra type', (c: any) => c.type.push('Other')],
    ['a subject of another type', (c: any) => (c.credentialSubject = degree)],
    ['an issuer outside vemphy.com', (c: any) => (c.issuer = 'did:web:example.com:i:gcb')],
    ['an uppercase slug in the DID', (c: any) => (c.issuer = 'did:web:vemphy.com:i:GCB')],
    ['a code from another issuer', (c: any) => (c.id = 'urn:vemphy:claim:UG-7K2M-9QXD')],
    ['a key from another issuer', (c: any) => (c.proof.verificationMethod = 'did:web:vemphy.com:i:ug#key-1')],
    ['a status list from another issuer', (c: any) => {
      c.credentialStatus.statusListCredential = 'https://vemphy.com/i/ug/status/1'
      c.credentialStatus.id = 'https://vemphy.com/i/ug/status/1#94567'
    }],
    ['a status id that disagrees with its index', (c: any) => (c.credentialStatus.statusListIndex = '5')],
    ['an index past the end of the list', (c: any) => {
      c.credentialStatus.statusListIndex = '131072'
      c.credentialStatus.id = 'https://vemphy.com/i/gcb/status/1#131072'
    }],
    ['validUntil before validFrom', (c: any) => (c.validUntil = '2025-01-01T00:00:00Z')],
    ['another cryptosuite', (c: any) => (c.proof.cryptosuite = 'eddsa-jcs-2022')],
    ['another proof purpose', (c: any) => (c.proof.proofPurpose = 'authentication')],
    ['two proofs', (c: any) => (c.proof = [proof, proof])],
    ['an unknown top-level member', (c: any) => (c.evidence = [])],
  ])('rejects %s', (_, mutate) => {
    const claim = structuredClone(signed())
    mutate(claim)
    expect(credentialSchema.safeParse(claim).success).toBe(false)
  })
})

describe('disclosure and JSON Schema', () => {
  it.each(CLAIM_TYPES)('%s discloses only fields it defines', (type) => {
    const fields = Object.keys(subjectSchemas[type].shape)
    expect(defaultDisclosure[type].length).toBeGreaterThan(0)
    for (const field of defaultDisclosure[type]) expect(fields).toContain(field)
  })

  it.each(CLAIM_TYPES)('%s exports a closed JSON Schema', (type) => {
    const schema = jsonSchemaFor(type)
    expect(schema.type).toBe('object')
    expect(schema.additionalProperties).toBe(false)
    expect(Object.keys(schema.properties as object).sort()).toEqual(Object.keys(subjectSchemas[type].shape).sort())
  })

  it('every subject field is a term in the claims context', () => {
    const context = JSON.parse(readFileSync(new URL('../context/claims-v1.json', import.meta.url), 'utf8'))['@context']
    for (const type of CLAIM_TYPES) {
      expect(context, type).toHaveProperty(type)
      for (const field of Object.keys(subjectSchemas[type].shape)) expect(context, field).toHaveProperty(field)
    }
  })
})
