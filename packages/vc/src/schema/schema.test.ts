import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { cacheFileName } from '../../cli/cache.js'
import credentialsV2 from '../context/credentials-v2.json' with { type: 'json' }
import metaSchema from '../../schemas/meta/vemphy-claim-schema.json' with { type: 'json' }
import {
  assertNoDroppedTerms,
  canonicalJson,
  type ClaimSchema,
  contextFromSchema,
  contextUrl,
  coreTypes,
  credentialSchemaDocument,
  displayNameFor,
  kindOf,
  labelFor,
  namespaceOf,
  orderedKeys,
  parseContextUrl,
  parseSchemaUrl,
  patternProblem,
  schemaUrl,
  subjectSchemaFrom,
  type TypeRef,
  validateSchema,
  validateSubject,
  valueLabelFor,
} from './index.js'

const root = new URL('../../../../vectors/', import.meta.url)
const repo = new URL('../../../../', import.meta.url)
const read = (path: string, base = root) => JSON.parse(readFileSync(new URL(path, base), 'utf8'))
const names = (dir: string) => readdirSync(new URL(dir, root)).map((f) => f.replace(/\.json$/, ''))

const custom = names('schemas/valid/').map((name) => read(`schemas/valid/${name}.json`) as { ref: TypeRef; schema: ClaimSchema })
const published = [...coreTypes, ...custom]

describe('the meta-schema', () => {
  it('reserves exactly the terms of the VC 2.0 context', () => {
    const terms = Object.keys(credentialsV2['@context']).filter((k) => !k.startsWith('@')).sort()
    expect(metaSchema.$defs.reserved.enum).toEqual(terms)
  })

  it.each(published.map((t) => [`${t.ref.issuer ?? 'core'} ${t.ref.name} v${t.ref.version}`, t.schema] as const))('accepts %s', (_, schema) => {
    expect(validateSchema(schema)).toEqual([])
  })

  it.each(names('schemas/invalid/'))('refuses %s', (name) => {
    const { rule, schema } = read(`schemas/invalid/${name}.json`)
    expect(validateSchema(schema).length, rule).toBeGreaterThan(0)
  })

  it.each([null, 42, 'text', []])('refuses %j', (input) => {
    expect(validateSchema(input).length).toBeGreaterThan(0)
  })
})

describe('patterns', () => {
  const { allowed, refused } = read('patterns.json') as { allowed: string[]; refused: string[] }
  it.each(allowed)('allows %s', (pattern) => expect(patternProblem(pattern)).toBeUndefined())
  it.each(refused)('refuses %s', (pattern) => expect(patternProblem(pattern)).toBeTypeOf('string'))
})

describe('subjects', () => {
  for (const name of names('schemas/subjects/')) {
    const fixture = read(`schemas/subjects/${name}.json`)
    const loaded = read(fixture.schema, repo)
    const schema: ClaimSchema = loaded.schema ?? loaded
    type Case = { note: string; set?: object; unset?: string[] }
    const build = (c: Case) => {
      const subject = { ...fixture.base, ...c.set }
      for (const key of c.unset ?? []) delete subject[key]
      return subject
    }
    it.each(fixture.accept as Case[])(`${name} accepts $note`, (c) => expect(validateSubject(schema, build(c))).toEqual([]))
    it.each(fixture.reject as Case[])(`${name} rejects $note`, (c) =>
      expect(validateSubject(schema, build(c)).length).toBeGreaterThan(0),
    )
  }

  it('names every failing field', () => {
    const schema = custom.find((t) => t.ref.name === 'StaffIdCard' && t.ref.version === 1)!.schema
    const problems = validateSubject(schema, { holderName: ' Ama', grade: 'principal', issuedOn: '2026-02-30', extra: 1 })
    expect(problems.map((p) => p.field).sort()).toEqual(['', 'grade', 'holderName', 'issuedOn', 'staffNumber'])
  })

  it('will not compile a schema that breaks the rules', () => {
    const { schema } = read('schemas/invalid/pattern-lookahead.json')
    expect(() => validateSubject(schema, {})).toThrow(/not a Vemphy claim schema/)
  })
})

describe('contexts', () => {
  it.each(published.map((t) => [contextUrl(t.ref), t] as const))('%s matches vectors/cache and drops nothing', async (url, { ref, schema }) => {
    const context = contextFromSchema(schema, namespaceOf(ref))
    expect(canonicalJson(context)).toBe(readFileSync(new URL(`cache/${cacheFileName(url)}`, root), 'utf8'))
    await assertNoDroppedTerms(schema, context, namespaceOf(ref))
  })

  it('notices a context that leaves a property out', async () => {
    const { ref, schema } = custom[0]!
    const context = contextFromSchema(schema, namespaceOf(ref))
    const last = Object.keys(schema.properties).at(-1)!
    delete context['@context'][last]
    await expect(assertNoDroppedTerms(schema, context, namespaceOf(ref))).rejects.toThrow(`drops ${last}`)
  })

  it('notices a context that maps a property somewhere else', async () => {
    const { ref, schema } = custom[0]!
    const context = contextFromSchema(schema, 'https://example.com/other#')
    await expect(assertNoDroppedTerms(schema, context, namespaceOf(ref))).rejects.toThrow(/drops/)
  })

  it('reads a type back out of its URLs', () => {
    const ref = { issuer: 'gcb', name: 'StaffIdCard', version: 2 }
    expect(parseContextUrl(contextUrl(ref))).toEqual(ref)
    expect(parseSchemaUrl(schemaUrl(ref))).toEqual(ref)
    expect(parseContextUrl('https://vemphy.com/ns/core/Attestation/v1')).toEqual({ name: 'Attestation', version: 1 })
    for (const url of ['https://vemphy.com/ns/claims/v1', 'https://vemphy.com/ns/core/attestation/v1', 'https://vemphy.com/ns/i/GCB/X1/v1', 'https://vemphy.com/ns/core/Attestation/v0']) {
      expect(parseContextUrl(url)).toBeUndefined()
    }
  })
})

describe('schema documents', () => {
  it.each(published.map((t) => [schemaUrl(t.ref), t] as const))('%s matches vectors/cache and unwraps to the schema', (url, { schema }) => {
    const document = credentialSchemaDocument(schema, url)
    expect(canonicalJson(document)).toBe(readFileSync(new URL(`cache/${cacheFileName(url)}`, root), 'utf8'))
    expect(subjectSchemaFrom(document)).toEqual(schema)
  })

  it.each([null, {}, { properties: {} }, { properties: { credentialSubject: 'x' } }])('finds no schema in %j', (document) => {
    expect(subjectSchemaFrom(document)).toBeUndefined()
  })
})

describe('labels', () => {
  const v2 = custom.find((t) => t.ref.name === 'StaffIdCard' && t.ref.version === 2)!.schema
  const all = custom.find((t) => t.ref.name === 'AllKinds')!.schema

  it('picks the best language on offer and falls back to en', () => {
    expect(labelFor(v2, 'holderName')).toBe('Card holder')
    expect(labelFor(v2, 'holderName', 'fr-CA')).toBe('Titulaire')
    expect(labelFor(v2, 'holderName', ['de', 'fr'])).toBe('Titulaire')
    expect(labelFor(v2, 'holderName', 'de')).toBe('Card holder')
    expect(labelFor(all, 'text', 'pt-br')).toBe('Texto')
    expect(labelFor(all, 'text', 'pt')).toBe('Text')
    expect(labelFor(v2, 'nothing')).toBeUndefined()
    expect(labelFor(v2, 'toString')).toBeUndefined()
    expect(displayNameFor(all, 'fr')).toBe('Tous les types de champ')
  })

  it('labels enum values, falling back to the value', () => {
    expect(valueLabelFor(all, 'choice', 'a', 'fr')).toBe('Choix A')
    expect(valueLabelFor(all, 'choice', 'b')).toBe('b')
  })

  it('orders fields and names their kind', () => {
    expect(orderedKeys(all).map((k) => kindOf(all.properties[k]!))).toEqual([
      'text', 'text', 'multiline', 'decimal', 'integer', 'integer', 'boolean', 'date', 'datetime', 'email', 'uri', 'choice',
    ])
  })
})
