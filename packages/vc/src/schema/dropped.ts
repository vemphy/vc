import jsonld from 'jsonld'
import { CREDENTIALS_V2 } from '../context/urls.js'
import { staticLoader } from '../context/loader.js'
import type { ClaimSchema, Field } from './types.js'

const SAMPLE_CONTEXT = 'https://vemphy.com/ns/sample'

function sample(field: Field): unknown {
  if (field.type === 'integer') return field.minimum
  if (field.type === 'boolean') return true
  if ('enum' in field) return field.enum[0]
  if ('format' in field) {
    return { date: '2026-01-01', 'date-time': '2026-01-01T00:00:00Z', email: 'a@example.com', uri: 'https://example.com/' }[field.format]
  }
  return 'x'
}

/**
 * Builds a claim with every property of the schema present, expands it under
 * the context, and throws unless the type and every property come out the
 * other side under `namespace`. A term that expansion drops is a field that
 * would be issued unsigned.
 */
export async function assertNoDroppedTerms(schema: ClaimSchema, context: unknown, namespace: string): Promise<void> {
  const name = schema['x-vemphy'].name
  const subject = Object.fromEntries(Object.entries(schema.properties).map(([key, field]) => [key, sample(field)]))
  const claim = {
    '@context': [CREDENTIALS_V2, SAMPLE_CONTEXT],
    type: ['VerifiableCredential', name],
    credentialSubject: subject,
  }
  const expanded = (await jsonld.expand(claim, {
    documentLoader: staticLoader({ [SAMPLE_CONTEXT]: context }) as never,
  })) as Array<Record<string, unknown>>

  const node = expanded[0] ?? {}
  const types = (node['@type'] ?? []) as string[]
  if (!types.includes(`${namespace}${name}`)) throw new Error(`the context drops the type ${name}`)

  const subjects = (node['https://www.w3.org/2018/credentials#credentialSubject'] ?? []) as Array<Record<string, unknown>>
  const out = subjects[0] ?? {}
  for (const key of Object.keys(subject)) {
    if (!Object.hasOwn(out, `${namespace}${key}`)) throw new Error(`the context drops ${key}`)
  }
}
