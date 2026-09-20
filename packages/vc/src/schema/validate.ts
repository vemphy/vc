import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js'
import { RE2JS } from 're2js'
import envelope from '../../schemas/envelope/envelope.json' with { type: 'json' }
import metaSchema from '../../schemas/meta/vemphy-claim-schema.json' with { type: 'json' }
import { formats } from './formats.js'
import { patternProblem } from './pattern.js'
import type { ClaimSchema, Problem } from './types.js'

// Patterns run on RE2, the engine Go uses, so both languages give the same
// answer and a pattern from a schema fetched a moment ago cannot stall the
// process: RE2 has no backtracking.
const regExp = Object.assign(
  (pattern: string) => {
    const re = RE2JS.compile(pattern)
    // Ajv tells compiled patterns apart by toString(). Without it every pattern would be the first one.
    return { test: (value: string) => re.matcher(value).find(), toString: () => `re2:${pattern}` }
  },
  { code: 'vemphy.re2' },
)

function newAjv(): InstanceType<typeof Ajv2020> {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    // The meta-schema requires `en` among labels whose keys are open-ended.
    strictRequired: false,
    validateFormats: true,
    formats,
    code: { regExp: regExp as never },
  })
  ajv.addVocabulary(['x-vemphy'])
  return ajv
}

const shared = newAjv()
const meta = shared.compile(metaSchema)
shared.addSchema(envelope)

/** A validator for one of the definitions in schemas/envelope/envelope.json. */
export function envelopeValidator(definition: string): ValidateFunction {
  const validate = shared.getSchema(`${envelope.$id}#/$defs/${definition}`)
  if (!validate) throw new Error(`no envelope definition ${definition}`)
  return validate
}

const checked = new WeakMap<object, Problem[]>()
const compiled = new WeakMap<object, ValidateFunction>()

/**
 * Checks that a document is a legitimate Vemphy claim schema: the meta-schema,
 * then the rules JSON Schema cannot express. Returns every problem found; an
 * empty list means the schema may be published.
 */
export function validateSchema(schema: unknown): Problem[] {
  if (typeof schema !== 'object' || schema === null) return [{ field: '', message: 'must be an object' }]
  let problems = checked.get(schema)
  if (!problems) {
    problems = meta(schema) ? beyondMetaSchema(schema as ClaimSchema) : toProblems(meta.errors)
    checked.set(schema, problems)
  }
  return problems
}

function beyondMetaSchema(schema: ClaimSchema): Problem[] {
  const problems: Problem[] = []
  const at = (key: string, message: string) => void problems.push({ field: `properties.${key}`, message })

  for (const name of schema.required ?? []) {
    if (!Object.hasOwn(schema.properties, name)) problems.push({ field: 'required', message: `${name} is not a property` })
  }

  const orders = new Map<number, string>()
  for (const [key, field] of Object.entries(schema.properties)) {
    const x = field['x-vemphy']
    const other = orders.get(x.order)
    if (other !== undefined) at(key, `has the same order as ${other}`)
    orders.set(x.order, key)

    if ('pattern' in field && field.pattern !== undefined) {
      const problem = patternProblem(field.pattern)
      if (problem) at(key, `pattern: ${problem}`)
    }
    if ('maxLength' in field && field.minLength !== undefined && field.minLength > field.maxLength) {
      at(key, 'minLength is greater than maxLength')
    }
    if ('minimum' in field && field.minimum > field.maximum) at(key, 'minimum is greater than maximum')
    if ('enum' in field) {
      for (const value of Object.keys(x.enumLabels ?? {})) {
        if (!field.enum.includes(value)) at(key, `enumLabels names ${value}, which is not in enum`)
      }
    }
  }
  return problems
}

/**
 * Validates a claim's subject against a claim schema. The schema is checked
 * with `validateSchema` first, so nothing outside the restricted subset is
 * ever compiled. Throws if the schema is not legitimate.
 */
export function validateSubject(schema: ClaimSchema, subject: unknown): Problem[] {
  let validate = compiled.get(schema)
  if (!validate) {
    const problems = validateSchema(schema)
    if (problems.length > 0) throw new Error(`not a Vemphy claim schema: ${problems[0]!.field} ${problems[0]!.message}`)
    // Its own instance: Ajv keeps every schema it compiles, and these are not ours to keep.
    validate = newAjv().compile(schema)
    compiled.set(schema, validate)
  }
  return validate(subject) ? [] : toProblems(validate.errors)
}

function toProblems(errors: ErrorObject[] | null | undefined): Problem[] {
  return (errors ?? []).map((e) => {
    const extra = e.keyword === 'additionalProperties' ? ` (${String(e.params['additionalProperty'])})` : ''
    const missing = e.keyword === 'required' ? String(e.params['missingProperty']) : ''
    const path = e.instancePath.slice(1).replaceAll('/', '.')
    return { field: missing ? [path, missing].filter(Boolean).join('.') : path, message: `${e.message ?? 'is not valid'}${extra}` }
  })
}
