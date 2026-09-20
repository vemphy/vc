import type { ClaimSchema, Field, Kind, Labels } from './types.js'

/**
 * Picks the language to show. `wanted` is a list of language tags, most
 * preferred first (the order of an Accept-Language header). An exact match
 * wins, then a match on the primary language (`fr-CA` → `fr`), then `en`.
 */
export function pickLabel(labels: Labels, wanted: readonly string[] = []): string {
  const keys = Object.keys(labels)
  for (const tag of wanted) {
    const lower = tag.toLowerCase()
    const exact = keys.find((k) => k.toLowerCase() === lower)
    if (exact) return labels[exact]!
    const primary = lower.split('-')[0]!
    const loose = keys.find((k) => k.toLowerCase() === primary)
    if (loose) return labels[loose]!
  }
  return labels.en
}

/** The label of a field, or undefined if the schema has no such field. */
export function labelFor(schema: ClaimSchema, key: string, lang?: string | readonly string[]): string | undefined {
  if (!Object.hasOwn(schema.properties, key)) return undefined
  return pickLabel(schema.properties[key]!['x-vemphy'].label, toList(lang))
}

/** The label of an enum value, falling back to the value itself. */
export function valueLabelFor(schema: ClaimSchema, key: string, value: string, lang?: string | readonly string[]): string {
  const labels = Object.hasOwn(schema.properties, key) ? schema.properties[key]!['x-vemphy'].enumLabels : undefined
  return labels && Object.hasOwn(labels, value) ? pickLabel(labels[value]!, toList(lang)) : value
}

export function displayNameFor(schema: ClaimSchema, lang?: string | readonly string[]): string {
  return pickLabel(schema['x-vemphy'].displayName, toList(lang))
}

export function kindOf(field: Field): Kind {
  if (field.type === 'integer' || field.type === 'boolean') return field.type
  if ('enum' in field) return 'choice'
  if ('format' in field) return field.format === 'date-time' ? 'datetime' : field.format
  return field['x-vemphy'].kind ?? 'text'
}

/** Field keys in the order the schema gives them. */
export function orderedKeys(schema: ClaimSchema): string[] {
  return Object.keys(schema.properties).sort(
    (a, b) => schema.properties[a]!['x-vemphy'].order - schema.properties[b]!['x-vemphy'].order,
  )
}

function toList(lang: string | readonly string[] | undefined): readonly string[] {
  return lang === undefined ? [] : typeof lang === 'string' ? [lang] : lang
}
