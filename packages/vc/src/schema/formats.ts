// JSON Schema leaves `format` loosely defined, and validator libraries differ.
// Vemphy defines its four formats here. vc-go/schema/formats.go is the same
// code in Go, and vectors/schemas/subjects holds the cases both must agree on.

const DATE = /^(\d{4})-(\d{2})-(\d{2})$/
const DATE_TIME = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-](\d{2}):(\d{2}))$/
const EMAIL_LOCAL = /^[A-Za-z0-9._%+-]{1,64}$/
const EMAIL_LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/
const URI = /^https?:\/\/[!-~]+$/

const DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

/** `YYYY-MM-DD`, a real calendar date, year 0001-9999. */
export function isDate(value: string): boolean {
  const m = DATE.exec(value)
  if (!m) return false
  const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])]
  if (year < 1 || month < 1 || month > 12 || day < 1) return false
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  return day <= (month === 2 && leap ? 29 : DAYS[month - 1]!)
}

/** `YYYY-MM-DDThh:mm:ss`, optional fraction of 1-9 digits, then `Z` or `±hh:mm`. No leap seconds. */
export function isDateTime(value: string): boolean {
  const m = DATE_TIME.exec(value)
  if (!m || !isDate(m[1]!)) return false
  if (Number(m[2]) > 23 || Number(m[3]) > 59 || Number(m[4]) > 59) return false
  return m[6] === 'Z' || (Number(m[7]) <= 23 && Number(m[8]) <= 59)
}

/** A conservative ASCII address: `local@domain`, at most 254 characters, a domain of two or more labels. */
export function isEmail(value: string): boolean {
  if (value.length > 254) return false
  const at = value.lastIndexOf('@')
  if (at < 1) return false
  const local = value.slice(0, at)
  if (!EMAIL_LOCAL.test(local) || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false
  const labels = value.slice(at + 1).split('.')
  return labels.length >= 2 && labels.every((label) => EMAIL_LABEL.test(label))
}

/** An `http` or `https` link in printable ASCII, at most 2000 characters. */
export function isUri(value: string): boolean {
  return value.length <= 2000 && URI.test(value)
}

export const formats = { date: isDate, 'date-time': isDateTime, email: isEmail, uri: isUri } as const
export type Format = keyof typeof formats
