// The schemas, subjects and patterns behind vectors/schemas and
// vectors/patterns.json. Both languages must agree on every one of them.
import type { ClaimSchema, TypeRef } from '../src/schema/index.js'

type Json = Record<string, unknown>

const DRAFT = 'https://json-schema.org/draft/2020-12/schema' as const
const TEXT = '^[^\\t\\n\\r ]([^\\t\\n\\r]*[^\\t\\n\\r ])?$'
const MAX = 9007199254740991

const x = (label: string, order: number, extra: Json = {}) => ({
  'x-vemphy': { label: { en: label }, disclosable: true, pii: false, order, ...extra },
})

const staffIdCardV1 = {
  $schema: DRAFT,
  type: 'object',
  additionalProperties: false,
  'x-vemphy': { name: 'StaffIdCard', displayName: { en: 'Staff ID card' } },
  properties: {
    holderName: { type: 'string', minLength: 1, maxLength: 200, pattern: TEXT, ...x('Name', 1, { pii: true }) },
    staffNumber: { type: 'string', maxLength: 12, pattern: '^[A-Z]{1,3}-\\d{3,8}$', ...x('Staff number', 2, { disclosable: false, pii: true }) },
    department: { type: 'string', minLength: 1, maxLength: 100, pattern: TEXT, ...x('Department', 3) },
    grade: {
      type: 'string',
      enum: ['junior', 'senior', 'lead'],
      ...x('Grade', 4, { enumLabels: { junior: { en: 'Junior' }, senior: { en: 'Senior' }, lead: { en: 'Lead' } } }),
    },
    issuedOn: { type: 'string', format: 'date', ...x('Issued on', 5) },
  },
  required: ['holderName', 'staffNumber', 'grade', 'issuedOn'],
} as unknown as ClaimSchema

// Version 2 renames a label and adds a field. Claims issued under version 1 are untouched by it.
const staffIdCardV2 = structuredClone(staffIdCardV1) as ClaimSchema & { properties: Record<string, any> }
staffIdCardV2.properties['holderName']['x-vemphy'].label = { en: 'Card holder', fr: 'Titulaire' }
staffIdCardV2.properties['expiresOn'] = { type: 'string', format: 'date', ...x('Expires on', 6) }

const allKinds = {
  $schema: DRAFT,
  type: 'object',
  additionalProperties: false,
  'x-vemphy': { name: 'AllKinds', displayName: { en: 'Every kind of field', fr: 'Tous les types de champ' } },
  properties: {
    text: { type: 'string', minLength: 1, maxLength: 200, pattern: TEXT, 'x-vemphy': { label: { en: 'Text', fr: 'Texte', 'pt-BR': 'Texto' }, disclosable: true, pii: false, order: 1 } },
    short: { type: 'string', maxLength: 5, ...x('At most five characters', 2) },
    long: { type: 'string', maxLength: 2000, ...x('Long text', 3, { kind: 'multiline' }) },
    amount: { type: 'string', maxLength: 18, pattern: '^(0|[1-9]\\d{0,14})(\\.\\d{2})?$', ...x('Amount', 4, { kind: 'decimal' }) },
    count: { type: 'integer', minimum: -MAX, maximum: MAX, ...x('Count', 5) },
    percent: { type: 'integer', minimum: 0, maximum: 100, ...x('Percent', 6) },
    flag: { type: 'boolean', ...x('Flag', 7) },
    day: { type: 'string', format: 'date', ...x('Day', 8) },
    instant: { type: 'string', format: 'date-time', ...x('Instant', 9) },
    email: { type: 'string', format: 'email', ...x('Email', 10, { pii: true }) },
    link: { type: 'string', format: 'uri', ...x('Link', 11) },
    choice: { type: 'string', enum: ['a', 'b'], ...x('Choice', 12, { enumLabels: { a: { en: 'Option A', fr: 'Choix A' } } }) },
  },
  required: ['text', 'count', 'flag', 'day', 'instant'],
} as unknown as ClaimSchema

export const customTypes: Array<{ file: string; ref: TypeRef; schema: ClaimSchema }> = [
  { file: 'gcb.StaffIdCard.v1', ref: { issuer: 'gcb', name: 'StaffIdCard', version: 1 }, schema: staffIdCardV1 },
  { file: 'gcb.StaffIdCard.v2', ref: { issuer: 'gcb', name: 'StaffIdCard', version: 2 }, schema: staffIdCardV2 },
  { file: 'gcb.AllKinds.v1', ref: { issuer: 'gcb', name: 'AllKinds', version: 1 }, schema: allKinds },
]

// ---- schemas that must be refused -------------------------------------------

type Mutable = { [key: string]: any }
const broken = (rule: string, change: (schema: Mutable) => void) => {
  const schema = structuredClone(staffIdCardV1) as Mutable
  change(schema)
  return { rule, schema }
}
const field = (order: number, extra: Json = {}) => ({ type: 'string', maxLength: 10, ...x('Extra', order), ...extra })

export const invalidSchemas: Record<string, { rule: string; schema: Json }> = {
  'nested-object': broken('a property must be a leaf, not an object', (s) => {
    s.properties.address = { type: 'object', properties: { city: field(7) }, ...x('Address', 6) }
  }),
  array: broken('a property must be a leaf, not an array', (s) => {
    s.properties.tags = { type: 'array', items: { type: 'string' }, ...x('Tags', 6) }
  }),
  ref: broken('$ref is not allowed', (s) => {
    s.properties.other = { $ref: '#/properties/holderName' }
  }),
  'one-of': broken('oneOf, anyOf and allOf are not allowed', (s) => {
    s.properties.either = { oneOf: [{ type: 'string' }, { type: 'integer' }], ...x('Either', 6) }
  }),
  'root-all-of': broken('combinators are not allowed at the root', (s) => {
    s.allOf = [{ required: ['department'] }]
  }),
  'reserved-key': broken('a property may not be a term of the VC 2.0 context', (s) => {
    s.properties.name = field(6)
  }),
  'reserved-key-id': broken('a property may not be a term of the VC 2.0 context', (s) => {
    s.properties.id = field(6)
  }),
  'key-casing': broken('property keys are lowerCamelCase ASCII, 2-40 characters', (s) => {
    s.properties.Holder_name = field(6)
  }),
  'key-too-short': broken('property keys are lowerCamelCase ASCII, 2-40 characters', (s) => {
    s.properties.a = field(6)
  }),
  'too-many-properties': broken('at most 30 properties', (s) => {
    for (let i = 0; i < 26; i++) s.properties[`extra${String.fromCharCode(97 + i)}`] = field(10 + i)
  }),
  'no-properties': broken('at least one property', (s) => {
    s.properties = {}
    s.required = []
  }),
  'missing-label-en': broken('a label needs en', (s) => {
    s.properties.department['x-vemphy'].label = { fr: 'Service' }
  }),
  'missing-extension': broken('every property carries x-vemphy', (s) => {
    delete s.properties.department['x-vemphy']
  }),
  'missing-disclosable': broken('x-vemphy needs label, disclosable, pii and order', (s) => {
    delete s.properties.department['x-vemphy'].disclosable
  }),
  'missing-root-extension': broken('the root carries x-vemphy.name and displayName', (s) => {
    delete s['x-vemphy']
  }),
  'type-name-casing': broken('the type name is PascalCase', (s) => {
    s['x-vemphy'].name = 'staffIdCard'
  }),
  'type-name-reserved': broken('the type name may not be a term of the VC 2.0 context', (s) => {
    s['x-vemphy'].name = 'VerifiableCredential'
  }),
  number: broken('there is no number type; an amount is a decimal string', (s) => {
    s.properties.salary = { type: 'number', ...x('Salary', 6) }
  }),
  'additional-properties': broken('additionalProperties must be false', (s) => {
    s.additionalProperties = true
  }),
  'wrong-draft': broken('$schema must be draft 2020-12', (s) => {
    s.$schema = 'http://json-schema.org/draft-07/schema#'
  }),
  'string-without-max-length': broken('plain text needs maxLength', (s) => {
    delete s.properties.department.maxLength
  }),
  'max-length-too-large': broken('maxLength is at most 2000', (s) => {
    s.properties.department.maxLength = 2001
  }),
  'integer-without-bounds': broken('an integer needs minimum and maximum', (s) => {
    s.properties.level = { type: 'integer', minimum: 0, ...x('Level', 6) }
  }),
  'integer-unsafe-bound': broken('integer bounds stay within ±(2^53 − 1)', (s) => {
    s.properties.level = { type: 'integer', minimum: 0, maximum: 9007199254740992, ...x('Level', 6) }
  }),
  'enum-too-long': broken('an enum has at most 50 values', (s) => {
    s.properties.grade.enum = Array.from({ length: 51 }, (_, i) => `g${i}`)
    delete s.properties.grade['x-vemphy'].enumLabels
  }),
  'enum-of-numbers': broken('enum values are strings', (s) => {
    s.properties.grade.enum = [1, 2, 3]
    delete s.properties.grade['x-vemphy'].enumLabels
  }),
  'unknown-format': broken('format is one of date, date-time, email, uri', (s) => {
    s.properties.issuedOn.format = 'hostname'
  }),
  'extra-keyword': broken('only the listed keywords are allowed on a property', (s) => {
    s.properties.department.default = 'Finance'
  }),
  'kind-on-enum': broken('kind belongs on plain text only', (s) => {
    s.properties.grade['x-vemphy'].kind = 'multiline'
  }),
  'pattern-too-long': broken('a pattern is at most 200 characters', (s) => {
    s.properties.department.pattern = `^${'a'.repeat(200)}$`
  }),
  'pattern-lookahead': broken('a pattern uses only syntax that means the same in RE2 and JavaScript', (s) => {
    s.properties.department.pattern = '^(?=.*[A-Z]).+$'
  }),
  'pattern-whitespace-class': broken('a pattern uses only syntax that means the same in RE2 and JavaScript', (s) => {
    s.properties.department.pattern = '^\\S+$'
  }),
  'required-unknown': broken('every name in required is a property', (s) => {
    s.required.push('manager')
  }),
  'duplicate-order': broken('order is unique within a schema', (s) => {
    s.properties.department['x-vemphy'].order = 1
  }),
  'enum-labels-unknown-value': broken('enumLabels names only enum values', (s) => {
    s.properties.grade['x-vemphy'].enumLabels.principal = { en: 'Principal' }
  }),
  'min-length-above-max': broken('minLength is not greater than maxLength', (s) => {
    s.properties.department.minLength = 101
  }),
  'minimum-above-maximum': broken('minimum is not greater than maximum', (s) => {
    s.properties.level = { type: 'integer', minimum: 10, maximum: 1, ...x('Level', 6) }
  }),
}

// ---- subjects -----------------------------------------------------------------

type Case = { note: string; set?: Json; unset?: string[] }
type Fixture = { schema: string; base: Json; accept: Case[]; reject: Case[] }

const smile = String.fromCodePoint(0x1f600)

export const subjectFixtures: Record<string, Fixture> = {
  'gcb.AllKinds.v1': {
    schema: 'vectors/schemas/valid/gcb.AllKinds.v1.json',
    base: { text: 'Plain', count: 0, flag: false, day: '2026-05-04', instant: '2026-05-04T09:00:00Z' },
    accept: [
      { note: 'the base subject' },
      { note: 'five characters outside the BMP count as five', set: { short: smile.repeat(5) } },
      { note: 'an empty string where no minLength is set', set: { short: '' } },
      { note: 'text with inner spaces', set: { text: 'Two  words' } },
      { note: 'new lines in long text', set: { long: 'one\ntwo' } },
      { note: 'a whole amount', set: { amount: '12500' } },
      { note: 'an amount with pesewas', set: { amount: '12500.50' } },
      { note: 'zero', set: { amount: '0.00' } },
      { note: 'the largest integer', set: { count: MAX } },
      { note: 'the smallest integer', set: { count: -MAX } },
      { note: 'both ends of a range', set: { percent: 100 } },
      { note: '29 February in a leap year', set: { day: '2024-02-29' } },
      { note: '29 February 2000', set: { day: '2000-02-29' } },
      { note: 'an offset', set: { instant: '2026-05-04T09:00:00+01:00' } },
      { note: 'a negative offset and a fraction', set: { instant: '2026-05-04T09:00:00.123456789-05:30' } },
      { note: 'the last second of a day', set: { instant: '2026-12-31T23:59:59Z' } },
      { note: 'an address', set: { email: 'ama.mensah+letters@gcb.com.gh' } },
      { note: 'a link', set: { link: 'https://vemphy.com/v/GCB-7K2M-9QXP?x=1#top' } },
      { note: 'a plain http link', set: { link: 'http://example.com' } },
      { note: 'an enum value', set: { choice: 'b' } },
    ],
    reject: [
      { note: 'a property the schema does not have', set: { other: 'x' } },
      { note: 'a required property missing', unset: ['flag'] },
      { note: 'null', set: { text: null } },
      { note: 'six characters outside the BMP', set: { short: smile.repeat(6) } },
      { note: 'a leading space', set: { text: ' Plain' } },
      { note: 'a trailing space', set: { text: 'Plain ' } },
      { note: 'a new line in single-line text', set: { text: 'one\ntwo' } },
      { note: 'empty text', set: { text: '' } },
      { note: 'an amount as a number', set: { amount: 12500.5 } },
      { note: 'one decimal place', set: { amount: '12500.5' } },
      { note: 'a leading zero', set: { amount: '012.00' } },
      { note: 'a thousands separator', set: { amount: '12,500.00' } },
      { note: 'a negative amount', set: { amount: '-1.00' } },
      { note: 'a fraction where an integer is expected', set: { count: 1.5 } },
      { note: 'an integer as a string', set: { count: '1' } },
      { note: 'past the end of a range', set: { percent: 101 } },
      { note: 'below the start of a range', set: { percent: -1 } },
      { note: 'a boolean as a string', set: { flag: 'true' } },
      { note: 'a boolean as a number', set: { flag: 1 } },
      { note: '29 February in a common year', set: { day: '2023-02-29' } },
      { note: '29 February 1900', set: { day: '1900-02-29' } },
      { note: 'month 13', set: { day: '2026-13-01' } },
      { note: 'day 0', set: { day: '2026-01-00' } },
      { note: '31 April', set: { day: '2026-04-31' } },
      { note: 'a date without zero padding', set: { day: '2026-5-4' } },
      { note: 'year 0000', set: { day: '0000-01-01' } },
      { note: 'a date with a time', set: { day: '2026-05-04T09:00:00Z' } },
      { note: 'a date with a trailing new line', set: { day: '2026-05-04\n' } },
      { note: 'an instant without an offset', set: { instant: '2026-05-04T09:00:00' } },
      { note: 'a lowercase t', set: { instant: '2026-05-04t09:00:00Z' } },
      { note: 'a lowercase z', set: { instant: '2026-05-04T09:00:00z' } },
      { note: 'a space for the T', set: { instant: '2026-05-04 09:00:00Z' } },
      { note: 'hour 24', set: { instant: '2026-05-04T24:00:00Z' } },
      { note: 'a leap second', set: { instant: '2026-06-30T23:59:60Z' } },
      { note: 'ten fraction digits', set: { instant: '2026-05-04T09:00:00.1234567890Z' } },
      { note: 'an offset of 24 hours', set: { instant: '2026-05-04T09:00:00+24:00' } },
      { note: 'an offset without a colon', set: { instant: '2026-05-04T09:00:00+0100' } },
      { note: 'no seconds', set: { instant: '2026-05-04T09:00Z' } },
      { note: 'an impossible date in an instant', set: { instant: '2026-02-30T09:00:00Z' } },
      { note: 'an address with no domain dot', set: { email: 'ama@localhost' } },
      { note: 'an address with two dots together', set: { email: 'ama..mensah@gcb.com.gh' } },
      { note: 'an address starting with a dot', set: { email: '.ama@gcb.com.gh' } },
      { note: 'an address with a space', set: { email: 'ama mensah@gcb.com.gh' } },
      { note: 'an address with no local part', set: { email: '@gcb.com.gh' } },
      { note: 'a domain label ending in a hyphen', set: { email: 'ama@gcb-.com' } },
      { note: 'an address outside ASCII', set: { email: 'amá@gcb.com.gh' } },
      { note: 'a local part of 65 characters', set: { email: `${'a'.repeat(65)}@gcb.com.gh` } },
      { note: 'an ftp link', set: { link: 'ftp://example.com/file' } },
      { note: 'a link with a space', set: { link: 'https://example.com/a b' } },
      { note: 'a link with no host', set: { link: 'https://' } },
      { note: 'a relative link', set: { link: '/v/GCB-7K2M-9QXP' } },
      { note: 'a link outside ASCII', set: { link: 'https://example.com/é' } },
      { note: 'a value outside the enum', set: { choice: 'c' } },
      { note: 'an enum value in another case', set: { choice: 'A' } },
    ],
  },
  'gcb.StaffIdCard.v1': {
    schema: 'vectors/schemas/valid/gcb.StaffIdCard.v1.json',
    base: { holderName: 'Ama Serwaa Mensah', staffNumber: 'GCB-00417', grade: 'senior', issuedOn: '2026-01-12' },
    accept: [{ note: 'the base subject' }, { note: 'with the optional department', set: { department: 'Treasury' } }],
    reject: [
      { note: 'a field that only version 2 has', set: { expiresOn: '2028-01-12' } },
      { note: 'a staff number in the wrong form', set: { staffNumber: 'gcb-417' } },
      { note: 'a staff number with text after it', set: { staffNumber: 'GCB-00417x' } },
    ],
  },
  'gcb.StaffIdCard.v2': {
    schema: 'vectors/schemas/valid/gcb.StaffIdCard.v2.json',
    base: { holderName: 'Ama Serwaa Mensah', staffNumber: 'GCB-00417', grade: 'senior', issuedOn: '2026-01-12' },
    accept: [{ note: 'the base subject' }, { note: 'with the field version 2 added', set: { expiresOn: '2028-01-12' } }],
    reject: [{ note: 'an impossible expiry date', set: { expiresOn: '2028-02-30' } }],
  },
  'core.BankBalanceLetter.v1': {
    schema: 'packages/vc/schemas/core/BankBalanceLetter.v1.json',
    base: {
      accountHolderName: 'Ama Serwaa Mensah',
      accountType: 'savings',
      accountNumberLast4: '0042',
      balanceAmount: '48210.75',
      currency: 'GHS',
      balanceAsAt: '2026-05-29',
    },
    accept: [{ note: 'the base subject' }, { note: 'with branch and addressee', set: { branch: 'Accra High Street', addressedTo: 'The Consular Section' } }],
    reject: [
      { note: 'a currency outside the list', set: { currency: 'NGN' } },
      { note: 'five digits of account number', set: { accountNumberLast4: '00421' } },
      { note: 'a balance as a number', set: { balanceAmount: 48210.75 } },
    ],
  },
  'core.Attestation.v1': {
    schema: 'packages/vc/schemas/core/Attestation.v1.json',
    base: { subjectName: 'Kofi Annan Memorial School', title: 'Letter of good standing', statement: 'The school is registered with the district.\nIts registration is current.' },
    accept: [{ note: 'the base subject' }, { note: 'with a reference', set: { reference: 'GES/AC/2026/118' } }],
    reject: [
      { note: 'a statement of 2001 characters', set: { statement: 'a'.repeat(2001) } },
      { note: 'a reference of 101 characters', set: { reference: 'a'.repeat(101) } },
      { note: 'a tab in the statement', set: { statement: 'one\ttwo' } },
    ],
  },
}

// ---- patterns -------------------------------------------------------------------

export const patterns = {
  allowed: [
    '^[A-Z]{1,3}-\\d{3,8}$',
    TEXT,
    '^(0|[1-9]\\d{0,14})(\\.\\d{2})?$',
    '^(?:GH|NG)-[0-9]+$',
    '^[^\\t\\n\\r]*$',
    'a|b|',
    '^\\[\\d+\\]\\{x\\}\\(y\\)\\.\\*\\+\\?\\|\\^\\$\\/\\\\$',
    '^[a-z\\-\\]\\[\\^]+$',
    '^é{2,}$',
    'x{1000}',
  ],
  refused: [
    '',
    '^(?=a)b$',
    '^(?!a)b$',
    '^(?<=a)b$',
    '^(?<name>a)$',
    '^(a)\\1$',
    '^\\s+$',
    '^\\S+$',
    '^\\w+$',
    '^\\bword\\b$',
    '^\\D$',
    '^.+$',
    '^\\p{L}+$',
    '^[[:alpha:]]+$',
    '^\\x41$',
    '^\\u0041$',
    '(?i)abc',
    'a+?',
    'a*+',
    'a**',
    '^*a',
    '|*',
    '(*a)',
    'a{,3}',
    'a{3,2}',
    'a{1001}',
    'a{2',
    'a}',
    'a]',
    '[]a]',
    '[a',
    '[z-a]',
    '[a-\\d]',
    '[a-]',
    '[a^]',
    '[a[b]',
    '(a',
    'a)',
    'a\\-b',
    'a\\',
    'a'.repeat(201),
  ],
}
