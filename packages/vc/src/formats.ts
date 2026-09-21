// The four format checks, on their own, for a caller under a Content Security
// Policy with no `unsafe-eval`: `./schema` re-exports the same names but also
// exports `validateSchema`/`validateSubject`, which pull in Ajv, and Ajv
// compiles code at runtime. A bundler follows the whole module graph of
// whatever it imports from a module, so importing `isDate` from `./schema`
// would drag Ajv along even though nothing here needs it. This entry point's
// only job is to keep that graph clean.
export { formats, isDate, isDateTime, isEmail, isUri } from './schema/formats.js'
