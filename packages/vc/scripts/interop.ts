// The TypeScript half of the interop check. Same commands as vc-go/cmd/vcinterop.
//
//   tsx scripts/interop.ts canon                                     < doc.json
//   tsx scripts/interop.ts sign --seed <hex> --vm <id> --created <iso> < unsigned.json
//   tsx scripts/interop.ts verify --key <publicKeyMultibase>         < signed.json
//   tsx scripts/interop.ts pubkey --seed <hex>
//   tsx scripts/interop.ts context --namespace <iri>                 < schema.json
//
// --cache <dir> names a directory of contexts for issuers' own types. Nothing is ever fetched.
import { readFileSync } from 'node:fs'
import { parseArgs } from 'node:util'
import { hexToBytes } from '@noble/hashes/utils.js'
import { dirCache } from '../cli/cache.js'
import { canonicalize } from '../src/canon.js'
import { documentLoader } from '../src/context/loader.js'
import { decodeMultikey, encodeMultikey } from '../src/multibase.js'
import { createProof, memorySigner, verifyProof } from '../src/proof.js'
import { assertNoDroppedTerms, canonicalJson, type ClaimSchema, contextFromSchema, validateSchema } from '../src/schema/index.js'

const [command, ...rest] = process.argv.slice(2)
const { values } = parseArgs({
  args: rest,
  options: {
    seed: { type: 'string' },
    vm: { type: 'string' },
    created: { type: 'string' },
    key: { type: 'string' },
    cache: { type: 'string' },
    namespace: { type: 'string' },
  },
})
const need = (name: keyof typeof values) => {
  const value = values[name]
  if (!value) {
    console.error(`--${name} is required`)
    process.exit(2)
  }
  return value
}
const stdin = () => JSON.parse(readFileSync(0, 'utf8'))
const loader = values.cache ? documentLoader({ cache: dirCache(values.cache) }) : undefined

switch (command) {
  case 'canon':
    process.stdout.write(await canonicalize(stdin(), loader))
    break
  case 'pubkey':
    console.log(encodeMultikey((await memorySigner(hexToBytes(need('seed')), 'unused')).publicKey))
    break
  case 'sign': {
    const signer = await memorySigner(hexToBytes(need('seed')), need('vm'))
    console.log(JSON.stringify(await createProof(stdin(), signer, { created: need('created') }, loader), null, 2))
    break
  }
  case 'verify':
    if (!(await verifyProof(stdin(), decodeMultikey(need('key')), loader))) {
      console.error('signature does not match')
      process.exit(1)
    }
    console.log('ok')
    break
  case 'context': {
    const schema = stdin() as ClaimSchema
    const problems = validateSchema(schema)
    if (problems.length > 0) {
      console.error(`${problems[0]!.field} ${problems[0]!.message}`)
      process.exit(1)
    }
    const context = contextFromSchema(schema, need('namespace'))
    await assertNoDroppedTerms(schema, context, need('namespace'))
    process.stdout.write(canonicalJson(context))
    break
  }
  default:
    console.error('usage: interop.ts canon|pubkey|sign|verify|context [flags] < document.json')
    process.exit(2)
}
