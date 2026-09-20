// The TypeScript half of the interop check. Same commands as vc-go/cmd/vcinterop.
//
//   tsx scripts/interop.ts canon                                     < doc.json
//   tsx scripts/interop.ts sign --seed <hex> --vm <id> --created <iso> < unsigned.json
//   tsx scripts/interop.ts verify --key <publicKeyMultibase>         < signed.json
//   tsx scripts/interop.ts pubkey --seed <hex>
import { readFileSync } from 'node:fs'
import { parseArgs } from 'node:util'
import { hexToBytes } from '@noble/hashes/utils.js'
import { canonicalize } from '../src/canon.js'
import { decodeMultikey, encodeMultikey } from '../src/multibase.js'
import { createProof, memorySigner, verifyProof } from '../src/proof.js'

const [command, ...rest] = process.argv.slice(2)
const { values } = parseArgs({
  args: rest,
  options: { seed: { type: 'string' }, vm: { type: 'string' }, created: { type: 'string' }, key: { type: 'string' } },
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

switch (command) {
  case 'canon':
    process.stdout.write(await canonicalize(stdin()))
    break
  case 'pubkey':
    console.log(encodeMultikey((await memorySigner(hexToBytes(need('seed')), 'unused')).publicKey))
    break
  case 'sign': {
    const signer = await memorySigner(hexToBytes(need('seed')), need('vm'))
    console.log(JSON.stringify(await createProof(stdin(), signer, { created: need('created') }), null, 2))
    break
  }
  case 'verify':
    if (!(await verifyProof(stdin(), decodeMultikey(need('key'))))) {
      console.error('signature does not match')
      process.exit(1)
    }
    console.log('ok')
    break
  default:
    console.error('usage: interop.ts canon|pubkey|sign|verify [flags] < document.json')
    process.exit(2)
}
