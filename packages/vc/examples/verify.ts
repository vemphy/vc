// The example in README.md, kept here so that it is typechecked.
// In your own project the import is from '@vemphy/vc'.
import { didToUrl, verifyCredential } from '../src/index.js'

const getJson = (url: string) => fetch(url).then((response) => response.json())

export async function check(claim: unknown) {
  const { result } = await verifyCredential(claim, {
    now: new Date(),
    resolveDid: (did) => getJson(didToUrl(did)),
    fetchStatusList: getJson,
  })
  return result // 'valid' | 'revoked' | 'expired' | 'unknown'
}
