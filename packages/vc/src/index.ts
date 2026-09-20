export * from './code.js'
export * from './schema/index.js'
export { canonicalize } from './canon.js'
export {
  BUNDLED_CONTEXTS,
  BUNDLED_SCHEMAS,
  CLAIMS_V1,
  CONTEXT_ALLOWLIST,
  CREDENTIALS_V2,
  type DocumentCache,
  type DocumentLoader,
  documentLoader,
  DocumentUnavailableError,
  type LoaderOptions,
  memoryCache,
  SCHEMA_ALLOWLIST,
  schemaLoader,
  staticLoader,
  UnknownContextError,
} from './context/loader.js'
export {
  type Credential,
  credentialProblem,
  type DidDocument,
  type Proof,
  type StatusEntry,
  type StatusListCredential,
  statusListProblem,
  type UnsignedCredential,
  type VerificationMethod,
} from './envelope.js'
export { didToUrl, findKey, parseDidDocument, slugOf, type ResolvedKey } from './did.js'
export { decodeBase58btc, decodeMultikey, encodeBase58btc, encodeMultikey } from './multibase.js'
export { createProof, hashForProof, memorySigner, verifyProof, type Signer } from './proof.js'
export { decodeList, encodeList, getBit, LIST_BITS, setBit } from './status.js'
export { verifyCredential, type Check, type Outcome, type Reason, type Result, type VerifyDeps } from './verify.js'
