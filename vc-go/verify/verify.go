// Package verify checks Vemphy claims. It is the same pipeline, in the same
// order, as verifyCredential in the @vemphy/vc TypeScript package.
package verify

import (
	"context"
	"encoding/json"
	"time"

	"github.com/piprate/json-gold/ld"

	"github.com/vemphy/vc/vc-go/did"
	"github.com/vemphy/vc/vc-go/proof"
	"github.com/vemphy/vc/vc-go/schema"
	"github.com/vemphy/vc/vc-go/status"
	"github.com/vemphy/vc/vc-go/vcctx"
)

type Result string

const (
	Valid   Result = "valid"
	Revoked Result = "revoked"
	Expired Result = "expired"
	Unknown Result = "unknown"
)

// Reason says why a result is Unknown. It is for operators and alerting.
// Anything shown to the person checking a claim uses the four results only.
type Reason string

const (
	Malformed              Reason = "malformed"
	ContextUnavailable     Reason = "context_unavailable"
	DIDUnresolvable        Reason = "did_unresolvable"
	KeyNotFound            Reason = "key_not_found"
	KeyWindowViolation     Reason = "key_window_violation"
	SignatureFailure       Reason = "signature_failure"
	StatusListUnverifiable Reason = "status_list_unverifiable"
)

type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
}

type Outcome struct {
	Result Result  `json:"result"`
	Reason Reason  `json:"reason,omitempty"`
	Checks []Check `json:"checks"`
	// SchemaValid says whether the subject matches the schema the claim names.
	// It is extra information: it never changes Result, which signature,
	// status and dates decide. Nil when the signature did not hold or the
	// schema could not be had.
	SchemaValid *bool `json:"schemaValid,omitempty"`
}

// Deps is everything verification needs from outside. Credential reads no
// clock and does no I/O of its own.
type Deps struct {
	Now time.Time
	// ResolveDID returns the DID document for an issuer DID. See did.URL.
	ResolveDID func(ctx context.Context, did string) ([]byte, error)
	// FetchStatusList returns the status list credential at a URL.
	FetchStatusList func(ctx context.Context, url string) ([]byte, error)
	// DocumentLoader loads JSON-LD contexts. Nil means the bundled ones,
	// offline: the W3C context and every core type. Give it a vcctx.Resolver
	// with a cache to verify claims of an issuer's own types.
	DocumentLoader ld.DocumentLoader
	// FetchSchema returns the schema document at a URL. Nil means the bundled
	// core schemas, offline.
	FetchSchema func(ctx context.Context, url string) ([]byte, error)
}

var (
	bundledContexts = vcctx.New(vcctx.Options{Allowlist: []string{}})
	bundledSchemas  = vcctx.NewSchemas(vcctx.Options{Allowlist: []string{}})
)

// Credential verifies a claim. Whatever goes wrong, the answer is one of the
// four results.
//
// The order matters. The signature is checked before revocation and dates, so
// a document that has been altered can only ever come back Unknown.
func Credential(ctx context.Context, raw []byte, deps Deps) Outcome {
	var checks []Check
	var schemaValid *bool
	pass := func(name string) { checks = append(checks, Check{name, true}) }
	stop := func(name string, result Result, reason Reason) Outcome {
		return Outcome{result, reason, append(checks, Check{name, false}), schemaValid}
	}
	loader := deps.DocumentLoader
	if loader == nil {
		loader = bundledContexts
	}

	// 1. Shape.
	c, err := parseCredential(raw)
	if err != nil {
		return stop("shape", Unknown, Malformed)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return stop("shape", Unknown, Malformed)
	}
	pass("shape")

	// The vocabulary the claim is written in. Without it nothing can be said about the signature.
	if _, err := loader.LoadDocument(c.Context[1]); err != nil {
		return stop("context", Unknown, ContextUnavailable)
	}
	pass("context")

	// 2. Issuer key.
	didDocument, err := resolve(ctx, deps, c.Issuer)
	if err != nil {
		return stop("did", Unknown, DIDUnresolvable)
	}
	pass("did")

	key, err := did.FindKey(didDocument, c.Proof.VerificationMethod)
	if err != nil || key == nil {
		return stop("key", Unknown, KeyNotFound)
	}
	pass("key")

	// 3. The key must not have been revoked or expired when the proof was made.
	if !key.UsableAt(c.created) {
		return stop("key_window", Unknown, KeyWindowViolation)
	}
	pass("key_window")

	// 4. Signature.
	if ok, err := proof.Verify(document, key.PublicKey, loader); err != nil || !ok {
		return stop("signature", Unknown, SignatureFailure)
	}
	pass("signature")
	schemaValid = matchesSchema(ctx, deps, c)

	// 5. The status list is itself a signed, short-lived credential from the same issuer.
	bits := loadStatusList(ctx, deps, c, didDocument)
	if bits == nil {
		return stop("status_list", Unknown, StatusListUnverifiable)
	}
	pass("status_list")

	// 6. Revocation.
	if revoked, err := status.Get(bits, c.index); err != nil || revoked {
		return stop("not_revoked", Revoked, "")
	}
	pass("not_revoked")

	// 7. Validity period.
	if deps.Now.Before(c.validFrom) || (c.validUntil != nil && !deps.Now.Before(*c.validUntil)) {
		return stop("validity_period", Expired, "")
	}
	pass("validity_period")

	return Outcome{Result: Valid, Checks: checks, SchemaValid: schemaValid}
}

// A claim issued under claims/v1 names no schema; version 1 of the core type
// of the same name describes it.
func matchesSchema(ctx context.Context, deps Deps, c *credential) *bool {
	answer := func(b bool) *bool { return &b }
	var s *schema.Schema
	if c.legacy {
		core, ok := schema.CoreSchema(c.ref.Name, 1)
		if !ok {
			return nil
		}
		s = core
	} else {
		fetch := deps.FetchSchema
		if fetch == nil {
			fetch = bundledSchemas.Get
		}
		document, err := fetch(ctx, c.CredentialSchema.ID)
		if err != nil {
			return nil
		}
		inner, ok := schema.SubjectSchemaFrom(document)
		if !ok {
			return nil
		}
		// Parse refuses anything outside the restricted subset before compiling it.
		if s, err = schema.Parse(inner); err != nil {
			return answer(false)
		}
	}
	return answer(len(s.ValidateSubject(c.CredentialSubject)) == 0)
}

func resolve(ctx context.Context, deps Deps, issuer string) (*did.Document, error) {
	raw, err := deps.ResolveDID(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return did.Parse(raw, issuer)
}

func loadStatusList(ctx context.Context, deps Deps, c *credential, didDocument *did.Document) []byte {
	url := c.CredentialStatus.StatusListCredential
	raw, err := deps.FetchStatusList(ctx, url)
	if err != nil {
		return nil
	}
	list, err := parseStatusList(raw)
	if err != nil || list.ID != url || list.Issuer != c.Issuer {
		return nil
	}
	if deps.Now.Before(list.validFrom) || !deps.Now.Before(list.validUntil) {
		return nil
	}
	key, err := did.FindKey(didDocument, list.Proof.VerificationMethod)
	if err != nil || key == nil || !key.UsableAt(list.created) {
		return nil
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil
	}
	if ok, err := proof.Verify(document, key.PublicKey, deps.DocumentLoader); err != nil || !ok {
		return nil
	}
	bits, err := status.Decode(list.CredentialSubject.EncodedList)
	if err != nil {
		return nil
	}
	return bits
}
