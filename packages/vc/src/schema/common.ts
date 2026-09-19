import { z } from 'zod'

// These schemas validate and never transform. The same object that was
// validated is the one that gets signed or verified.

/** Free text as it appears on a document: 1-200 characters, no leading or trailing space. */
export const text = z
  .string()
  .min(1)
  .max(200)
  .refine((s) => s === s.trim(), 'must not start or end with a space')

/** A calendar date, YYYY-MM-DD. */
export const date = z.iso.date()

/** An instant with an explicit offset, e.g. 2026-01-10T09:00:00Z. */
export const instant = z.iso.datetime({ offset: true })

export const SLUG = '[a-z]{2,4}'
export const issuerDid = z.string().regex(new RegExp(`^did:web:vemphy\\.com:i:${SLUG}$`))
