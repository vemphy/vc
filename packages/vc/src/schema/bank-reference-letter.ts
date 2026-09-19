import { z } from 'zod'
import { date, text } from './common.js'

export const bankReferenceLetter = z.strictObject({
  accountHolderName: text,
  accountType: z.enum(['current', 'savings', 'business']),
  accountNumberLast4: z.string().regex(/^\d{4}$/),
  accountOpenedOn: date,
  branch: text,
  standing: z.enum(['satisfactory', 'unsatisfactory']),
  addressedTo: text.optional(),
  referenceDate: date,
})

export const bankReferenceLetterDisclosure = ['accountHolderName', 'accountType', 'standing', 'referenceDate'] as const
