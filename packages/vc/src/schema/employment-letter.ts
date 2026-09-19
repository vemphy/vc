import { z } from 'zod'
import { date, text } from './common.js'

export const employmentLetter = z
  .strictObject({
    employeeName: text,
    staffNumber: text.optional(),
    jobTitle: text,
    employmentType: z.enum(['permanent', 'contract', 'temporary', 'internship']),
    startDate: date,
    endDate: date.optional(),
    currentlyEmployed: z.boolean(),
  })
  .superRefine((value, ctx) => {
    if (value.endDate === undefined) return
    if (value.currentlyEmployed) {
      ctx.addIssue({ code: 'custom', path: ['endDate'], message: 'a current employee has no end date' })
    }
    // ISO dates compare correctly as strings.
    if (value.endDate < value.startDate) {
      ctx.addIssue({ code: 'custom', path: ['endDate'], message: 'must not be before startDate' })
    }
  })

export const employmentLetterDisclosure = ['employeeName', 'jobTitle', 'startDate', 'currentlyEmployed'] as const
