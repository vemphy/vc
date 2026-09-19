import { z } from 'zod'
import { date, text } from './common.js'

export const degreeCertificate = z.strictObject({
  graduateName: text,
  studentNumber: text,
  qualification: text,
  programme: text,
  classification: text.optional(),
  conferredOn: date,
})

export const degreeCertificateDisclosure = [
  'graduateName',
  'qualification',
  'programme',
  'classification',
  'conferredOn',
] as const
