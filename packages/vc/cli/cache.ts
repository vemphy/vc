import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { DocumentCache } from '../src/context/loader.js'
import { canonicalJson } from '../src/schema/context.js'

/** https://vemphy.com/ns/i/gcb/StaffIdCard/v1 -> vemphy.com_ns_i_gcb_StaffIdCard_v1.json */
export function cacheFileName(url: string): string {
  return `${url.replace(/^https:\/\//, '').replace(/[^A-Za-z0-9.-]/g, '_')}.json`
}

/** A cache that is a directory of JSON files. Published contexts and schemas never change, so nothing expires. */
export function dirCache(dir: string): DocumentCache {
  return {
    async get(url) {
      const path = join(dir, cacheFileName(url))
      return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : undefined
    },
    async set(url, document) {
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, cacheFileName(url)), canonicalJson(document))
    },
  }
}
