#!/usr/bin/env node
/**
 * Fence for a whole CLASS of silent runtime bug.
 *
 * Every response in lib/api.ts goes through `toCamel(...) as T`. The `as T` cast
 * is a lie the compiler cannot check: if a response interface declares a
 * snake_case field, the mapper has already renamed it, so EVERY read of that
 * field is `undefined` at runtime with zero type errors.
 *
 * This actually shipped: `ConnectorKind.needs_key` / `needs_url` /
 * `default_url` / `default_interval` were declared snake_case, so the
 * Add-connector modal hid the API-key field, wrongly showed Source URL for OTX,
 * and sent interval_minutes=NaN -> a 422 that made OTX impossible to configure.
 *
 * So: response interfaces must be camelCase. Request-body types are exempt -
 * those are sent as-is and the API expects snake_case.
 */
import { readFileSync } from 'node:fs'

const FILE = new URL('../lib/api.ts', import.meta.url)
const src = readFileSync(FILE, 'utf8')

// Interfaces used only to build request bodies keep the wire's snake_case.
const REQUEST_TYPES = new Set([
  'ConnectorCreate', 'ConnectorPatch', 'IocImportBody', 'RuleBody', 'SigmaImportBody',
])

const failures = []
// Walk each `export interface Name {` and brace-match to its real end, so
// single-line interfaces don't swallow the next declaration's fields.
const head = /export interface (\w+)\s*\{/g
let m
while ((m = head.exec(src)) !== null) {
  const name = m[1]
  let depth = 1
  let i = m.index + m[0].length
  for (; i < src.length && depth > 0; i++) {
    if (src[i] === '{') depth++
    else if (src[i] === '}') depth--
  }
  if (REQUEST_TYPES.has(name)) continue
  const body = src.slice(m.index + m[0].length, i - 1)
  // Field names appear after `{`, `;` or a newline - never inside a comment.
  for (const fm of body.matchAll(/(?:^|[;{])\s*([a-z][a-zA-Z0-9]*_[a-zA-Z0-9_]+)\??\s*:/gm)) {
    failures.push(`${name}.${fm[1]}`)
  }
}

if (failures.length) {
  console.error('\x1b[31mAPI casing check FAILED\x1b[0m')
  console.error(
    'These response-interface fields are snake_case, but api() runs every\n' +
    'response through toCamel(), so each one reads as `undefined` at runtime:\n')
  for (const f of failures) console.error(`  - ${f}`)
  console.error('\nRename them to camelCase (needs_key -> needsKey), or add the type to')
  console.error('REQUEST_TYPES in this script if it is only used to build a request body.')
  process.exit(1)
}

console.log(`API casing check passed - no snake_case fields in response interfaces.`)
