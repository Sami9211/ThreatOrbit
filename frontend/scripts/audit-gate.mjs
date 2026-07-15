#!/usr/bin/env node
/**
 * Dependency-audit gate with an explicit, expiring allowlist.
 *
 * `npm audit --audit-level=high` alone would be permanently red here (the
 * next.js advisories only fix in a breaking major), which trains people to
 * ignore CI. Instead: every high/critical advisory must either fail the
 * build or be consciously triaged in .audit-allowlist.json with a reason
 * and an expiry - when the expiry passes, the build goes red again, so a
 * triage decision can never rot silently. Any NEW advisory fails immediately.
 */
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const FAIL_LEVELS = new Set(['high', 'critical'])

let raw
try {
  raw = execSync('npm audit --omit=dev --json', { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
} catch (e) {
  // npm audit exits non-zero when vulnerabilities exist - the JSON is still on stdout
  raw = e.stdout?.toString() ?? ''
  if (!raw) { console.error('npm audit produced no output:', e.message); process.exit(2) }
}
const report = JSON.parse(raw)

let allow = { allow: [] }
try { allow = JSON.parse(readFileSync(new URL('../.audit-allowlist.json', import.meta.url), 'utf8')) } catch { /* no allowlist */ }

const today = new Date().toISOString().slice(0, 10)
const allowed = new Map() // advisory id -> entry
for (const entry of allow.allow ?? []) {
  for (const id of entry.advisories ?? []) allowed.set(id, entry)
}

const failures = []
const triaged = []
for (const [pkg, vuln] of Object.entries(report.vulnerabilities ?? {})) {
  if (!FAIL_LEVELS.has(vuln.severity)) continue
  const ids = (vuln.via ?? []).filter((v) => typeof v === 'object')
    .map((v) => (v.url ?? '').split('/').pop()).filter(Boolean)
  if (ids.length === 0) continue // transitive marker entries ("via": ["next"]) - the root package carries the ids
  for (const id of ids) {
    const entry = allowed.get(id)
    if (!entry) failures.push(`${pkg} ${vuln.severity} ${id} - NOT triaged (add a fix or an allowlist entry with reason+expiry)`)
    else if (entry.expires < today) failures.push(`${pkg} ${vuln.severity} ${id} - allowlist entry EXPIRED ${entry.expires}: ${entry.reason}`)
    else triaged.push(`${pkg} ${id} (until ${entry.expires})`)
  }
}

if (triaged.length) {
  console.log(`Triaged advisories accepted (${triaged.length}):`)
  for (const t of triaged) console.log(`  · ${t}`)
}
if (failures.length) {
  console.error(`\nAudit gate FAILED (${failures.length}):`)
  for (const f of failures) console.error(`  ✗ ${f}`)
  process.exit(1)
}
console.log('\nAudit gate passed: no untriaged high/critical advisories.')
