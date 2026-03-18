import { Log } from "@/util/log"
import { Identifier } from "@/id/id"
import type { SessionID } from "@/session/schema"

export namespace ResourceRef {
  const log = Log.create({ service: "resource-ref" })

  const SCHEME = "rsrf"
  const DEFAULT_TTL = 30 * 60 * 1000 // 30 minutes
  const MAX_ENTRIES = 1000
  const CLEANUP_INTERVAL = 5 * 60 * 1000 // 5 minutes
  export const OVERSIZE_BYTES = 50 * 1024 // 50KB — matches truncation threshold
  const PREVIEW_LINES = 20
  const PREVIEW_BYTES = 1024

  export type Classification = "sensitive" | "oversize" | "normal"

  export interface Entry {
    key: string
    uri: string
    tool: string
    sessionID: SessionID
    data: string
    classification: Classification
    preview?: string
    metadata?: Record<string, unknown>
    created: number
    ttl: number
    bytes: number
  }

  export interface StoreInput {
    tool: string
    sessionID: SessionID
    data: string
    classification: Classification
    key?: string
    ttl?: number
    preview?: string
    metadata?: Record<string, unknown>
  }

  export interface ResolveResult {
    data: string
    classification: Classification
    uri: string
    tool: string
  }

  // in-memory store keyed by URI
  const store = new Map<string, Entry>()
  let timer: ReturnType<typeof setInterval> | undefined

  function uri(tool: string, key: string): string {
    return `${SCHEME}://${tool}/${key}`
  }

  function generateKey(): string {
    // Extract the 12-char hex timestamp portion from the ascending ID (after the "tool_" prefix)
    return Identifier.ascending("tool").slice(5, 17)
  }

  export function put(input: StoreInput): Entry {
    const key = input.key || generateKey()
    const ref = uri(input.tool, key)
    const bytes = Buffer.byteLength(input.data, "utf-8")

    if (store.size >= MAX_ENTRIES) {
      evict()
    }

    const entry: Entry = {
      key,
      uri: ref,
      tool: input.tool,
      sessionID: input.sessionID,
      data: input.data,
      classification: input.classification,
      preview: input.preview,
      metadata: input.metadata,
      created: Date.now(),
      ttl: input.ttl ?? DEFAULT_TTL,
      bytes,
    }

    store.set(ref, entry)
    ensureCleanup()

    // only log non-sensitive metadata — never log URIs for sensitive data
    if (input.classification !== "sensitive") {
      log.info("stored", { uri: ref, classification: input.classification, bytes })
    } else {
      log.info("stored sensitive ref", { tool: input.tool, bytes })
    }

    return entry
  }

  export function resolve(ref: string, sessionID: SessionID): ResolveResult | undefined {
    const entry = store.get(ref)
    if (!entry) return undefined
    if (entry.sessionID !== sessionID) {
      log.warn("cross-session access denied", { requested: sessionID })
      return undefined
    }
    if (isExpired(entry)) {
      store.delete(ref)
      return undefined
    }
    return {
      data: entry.data,
      classification: entry.classification,
      uri: entry.uri,
      tool: entry.tool,
    }
  }

  export function has(ref: string): boolean {
    const entry = store.get(ref)
    if (!entry) return false
    if (isExpired(entry)) {
      store.delete(ref)
      return false
    }
    return true
  }

  export function remove(ref: string): boolean {
    return store.delete(ref)
  }

  export function list(sessionID: SessionID): Entry[] {
    const result: Entry[] = []
    for (const entry of store.values()) {
      if (entry.sessionID !== sessionID) continue
      if (isExpired(entry)) {
        store.delete(entry.uri)
        continue
      }
      result.push(entry)
    }
    return result
  }

  export function clear(sessionID: SessionID): number {
    let count = 0
    for (const [key, entry] of store) {
      if (entry.sessionID === sessionID) {
        store.delete(key)
        count++
      }
    }
    return count
  }

  export function clearAll(): void {
    store.clear()
  }

  export function size(): number {
    return store.size
  }

  /** Total bytes held across all entries (approximate memory footprint). */
  export function totalBytes(): number {
    let total = 0
    for (const entry of store.values()) {
      total += entry.bytes
    }
    return total
  }

  /**
   * Parse a rsrf:// URI into its components.
   * Returns undefined if the string is not a valid resource ref URI.
   */
  export function parse(ref: string): { tool: string; key: string } | undefined {
    if (!ref.startsWith(SCHEME + "://")) return undefined
    const rest = ref.slice(SCHEME.length + 3)
    const idx = rest.indexOf("/")
    if (idx < 0) return undefined
    const tool = rest.slice(0, idx)
    const key = rest.slice(idx + 1)
    if (!tool || !key) return undefined
    return { tool, key }
  }

  /**
   * Check if a string looks like a resource ref URI.
   */
  export function isRef(value: string): boolean {
    return value.startsWith(SCHEME + "://")
  }

  /**
   * Resolve all rsrf:// URIs found in tool arguments, replacing them with actual data.
   * Only resolves refs belonging to the given session. Returns the args unchanged
   * if no refs are present (avoids unnecessary copying).
   */
  export function resolveInArgs(args: Record<string, unknown>, sessionID: SessionID): Record<string, unknown> {
    let changed = false
    const result: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(args)) {
      const resolved = resolveValue(v, sessionID)
      if (resolved !== v) changed = true
      result[k] = resolved
    }
    return changed ? result : args
  }

  function resolveValue(value: unknown, sessionID: SessionID): unknown {
    if (typeof value === "string") {
      if (!isRef(value)) return value
      const resolved = resolve(value, sessionID)
      return resolved ? resolved.data : value
    }
    if (Array.isArray(value)) {
      let changed = false
      const out = value.map((v) => {
        const r = resolveValue(v, sessionID)
        if (r !== v) changed = true
        return r
      })
      return changed ? out : value
    }
    if (typeof value === "object" && value !== null) {
      let changed = false
      const out: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(value)) {
        const r = resolveValue(v, sessionID)
        if (r !== v) changed = true
        out[k] = r
      }
      return changed ? out : value
    }
    return value
  }

  /**
   * Classify a tool output.
   * - `sensitive`: if the tool or output was flagged as sensitive (always takes precedence)
   * - `oversize`: if the output exceeds the byte threshold
   * - `normal`: otherwise
   */
  export function classify(
    output: string,
    opts: { sensitive?: boolean; oversizeBytes?: number },
  ): Classification {
    if (opts.sensitive) return "sensitive"
    const bytes = Buffer.byteLength(output, "utf-8")
    const threshold = opts.oversizeBytes ?? OVERSIZE_BYTES
    if (bytes > threshold) return "oversize"
    return "normal"
  }

  /**
   * Generate a redacted placeholder for sensitive output.
   * Preserves structural hints (line count, byte size) while ensuring
   * no actual data is exposed. Handles edge cases like empty or very
   * short secrets by keeping the placeholder informative.
   */
  export function redact(entry: Entry): string {
    const lines = entry.data.split("\n").length
    const parts = [
      `[SENSITIVE OUTPUT — REDACTED]`,
      `URI: ${entry.uri}`,
      `Tool: ${entry.tool}`,
      `Size: ${entry.bytes} bytes, ${lines} line${lines === 1 ? "" : "s"}`,
    ]
    if (entry.metadata) {
      const safe = Object.entries(entry.metadata)
        .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
        .map(([k, v]) => `${k}=${v}`)
      if (safe.length) parts.push(`Metadata: ${safe.join(", ")}`)
    }
    parts.push(
      ``,
      `This output contains sensitive data and has been redacted from the context window.`,
      `To use this data, pass the URI directly as a tool argument: ${entry.uri}`,
      `Do NOT attempt to read, log, or display the contents of this resource.`,
    )
    return parts.join("\n")
  }

  /**
   * Generate a preview placeholder for oversize output.
   * Uses line-based truncation for readable previews rather than
   * arbitrary character slicing.
   */
  export function oversizePreview(entry: Entry): string {
    const allLines = entry.data.split("\n")
    let preview = entry.preview
    if (!preview) {
      const selected: string[] = []
      let bytes = 0
      for (const line of allLines) {
        if (selected.length >= PREVIEW_LINES) break
        const size = Buffer.byteLength(line, "utf-8")
        if (bytes + size > PREVIEW_BYTES && selected.length > 0) break
        selected.push(line)
        bytes += size
      }
      preview = selected.join("\n")
      if (selected.length < allLines.length) {
        preview += `\n... (${allLines.length - selected.length} more lines)`
      }
    }
    const parts = [
      `[OVERSIZE OUTPUT — STORED AS RESOURCE REF]`,
      `URI: ${entry.uri}`,
      `Tool: ${entry.tool}`,
      `Size: ${entry.bytes} bytes, ${allLines.length} line${allLines.length === 1 ? "" : "s"}`,
    ]
    if (entry.metadata) {
      const safe = Object.entries(entry.metadata)
        .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
        .map(([k, v]) => `${k}=${v}`)
      if (safe.length) parts.push(`Metadata: ${safe.join(", ")}`)
    }
    parts.push(``, `Preview:`, preview, ``, `To access the full data, pass the URI to another tool: ${entry.uri}`)
    return parts.join("\n")
  }

  // --- internal ---

  function isExpired(entry: Entry): boolean {
    return Date.now() - entry.created > entry.ttl
  }

  function evict() {
    // evict expired entries first, then oldest
    let oldest: Entry | undefined
    for (const entry of store.values()) {
      if (isExpired(entry)) {
        store.delete(entry.uri)
        continue
      }
      if (!oldest || entry.created < oldest.created) {
        oldest = entry
      }
    }
    if (oldest && store.size >= MAX_ENTRIES) {
      store.delete(oldest.uri)
    }
  }

  function cleanup() {
    for (const [key, entry] of store) {
      if (isExpired(entry)) {
        store.delete(key)
      }
    }
    if (store.size === 0 && timer) {
      clearInterval(timer)
      timer = undefined
    }
  }

  function ensureCleanup() {
    if (timer) return
    timer = setInterval(cleanup, CLEANUP_INTERVAL)
    // Allow process to exit without waiting for cleanup
    if (typeof timer === "object" && "unref" in timer) {
      timer.unref()
    }
  }
}
