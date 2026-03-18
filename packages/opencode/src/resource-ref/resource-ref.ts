import { Log } from "@/util/log"
import { Identifier } from "@/id/id"
import type { SessionID } from "@/session/schema"

export namespace ResourceRef {
  const log = Log.create({ service: "resource-ref" })

  const SCHEME = "rsrf"
  const DEFAULT_TTL = 30 * 60 * 1000 // 30 minutes
  const MAX_ENTRIES = 1000
  const CLEANUP_INTERVAL = 5 * 60 * 1000 // 5 minutes

  export type Classification = "sensitive" | "oversize" | "normal"

  export interface Entry {
    key: string
    uri: string
    tool: string
    sessionID: SessionID
    data: string
    classification: Classification
    preview?: string
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
      created: Date.now(),
      ttl: input.ttl ?? DEFAULT_TTL,
      bytes,
    }

    store.set(ref, entry)
    ensureCleanup()

    log.info("stored", {
      uri: ref,
      classification: input.classification,
      bytes,
    })

    return entry
  }

  export function resolve(ref: string, sessionID: SessionID): ResolveResult | undefined {
    const entry = store.get(ref)
    if (!entry) return undefined
    if (entry.sessionID !== sessionID) {
      log.warn("cross-session access denied", { uri: ref, requested: sessionID, owner: entry.sessionID })
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

  /**
   * Parse a rsrf:// URI into its components.
   * Returns undefined if the string is not a valid resource ref URI.
   */
  export function parse(ref: string): { tool: string; key: string } | undefined {
    if (!ref.startsWith(SCHEME + "://")) return undefined
    const rest = ref.slice(SCHEME.length + 3)
    const idx = rest.indexOf("/")
    if (idx < 0) return undefined
    return { tool: rest.slice(0, idx), key: rest.slice(idx + 1) }
  }

  /**
   * Check if a string looks like a resource ref URI.
   */
  export function isRef(value: string): boolean {
    return value.startsWith(SCHEME + "://")
  }

  /**
   * Resolve all rsrf:// URIs found in a string argument, replacing them with their actual data.
   * Only resolves refs belonging to the given session.
   */
  export function resolveInArgs(args: Record<string, unknown>, sessionID: SessionID): Record<string, unknown> {
    const result: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(args)) {
      result[k] = resolveValue(v, sessionID)
    }
    return result
  }

  function resolveValue(value: unknown, sessionID: SessionID): unknown {
    if (typeof value === "string") {
      if (isRef(value)) {
        const resolved = resolve(value, sessionID)
        if (resolved) return resolved.data
      }
      return value
    }
    if (Array.isArray(value)) {
      return value.map((v) => resolveValue(v, sessionID))
    }
    if (typeof value === "object" && value !== null) {
      const out: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(value)) {
        out[k] = resolveValue(v, sessionID)
      }
      return out
    }
    return value
  }

  /**
   * Classify a tool output based on its content.
   * - `sensitive`: if the tool was configured as sensitive before invocation
   * - `oversize`: if the output exceeds the oversize threshold
   * - `normal`: otherwise
   */
  export function classify(
    output: string,
    opts: { sensitive?: boolean; oversizeBytes?: number },
  ): Classification {
    if (opts.sensitive) return "sensitive"
    const bytes = Buffer.byteLength(output, "utf-8")
    if (opts.oversizeBytes && bytes > opts.oversizeBytes) return "oversize"
    return "normal"
  }

  /**
   * Generate a redacted placeholder for sensitive output.
   * The placeholder preserves structural hints (line count, byte size)
   * while ensuring no actual data is exposed.
   */
  export function redact(entry: Entry): string {
    const lines = entry.data.split("\n").length
    return [
      `[SENSITIVE OUTPUT STORED AS RESOURCE REF]`,
      `URI: ${entry.uri}`,
      `Tool: ${entry.tool}`,
      `Size: ${entry.bytes} bytes, ${lines} lines`,
      ``,
      `This output contains sensitive data and has been redacted from the context window.`,
      `Pass the URI (${entry.uri}) directly to other tools that need this data.`,
      `DO NOT attempt to read, log, or display the contents of this resource.`,
    ].join("\n")
  }

  /**
   * Generate an oversize preview placeholder.
   */
  export function oversizePreview(entry: Entry): string {
    const preview = entry.preview || entry.data.slice(0, 500)
    const lines = entry.data.split("\n").length
    return [
      `[OVERSIZE OUTPUT STORED AS RESOURCE REF]`,
      `URI: ${entry.uri}`,
      `Tool: ${entry.tool}`,
      `Size: ${entry.bytes} bytes, ${lines} lines`,
      ``,
      `Preview:`,
      preview,
      ``,
      `Pass the URI (${entry.uri}) to other tools that need the full data.`,
    ].join("\n")
  }

  // --- internal ---

  function isExpired(entry: Entry): boolean {
    return Date.now() - entry.created > entry.ttl
  }

  function evict() {
    // evict oldest entries first
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
