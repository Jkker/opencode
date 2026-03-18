import { describe, test, expect, beforeEach } from "bun:test"
import { ResourceRef } from "../../src/resource-ref/resource-ref"
import { SessionID } from "../../src/session/schema"

const sess1 = SessionID.descending("test-session-1")
const sess2 = SessionID.descending("test-session-2")

describe("ResourceRef", () => {
  beforeEach(() => {
    ResourceRef.clearAll()
  })

  describe("put and resolve", () => {
    test("stores and retrieves data", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "secret-password-123",
        classification: "sensitive",
      })
      expect(entry.uri).toStartWith("rsrf://bash/")
      expect(entry.bytes).toBe(Buffer.byteLength("secret-password-123"))
      expect(entry.classification).toBe("sensitive")

      const resolved = ResourceRef.resolve(entry.uri, sess1)
      expect(resolved).toBeDefined()
      expect(resolved!.data).toBe("secret-password-123")
      expect(resolved!.classification).toBe("sensitive")
    })

    test("uses custom key when provided", () => {
      const entry = ResourceRef.put({
        tool: "password-manager",
        sessionID: sess1,
        data: "s3cret",
        classification: "sensitive",
        key: "db-pass",
      })
      expect(entry.uri).toBe("rsrf://password-manager/db-pass")
      expect(entry.key).toBe("db-pass")
    })

    test("stores metadata on entries", () => {
      const entry = ResourceRef.put({
        tool: "vault",
        sessionID: sess1,
        data: "token-value",
        classification: "sensitive",
        key: "api-token",
        metadata: { type: "bearer", scope: "admin" },
      })
      expect(entry.metadata).toEqual({ type: "bearer", scope: "admin" })
    })

    test("denies cross-session access", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "secret",
        classification: "sensitive",
      })
      const resolved = ResourceRef.resolve(entry.uri, sess2)
      expect(resolved).toBeUndefined()
    })

    test("returns undefined for non-existent ref", () => {
      const resolved = ResourceRef.resolve("rsrf://bash/nonexistent", sess1)
      expect(resolved).toBeUndefined()
    })

    test("expires entries after TTL", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "temp",
        classification: "normal",
        ttl: -1, // already expired
      })
      const resolved = ResourceRef.resolve(entry.uri, sess1)
      expect(resolved).toBeUndefined()
    })
  })

  describe("has and remove", () => {
    test("has returns true for existing entries", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "data",
        classification: "normal",
      })
      expect(ResourceRef.has(entry.uri)).toBe(true)
    })

    test("has returns false after removal", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "data",
        classification: "normal",
      })
      ResourceRef.remove(entry.uri)
      expect(ResourceRef.has(entry.uri)).toBe(false)
    })

    test("has returns false for expired entries", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "data",
        classification: "normal",
        ttl: -1,
      })
      expect(ResourceRef.has(entry.uri)).toBe(false)
    })
  })

  describe("list and clear", () => {
    test("lists entries for a session", () => {
      ResourceRef.put({ tool: "a", sessionID: sess1, data: "1", classification: "normal" })
      ResourceRef.put({ tool: "b", sessionID: sess1, data: "2", classification: "sensitive" })
      ResourceRef.put({ tool: "c", sessionID: sess2, data: "3", classification: "normal" })

      const list = ResourceRef.list(sess1)
      expect(list.length).toBe(2)
      expect(list.every((e) => e.sessionID === sess1)).toBe(true)
    })

    test("clears entries for a session", () => {
      ResourceRef.put({ tool: "a", sessionID: sess1, data: "1", classification: "normal" })
      ResourceRef.put({ tool: "b", sessionID: sess1, data: "2", classification: "normal" })
      ResourceRef.put({ tool: "c", sessionID: sess2, data: "3", classification: "normal" })

      const cleared = ResourceRef.clear(sess1)
      expect(cleared).toBe(2)
      expect(ResourceRef.size()).toBe(1)
      expect(ResourceRef.list(sess2).length).toBe(1)
    })

    test("clearAll removes everything", () => {
      ResourceRef.put({ tool: "a", sessionID: sess1, data: "1", classification: "normal" })
      ResourceRef.put({ tool: "b", sessionID: sess2, data: "2", classification: "normal" })
      ResourceRef.clearAll()
      expect(ResourceRef.size()).toBe(0)
    })
  })

  describe("parse", () => {
    test("parses valid rsrf URIs", () => {
      const parsed = ResourceRef.parse("rsrf://bash/my-key")
      expect(parsed).toEqual({ tool: "bash", key: "my-key" })
    })

    test("parses URIs with nested paths", () => {
      const parsed = ResourceRef.parse("rsrf://mcp-server/output/sub-key")
      expect(parsed).toEqual({ tool: "mcp-server", key: "output/sub-key" })
    })

    test("returns undefined for non-rsrf URIs", () => {
      expect(ResourceRef.parse("https://example.com")).toBeUndefined()
      expect(ResourceRef.parse("file:///tmp/foo")).toBeUndefined()
      expect(ResourceRef.parse("plain-string")).toBeUndefined()
    })

    test("returns undefined for malformed rsrf URIs", () => {
      expect(ResourceRef.parse("rsrf://nokey")).toBeUndefined()
    })

    test("returns undefined for empty tool or key", () => {
      expect(ResourceRef.parse("rsrf:///key")).toBeUndefined()
      expect(ResourceRef.parse("rsrf://tool/")).toBeUndefined()
    })
  })

  describe("isRef", () => {
    test("identifies rsrf URIs", () => {
      expect(ResourceRef.isRef("rsrf://bash/key")).toBe(true)
      expect(ResourceRef.isRef("rsrf://x/y")).toBe(true)
    })

    test("rejects non-rsrf strings", () => {
      expect(ResourceRef.isRef("https://example.com")).toBe(false)
      expect(ResourceRef.isRef("plain-string")).toBe(false)
    })
  })

  describe("resolveInArgs", () => {
    test("resolves rsrf URIs in string args", () => {
      const entry = ResourceRef.put({
        tool: "vault",
        sessionID: sess1,
        data: "actual-secret-value",
        classification: "sensitive",
        key: "secret",
      })

      const result = ResourceRef.resolveInArgs({ password: entry.uri, username: "admin" }, sess1)
      expect(result.password).toBe("actual-secret-value")
      expect(result.username).toBe("admin")
    })

    test("resolves nested rsrf URIs in objects", () => {
      const entry = ResourceRef.put({
        tool: "vault",
        sessionID: sess1,
        data: "nested-secret",
        classification: "sensitive",
        key: "nested",
      })

      const result = ResourceRef.resolveInArgs({ config: { auth: { token: entry.uri } } }, sess1)
      expect((result.config as any).auth.token).toBe("nested-secret")
    })

    test("resolves rsrf URIs in arrays", () => {
      const entry = ResourceRef.put({
        tool: "vault",
        sessionID: sess1,
        data: "array-secret",
        classification: "sensitive",
        key: "arr",
      })

      const result = ResourceRef.resolveInArgs({ items: [entry.uri, "normal-value"] }, sess1)
      expect((result.items as string[])[0]).toBe("array-secret")
      expect((result.items as string[])[1]).toBe("normal-value")
    })

    test("leaves unresolvable refs as-is", () => {
      const result = ResourceRef.resolveInArgs({ key: "rsrf://nonexistent/key" }, sess1)
      expect(result.key).toBe("rsrf://nonexistent/key")
    })

    test("preserves non-string values", () => {
      const result = ResourceRef.resolveInArgs({ count: 42, flag: true, empty: null }, sess1)
      expect(result.count).toBe(42)
      expect(result.flag).toBe(true)
      expect(result.empty).toBeNull()
    })

    test("returns original args when no refs present", () => {
      const args = { command: "ls -la", timeout: 30 }
      const result = ResourceRef.resolveInArgs(args, sess1)
      expect(result).toBe(args) // same reference — no copy made
    })
  })

  describe("classify", () => {
    test("classifies as sensitive when flag is set", () => {
      expect(ResourceRef.classify("data", { sensitive: true })).toBe("sensitive")
    })

    test("classifies as oversize using default threshold", () => {
      const data = "x".repeat(ResourceRef.OVERSIZE_BYTES + 1)
      expect(ResourceRef.classify(data, {})).toBe("oversize")
    })

    test("classifies as oversize using custom threshold", () => {
      const data = "x".repeat(1000)
      expect(ResourceRef.classify(data, { oversizeBytes: 500 })).toBe("oversize")
    })

    test("classifies as normal when under threshold", () => {
      expect(ResourceRef.classify("data", {})).toBe("normal")
    })

    test("sensitive takes precedence over oversize", () => {
      const data = "x".repeat(ResourceRef.OVERSIZE_BYTES + 1)
      expect(ResourceRef.classify(data, { sensitive: true })).toBe("sensitive")
    })
  })

  describe("redact", () => {
    test("produces redacted placeholder with metadata", () => {
      const entry = ResourceRef.put({
        tool: "vault",
        sessionID: sess1,
        data: "my-secret-password\nsecond-line",
        classification: "sensitive",
        key: "pass",
      })

      const redacted = ResourceRef.redact(entry)
      expect(redacted).toContain("SENSITIVE OUTPUT")
      expect(redacted).toContain("REDACTED")
      expect(redacted).toContain(entry.uri)
      expect(redacted).toContain("vault")
      expect(redacted).toContain("2 lines")
      expect(redacted).not.toContain("my-secret-password")
      expect(redacted).not.toContain("second-line")
    })

    test("handles single-line secret correctly", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "short",
        classification: "sensitive",
        key: "k",
      })
      const redacted = ResourceRef.redact(entry)
      expect(redacted).toContain("1 line")
      expect(redacted).not.toContain("1 lines")
    })

    test("includes entry metadata in redacted output", () => {
      const entry = ResourceRef.put({
        tool: "vault",
        sessionID: sess1,
        data: "secret",
        classification: "sensitive",
        key: "tok",
        metadata: { type: "bearer" },
      })
      const redacted = ResourceRef.redact(entry)
      expect(redacted).toContain("type=bearer")
    })
  })

  describe("oversizePreview", () => {
    test("includes line-based preview and URI", () => {
      const lines = Array.from({ length: 100 }, (_, i) => `line ${i}: ${"x".repeat(50)}`)
      const data = lines.join("\n")
      const entry = ResourceRef.put({
        tool: "duckdb",
        sessionID: sess1,
        data,
        classification: "oversize",
        key: "results",
      })

      const preview = ResourceRef.oversizePreview(entry)
      expect(preview).toContain("OVERSIZE OUTPUT")
      expect(preview).toContain(entry.uri)
      expect(preview).toContain("line 0:")
      expect(preview).toContain("duckdb")
      expect(preview).toContain("100 lines")
      expect(preview).toContain("more lines")
    })

    test("uses custom preview when provided", () => {
      const entry = ResourceRef.put({
        tool: "query",
        sessionID: sess1,
        data: "x".repeat(10000),
        classification: "oversize",
        key: "big",
        preview: "Custom preview text",
      })

      const text = ResourceRef.oversizePreview(entry)
      expect(text).toContain("Custom preview text")
    })

    test("includes entry metadata in preview", () => {
      const entry = ResourceRef.put({
        tool: "query",
        sessionID: sess1,
        data: "x".repeat(1000),
        classification: "oversize",
        key: "m",
        metadata: { rows: 500 },
      })
      const text = ResourceRef.oversizePreview(entry)
      expect(text).toContain("rows=500")
    })

    test("shows full content when data fits preview limits", () => {
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "line1\nline2\nline3",
        classification: "oversize",
        key: "small",
      })
      const text = ResourceRef.oversizePreview(entry)
      expect(text).toContain("line1")
      expect(text).toContain("line3")
      expect(text).not.toContain("more lines")
    })
  })

  describe("totalBytes", () => {
    test("tracks total memory footprint", () => {
      ResourceRef.put({ tool: "a", sessionID: sess1, data: "hello", classification: "normal" })
      ResourceRef.put({ tool: "b", sessionID: sess1, data: "world!", classification: "normal" })
      expect(ResourceRef.totalBytes()).toBe(Buffer.byteLength("hello") + Buffer.byteLength("world!"))
    })

    test("returns 0 when empty", () => {
      expect(ResourceRef.totalBytes()).toBe(0)
    })
  })

  describe("eviction", () => {
    test("overwrites existing entry with same key", () => {
      ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "old-data",
        classification: "normal",
        key: "same-key",
      })
      const entry = ResourceRef.put({
        tool: "bash",
        sessionID: sess1,
        data: "new-data",
        classification: "normal",
        key: "same-key",
      })

      const resolved = ResourceRef.resolve(entry.uri, sess1)
      expect(resolved!.data).toBe("new-data")
    })
  })

  describe("OVERSIZE_BYTES constant", () => {
    test("is exported and matches truncation threshold", () => {
      expect(ResourceRef.OVERSIZE_BYTES).toBe(50 * 1024)
    })
  })
})
