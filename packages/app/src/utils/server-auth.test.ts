import { describe, expect, test } from "bun:test"
import { createSdkForServer } from "./server"
import { clearServerAuthCache } from "./server-auth"

const server = {
  url: "http://localhost:4096",
  username: "solo",
  password: "secret-123",
}

describe("createSdkForServer auth", () => {
  test("adds bearer auth to normal sdk requests after Better Auth sign-in", async () => {
    clearServerAuthCache()
    const seen: string[] = []
    const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = new Request(input, init)
      const url = new URL(req.url)
      seen.push(`${req.method} ${url.pathname} ${req.headers.get("authorization") ?? ""}`.trim())
      if (url.pathname === "/api/auth/info") {
        return new Response(
          JSON.stringify({ enabled: true, methods: ["password"], path: "/_auth", api: "/api/auth", username: "solo" }),
          { headers: { "content-type": "application/json" } },
        )
      }
      if (url.pathname === "/api/auth/sign-in/username") {
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "content-type": "application/json",
            "set-auth-token": "tok-123",
          },
        })
      }
      if (url.pathname === "/global/health") {
        return new Response(JSON.stringify({ healthy: true, version: "1.2.3" }), {
          headers: { "content-type": "application/json" },
        })
      }
      return new Response(JSON.stringify({ healthy: true, version: "1.2.3" }), {
        headers: { "content-type": "application/json" },
      })
    }) as typeof globalThis.fetch

    const sdk = createSdkForServer({ server, fetch })
    const res = await sdk.global.health()

    expect(res.data).toEqual({ healthy: true, version: "1.2.3" })
    expect(seen).toEqual([
      "GET /global/health",
    ])

    await sdk.config.get()
    expect(seen).toEqual([
      "GET /global/health",
      "GET /api/auth/info",
      "POST /api/auth/sign-in/username",
      "GET /config Bearer tok-123",
    ])
  })

  test("falls back to anonymous auth when no password is stored", async () => {
    clearServerAuthCache()
    let auth = ""
    const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const req = new Request(input, init)
      const url = new URL(req.url)
      if (url.pathname === "/api/auth/info") {
        return new Response(
          JSON.stringify({ enabled: true, methods: ["anonymous"], path: "/_auth", api: "/api/auth", username: "solo" }),
          { headers: { "content-type": "application/json" } },
        )
      }
      if (url.pathname === "/api/auth/sign-in/anonymous") {
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "content-type": "application/json",
            "set-auth-token": "anon-123",
          },
        })
      }
      auth = req.headers.get("authorization") ?? ""
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "content-type": "application/json" },
      })
    }) as typeof globalThis.fetch

    const sdk = createSdkForServer({
      server: { url: server.url },
      fetch,
    })

    await sdk.config.get()
    expect(auth).toBe("Bearer anon-123")
  })
})
