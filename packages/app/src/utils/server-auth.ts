import type { ServerConnection } from "@/context/server"

const cache = new Map<string, Promise<string | undefined>>()

function key(server: ServerConnection.HttpBase) {
  return `${server.url}\n${server.username ?? ""}\n${server.password ?? ""}`
}

type Info = {
  enabled: boolean
  methods: string[]
  path: string
  api: string
  username: string
}

async function info(server: ServerConnection.HttpBase, fetch: typeof globalThis.fetch): Promise<Info> {
  const res = await fetch(new URL("/api/auth/info", server.url), {
    headers: {
      accept: "application/json",
    },
  }).catch(() => undefined)
  if (!res || !res.ok) {
    return {
      enabled: false,
      methods: [],
      path: "/_auth",
      api: "/api/auth",
      username: "opencode",
    }
  }
  return (await res.json()) as Info
}

async function message(res: Response, fallback: string) {
  const text = await res.text().catch(() => "")
  if (!text) return fallback
  try {
    const json = JSON.parse(text) as { message?: string; error?: { message?: string } }
    return json.message ?? json.error?.message ?? fallback
  } catch {
    return fallback
  }
}

export async function serverToken(server: ServerConnection.HttpBase, fetch: typeof globalThis.fetch) {
  const cfg = await info(server, fetch)
  if (!cfg.enabled) return
  if (cfg.methods.includes("password") && server.password) {
    const res = await fetch(new URL(`${cfg.api}/sign-in/username`, server.url), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        username: server.username ?? cfg.username,
        password: server.password,
      }),
    })
    const token = res.headers.get("set-auth-token")
    if (res.ok && token) return token
    throw new Error(await message(res, "Authentication failed"))
  }
  if (cfg.methods.includes("anonymous")) {
    const res = await fetch(new URL(`${cfg.api}/sign-in/anonymous`, server.url), {
      method: "POST",
      headers: {
        accept: "application/json",
      },
    })
    const token = res.headers.get("set-auth-token")
    if (res.ok && token) return token
  }
}

export function authFetch(server: ServerConnection.HttpBase, fetch: typeof globalThis.fetch) {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init)
    const url = new URL(req.url, server.url)
    if (url.pathname === "/global/health" || url.pathname.startsWith("/api/auth/")) return fetch(req)
    const id = key(server)
    let hit = cache.get(id)
    if (!hit) {
      hit = serverToken(server, fetch).catch((error) => {
        cache.delete(id)
        throw error
      })
      cache.set(id, hit)
    }
    const token = await hit.catch(() => undefined)
    if (!token) return fetch(req)
    const headers = new Headers(req.headers)
    if (!headers.has("Authorization") && !headers.has("authorization")) {
      headers.set("Authorization", `Bearer ${token}`)
    }
    return fetch(new Request(req, { headers }))
  }
}

export function clearServerAuthCache() {
  cache.clear()
}
