export namespace RemoteAuth {
  export type Fetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

  export type Info = {
    enabled: boolean
    methods: string[]
    path: string
    api: string
    username: string
  }

  export async function info(input: { url: string; fetch?: Fetch }) {
    const fetcher = input.fetch ?? globalThis.fetch
    const res = await fetcher(new URL("/api/auth/info", input.url), {
      headers: {
        accept: "application/json",
      },
    }).catch(() => undefined)
    if (!res || !res.ok) return { enabled: false, methods: [], path: "/_auth", api: "/api/auth", username: "opencode" } as Info
    return (await res.json()) as Info
  }

  export async function token(input: {
    url: string
    fetch?: Fetch
    username?: string
    password?: string
  }) {
    const cfg = await info(input)
    if (!cfg.enabled) return
    const fetcher = input.fetch ?? globalThis.fetch
    if (cfg.methods.includes("password")) {
      const password = input.password
      if (!password) throw new Error(`This server requires username/password auth. Open ${input.url}${cfg.path} or provide a password.`)
      const res = await fetcher(new URL(`${cfg.api}/sign-in/username`, input.url), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({
          username: input.username ?? cfg.username,
          password,
        }),
      })
      const token = res.headers.get("set-auth-token")
      if (res.ok && token) return token
      throw new Error(await message(res, "Authentication failed"))
    }
    if (cfg.methods.includes("anonymous")) {
      const res = await fetcher(new URL(`${cfg.api}/sign-in/anonymous`, input.url), {
        method: "POST",
        headers: {
          accept: "application/json",
        },
      })
      const token = res.headers.get("set-auth-token")
      if (res.ok && token) return token
      throw new Error(await message(res, "Anonymous authentication failed"))
    }
    throw new Error(`This server requires browser-based authentication. Open ${input.url}${cfg.path}.`)
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
}
