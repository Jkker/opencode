import { betterAuth, type BetterAuthOptions } from "better-auth"
import { getMigrations } from "better-auth/db/migration"
import { anonymous, bearer, username } from "better-auth/plugins"
import { passkey } from "@better-auth/passkey"
import { Config } from "../config/config"
import { Global } from "../global"
import { Instance } from "../project/instance"
import { Log } from "../util/log"
import { allowOrigin } from "./origin"
import { DatabaseSync } from "node:sqlite"
import { existsSync } from "fs"
import fs from "fs/promises"
import path from "path"
import { fileURLToPath, pathToFileURL } from "url"
import crypto from "crypto"

export namespace ServerAuth {
  const log = Log.create({ service: "server-auth" })
  const methods = ["password", "passkey", "anonymous"] as const
  const page = "/_auth"
  const api = "/api/auth"

  export type Method = (typeof methods)[number]

  export interface Info {
    enabled: boolean
    methods: Method[]
    path: string
    api: string
    username: string
  }

  interface ServerModule {
    default?: (input: {
      options: BetterAuthOptions
      methods: Method[]
      directory: string
      info: Info
    }) =>
      | Promise<void | BetterAuthOptions | { options?: BetterAuthOptions; methods?: Method[] }>
      | void
      | BetterAuthOptions
      | { options?: BetterAuthOptions; methods?: Method[] }
  }

  interface State {
    auth?: ReturnType<typeof betterAuth>
    info: Info
    js?: string
  }

  type ServerPatch = { options: BetterAuthOptions; methods: Method[] }

  export function create(input: { directory: string; url: string; cors?: string[] }) {
    const state = load(input)
    return {
      state: () => state,
    }
  }

  async function load(input: { directory: string; url: string; cors?: string[] }): Promise<State> {
    const data = await Instance.provide({
      directory: input.directory,
      async fn() {
        return {
          cfg: await Config.get(),
          dirs: await Config.directories(),
        }
      },
    })
    const raw = data.cfg.server?.auth
    const legacy = process.env.OPENCODE_SERVER_PASSWORD
      ? {
          methods: ["password"] as Method[],
          username: process.env.OPENCODE_SERVER_USERNAME ?? "opencode",
          password: process.env.OPENCODE_SERVER_PASSWORD,
        }
      : undefined
    let active = (raw?.methods?.length ? raw.methods : legacy?.methods ?? []).filter((item, idx, all) => {
      return methods.includes(item) && all.indexOf(item) === idx
    }) as Method[]
    if (!active.length && raw?.password) active = ["password"]
    const info: Info = {
      enabled: active.length > 0,
      methods: active,
      path: page,
      api,
      username: raw?.username ?? legacy?.username ?? "opencode",
    }
    if (!info.enabled) return { info }
    const secret = raw?.secret ?? (await storedSecret())
    const file = authPath(raw?.database)
    await fs.mkdir(path.dirname(file), { recursive: true })
    const db = new DatabaseSync(file)
    const opts: BetterAuthOptions = {
      baseURL: input.url,
      basePath: api,
      secret,
      database: db,
      trustedOrigins(request) {
        if (!request) return raw?.trustedOrigins ?? []
        const list = new Set<string>()
        const origin = request.headers.get("origin")
        const host = request.headers.get("host")
        if (origin && allowOrigin(origin, input)) list.add(origin)
        if (host) {
          list.add(`https://${host}`)
          if (host.includes("localhost") || host.includes("127.0.0.1")) list.add(`http://${host}`)
        }
        for (const item of raw?.trustedOrigins ?? []) {
          if (item) list.add(item)
        }
        return [...list]
      },
      advanced: {
        cookies: {},
      },
      rateLimit: {
        enabled: false,
      },
      emailAndPassword: active.includes("password")
        ? {
            enabled: true,
          }
        : undefined,
      plugins: [
        bearer(),
        ...(active.includes("password") ? [username()] : []),
        ...(active.includes("anonymous") ? [anonymous()] : []),
        ...(active.includes("passkey")
          ? [
              passkey({
                rpID: raw?.passkey?.rpID ?? new URL(raw?.passkey?.origin ?? input.url).hostname,
                rpName: raw?.passkey?.rpName ?? "opencode",
                origin: raw?.passkey?.origin ?? input.url,
              }),
            ]
          : []),
      ],
    }
    const next = await patchServer({
      directory: input.directory,
      dirs: data.dirs,
      file: raw?.server,
      info,
      methods: active,
      options: opts,
    })
    info.methods = next.methods
    info.enabled = next.methods.length > 0
    if (!info.enabled) return { info }
    const auth = betterAuth(next.options)
    await getMigrations(auth.options).then((item) => item.runMigrations())
    await bootstrap({ auth, info, raw, legacy, url: input.url })
    const js = await bundle({
      directory: input.directory,
      dirs: data.dirs,
      file: raw?.client,
    })
    return { auth, info, js }
  }

  async function bootstrap(input: {
    auth: ReturnType<typeof betterAuth>
    info: Info
    url: string
    raw: NonNullable<Awaited<ReturnType<typeof Config.get>>["server"]>["auth"] | undefined
    legacy:
      | {
          methods: Method[]
          username: string
          password: string
        }
      | undefined
  }) {
    if (!input.info.methods.includes("password")) return
    const password = input.raw?.password ?? input.legacy?.password
    if (!password) throw new Error("server.auth.password is required when password authentication is enabled")
    const email = input.raw?.email ?? `${input.info.username}@opencode.local`
    const res = await input.auth.handler(
      new Request(new URL(`${api}/sign-up/email`, input.url), {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email,
          password,
          name: input.info.username,
          username: input.info.username,
          displayUsername: input.info.username,
        }),
      }),
    )
    if (res.ok) return
    const text = await res.text().catch(() => "")
    if (/exist|duplicate|taken/i.test(text)) return
    throw new Error(text || "Failed to bootstrap auth user")
  }

  async function patchServer(input: {
    directory: string
    dirs: string[]
    file?: string
    info: Info
    methods: Method[]
    options: BetterAuthOptions
  }): Promise<ServerPatch> {
    const ref = await customFile(input.directory, input.dirs, input.file, "auth-server")
    if (!ref) return { methods: input.methods, options: input.options }
    const mod = (await import(pathToFileURL(ref).href)) as ServerModule
    if (!mod.default) return { methods: input.methods, options: input.options }
    const next = await mod.default({
      options: input.options,
      methods: input.methods,
      directory: input.directory,
      info: input.info,
    })
    if (!next) return { methods: input.methods, options: input.options }
    if (isPatch(next)) {
      return {
        options: next.options ?? input.options,
        methods: (next.methods ?? input.methods).filter((item, idx, all) => methods.includes(item) && all.indexOf(item) === idx),
      }
    }
    return {
      methods: input.methods,
      options: next,
    }
  }

  function isPatch(input: unknown): input is { options?: BetterAuthOptions; methods?: Method[] } {
    return typeof input === "object" && input !== null && ("options" in input || "methods" in input)
  }

  async function bundle(input: { directory: string; dirs: string[]; file?: string }) {
    const entry =
      (await customFile(input.directory, input.dirs, input.file, "auth-client")) ??
      filePath("./auth-client.ts")
    const result = await Bun.build({
      entrypoints: [entry],
      target: "browser",
      format: "esm",
      minify: true,
    })
    if (!result.success) {
      throw new Error(result.logs.map((item) => item.message).join("\n"))
    }
    const out = result.outputs[0]
    if (!out) throw new Error("Missing auth client bundle output")
    return await out.text()
  }

  function authPath(file?: string) {
    if (!file) return path.join(Global.Path.data, "opencode-auth.db")
    if (path.isAbsolute(file)) return file
    return path.join(Global.Path.data, file)
  }

  async function storedSecret() {
    const file = path.join(Global.Path.data, "opencode-auth.secret")
    const found = existsSync(file) ? await fs.readFile(file, "utf8").catch(() => "") : ""
    if (found.trim()) return found.trim()
    const next = crypto.randomBytes(32).toString("hex")
    await fs.writeFile(file, next)
    return next
  }

  async function customFile(directory: string, dirs: string[], file: string | undefined, name: string) {
    if (file) {
      if (path.isAbsolute(file) && existsSync(file)) return file
      const hit = [directory, ...dirs]
        .map((dir) => path.join(dir, file))
        .find((item) => existsSync(item))
      if (hit) return hit
    }
    for (const dir of [directory, ...dirs]) {
      for (const ext of ["ts", "js", "mts", "mjs"]) {
        const hit = path.join(dir, `${name}.${ext}`)
        if (existsSync(hit)) return hit
      }
    }
    return
  }

  function filePath(file: string) {
    return fileURLToPath(new URL(file, import.meta.url))
  }

  export async function session(state: Promise<State>, headers: Headers) {
    const item = await state
    if (!item.auth) return
    const result = await item.auth.api.getSession({ headers }).catch((error) => {
      log.debug("failed to resolve session", { error })
      return undefined
    })
    if (!result?.session || !result?.user) return
    return result
  }

  export async function info(state: Promise<State>) {
    return (await state).info
  }

  export async function handler(state: Promise<State>, req: Request) {
    const item = await state
    if (!item.auth) return new Response("Not Found", { status: 404 })
    return item.auth.handler(req)
  }

  export async function client(state: Promise<State>) {
    const item = await state
    return new Response(item.js ?? "", {
      headers: {
        "content-type": "text/javascript; charset=utf-8",
        "cache-control": "no-store",
      },
    })
  }

  export async function html(state: Promise<State>, req: Request) {
    const item = await state
    if (!item.info.enabled) return Response.redirect(new URL("/", req.url), 302)
    const current = await session(Promise.resolve(item), req.headers)
    const redirect = new URL(req.url).searchParams.get("redirect") || "/"
    if (current) return Response.redirect(new URL(redirect, req.url), 302)
    return new Response(
      `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>opencode auth</title>
  </head>
  <body>
    <div id="root"></div>
    <script>
      window.__OPENCODE_AUTH__ = ${JSON.stringify({
        methods: item.info.methods,
        redirect,
        username: item.info.username,
      })}
    </script>
    <script type="module" src="${page}/client.js"></script>
  </body>
</html>`,
      {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
        },
      },
    )
  }
}
