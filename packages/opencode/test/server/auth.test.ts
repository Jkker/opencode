import { describe, expect, test } from "bun:test"
import { Server } from "../../src/server/server"
import { tmpdir } from "../fixture/fixture"

async function text(res: Response) {
  return res.text().catch(() => "")
}

describe("Server auth", () => {
  test("password auth protects routes and accepts bearer sessions", async () => {
    await using tmp = await tmpdir({
      config: {
        server: {
          auth: {
            methods: ["password"],
            username: "solo",
            password: "secret-123",
          },
        },
      },
    })
    const app = Server.createApp({
      directory: tmp.path,
      url: "http://localhost:4096",
    })

    const blocked = await app.fetch(new Request("http://localhost:4096/config"))
    expect(blocked.status).toBe(401)

    const info = await app.fetch(new Request("http://localhost:4096/api/auth/info"))
    expect(await info.json()).toEqual({
      enabled: true,
      methods: ["password"],
      path: "/_auth",
      api: "/api/auth",
      username: "solo",
    })

    const signIn = await app.fetch(
      new Request("http://localhost:4096/api/auth/sign-in/username", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          username: "solo",
          password: "secret-123",
        }),
      }),
    )
    expect(signIn.status).toBe(200)
    const token = signIn.headers.get("set-auth-token")
    expect(token).toBeTruthy()

    const ok = await app.fetch(
      new Request("http://localhost:4096/config", {
        headers: {
          Authorization: `Bearer ${token}`,
          "x-opencode-directory": encodeURIComponent(tmp.path),
        },
      }),
    )
    expect(ok.status).toBe(200)
  })

  test("anonymous auth can create a bearer session", async () => {
    await using tmp = await tmpdir({
      config: {
        server: {
          auth: {
            methods: ["anonymous"],
          },
        },
      },
    })
    const app = Server.createApp({
      directory: tmp.path,
      url: "http://localhost:4096",
    })

    const signIn = await app.fetch(
      new Request("http://localhost:4096/api/auth/sign-in/anonymous", {
        method: "POST",
      }),
    )
    expect(signIn.status).toBe(200)
    const token = signIn.headers.get("set-auth-token")
    expect(token).toBeTruthy()

    const ok = await app.fetch(
      new Request("http://localhost:4096/path", {
        headers: {
          Authorization: `Bearer ${token}`,
          "x-opencode-directory": encodeURIComponent(tmp.path),
        },
      }),
    )
    expect(ok.status).toBe(200)
  })

  test("html requests redirect to the auth page", async () => {
    await using tmp = await tmpdir({
      config: {
        server: {
          auth: {
            methods: ["password"],
            password: "secret-123",
          },
        },
      },
    })
    const app = Server.createApp({
      directory: tmp.path,
      url: "http://localhost:4096",
    })

    const res = await app.fetch(
      new Request("http://localhost:4096/config?tab=general", {
        headers: {
          accept: "text/html",
        },
      }),
    )

    expect(res.status).toBe(302)
    expect(res.headers.get("location")).toBe("/_auth?redirect=%2Fconfig%3Ftab%3Dgeneral")

    const page = await app.fetch(new Request("http://localhost:4096/_auth"))
    expect(page.status).toBe(200)
    expect(await text(page)).toContain("/_auth/client.js")
  })
})

test("custom auth-server module can extend enabled methods", async () => {
  await using tmp = await tmpdir({
    config: {
      server: {
        auth: {
          methods: ["password"],
          password: "secret-123",
        },
      },
    },
    async init(dir) {
      await Bun.write(
        `${dir}/auth-server.ts`,
        `export default function ({ methods, options }) { return { methods: [...methods, "anonymous"], options } }`,
      )
    },
  })
  const app = Server.createApp({
    directory: tmp.path,
    url: "http://localhost:4096",
  })

  const info = await app.fetch(new Request("http://localhost:4096/api/auth/info"))
  expect(await info.json()).toEqual({
    enabled: true,
    methods: ["password", "anonymous"],
    path: "/_auth",
    api: "/api/auth",
    username: "opencode",
  })
})

test("custom auth-client module is served for the auth page", async () => {
  await using tmp = await tmpdir({
    config: {
      server: {
        auth: {
          methods: ["anonymous"],
        },
      },
    },
    async init(dir) {
      await Bun.write(`${dir}/auth-client.ts`, `console.log("custom-auth-client")`)
    },
  })
  const app = Server.createApp({
    directory: tmp.path,
    url: "http://localhost:4096",
  })

  const js = await app.fetch(new Request("http://localhost:4096/_auth/client.js"))
  expect(js.status).toBe(200)
  expect(await text(js)).toContain("custom-auth-client")
})
