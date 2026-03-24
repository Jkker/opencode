import { createAuthClient } from "better-auth/client"
import { anonymousClient, usernameClient } from "better-auth/client/plugins"
import { passkeyClient } from "@better-auth/passkey/client"

declare global {
  interface Window {
    __OPENCODE_AUTH__?: {
      methods: string[]
      redirect: string
      username: string
    }
  }
}

const cfg = window.__OPENCODE_AUTH__ ?? {
  methods: [],
  redirect: "/",
  username: "opencode",
}

const auth = createAuthClient({
  plugins: [anonymousClient(), usernameClient(), passkeyClient()],
})

const root = document.getElementById("root")
if (!root) throw new Error("Missing auth root")

const css = document.createElement("style")
css.textContent = `
  :root {
    color-scheme: dark;
    font-family: Inter, ui-sans-serif, system-ui, sans-serif;
    background: #09090b;
    color: #fafafa;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    background: radial-gradient(circle at top, #18181b, #09090b 60%);
  }
  .card {
    width: min(28rem, calc(100vw - 2rem));
    border: 1px solid #27272a;
    border-radius: 1rem;
    background: rgba(24, 24, 27, 0.92);
    box-shadow: 0 20px 80px rgba(0, 0, 0, 0.45);
    padding: 1.5rem;
    display: grid;
    gap: 1rem;
  }
  h1 {
    margin: 0;
    font-size: 1.5rem;
  }
  p {
    margin: 0;
    color: #a1a1aa;
    line-height: 1.5;
  }
  form, .stack {
    display: grid;
    gap: 0.75rem;
  }
  label {
    display: grid;
    gap: 0.35rem;
    font-size: 0.9rem;
    color: #d4d4d8;
  }
  input {
    width: 100%;
    border: 1px solid #3f3f46;
    border-radius: 0.75rem;
    background: #09090b;
    color: #fafafa;
    padding: 0.75rem 0.9rem;
    font: inherit;
  }
  button {
    width: 100%;
    border: 0;
    border-radius: 0.75rem;
    background: #fafafa;
    color: #09090b;
    padding: 0.8rem 1rem;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }
  button.alt {
    background: #18181b;
    color: #fafafa;
    border: 1px solid #3f3f46;
  }
  button:disabled {
    opacity: 0.6;
    cursor: wait;
  }
  .err {
    min-height: 1.25rem;
    color: #fda4af;
    font-size: 0.9rem;
  }
  .sep {
    height: 1px;
    background: #27272a;
    margin: 0.25rem 0;
  }
`
document.head.append(css)

const card = document.createElement("div")
card.className = "card"
root.append(card)

const title = document.createElement("h1")
title.textContent = "Sign in to opencode"
card.append(title)

const copy = document.createElement("p")
copy.textContent = "Authenticate with a configured sign-in method to continue."
card.append(copy)

const err = document.createElement("div")
err.className = "err"
card.append(err)

const setBusy = (state: boolean) => {
  card.querySelectorAll("button, input").forEach((el) => {
    ;(el as HTMLButtonElement | HTMLInputElement).disabled = state
  })
}

const done = () => {
  window.location.href = cfg.redirect || "/"
}

const fail = (error: unknown) => {
  setBusy(false)
  err.textContent = error instanceof Error ? error.message : String(error)
}

const line = document.createElement("div")
line.className = "stack"
card.append(line)

if (cfg.methods.includes("password")) {
  const form = document.createElement("form")
  form.innerHTML = `
    <label>
      Username
      <input id="username" name="username" autocomplete="username webauthn" />
    </label>
    <label>
      Password
      <input id="password" name="password" type="password" autocomplete="current-password" />
    </label>
    <button type="submit">Continue with password</button>
  `
  const user = form.querySelector("#username") as HTMLInputElement
  user.value = cfg.username
  form.addEventListener("submit", async (event) => {
    event.preventDefault()
    err.textContent = ""
    setBusy(true)
    try {
      await auth.signIn.username({
        username: user.value,
        password: (form.querySelector("#password") as HTMLInputElement).value,
        fetchOptions: {
          onSuccess() {
            done()
          },
        },
      })
    } catch (error) {
      fail(error)
    }
  })
  line.append(form)
}

if (cfg.methods.includes("passkey")) {
  const btn = document.createElement("button")
  btn.type = "button"
  btn.className = cfg.methods.includes("password") ? "alt" : ""
  btn.textContent = "Continue with passkey"
  btn.addEventListener("click", async () => {
    err.textContent = ""
    setBusy(true)
    try {
      await auth.signIn.passkey({
        fetchOptions: {
          onSuccess() {
            done()
          },
        },
      })
    } catch (error) {
      fail(error)
    }
  })
  if (line.childElementCount) {
    const sep = document.createElement("div")
    sep.className = "sep"
    line.append(sep)
  }
  line.append(btn)
}

if (cfg.methods.includes("anonymous")) {
  const btn = document.createElement("button")
  btn.type = "button"
  btn.className = cfg.methods.includes("password") || cfg.methods.includes("passkey") ? "alt" : ""
  btn.textContent = "Continue anonymously"
  btn.addEventListener("click", async () => {
    err.textContent = ""
    setBusy(true)
    try {
      await auth.signIn.anonymous({
        fetchOptions: {
          onSuccess() {
            done()
          },
        },
      })
    } catch (error) {
      fail(error)
    }
  })
  if (line.childElementCount) {
    const sep = document.createElement("div")
    sep.className = "sep"
    line.append(sep)
  }
  line.append(btn)
}

if (cfg.methods.length === 1 && cfg.methods[0] === "anonymous") {
  queueMicrotask(() => {
    ;(line.querySelector("button") as HTMLButtonElement | null)?.click()
  })
}
