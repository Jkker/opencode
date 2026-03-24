export function allowOrigin(input: string | undefined, opts?: { cors?: string[] }) {
  if (!input) return
  if (input.startsWith("http://localhost:")) return input
  if (input.startsWith("http://127.0.0.1:")) return input
  if (input === "tauri://localhost" || input === "http://tauri.localhost" || input === "https://tauri.localhost") {
    return input
  }
  if (/^https:\/\/([a-z0-9-]+\.)*opencode\.ai$/.test(input)) return input
  if (opts?.cors?.includes(input)) return input
  return
}
