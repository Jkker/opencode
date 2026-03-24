import { createOpencodeClient } from "@opencode-ai/sdk/v2/client"
import type { ServerConnection } from "@/context/server"
import { authFetch } from "./server-auth"

export function createSdkForServer({
  server,
  ...config
}: Omit<NonNullable<Parameters<typeof createOpencodeClient>[0]>, "baseUrl"> & {
  server: ServerConnection.HttpBase
}) {
  const fetch = authFetch(server, config.fetch ?? globalThis.fetch) as typeof globalThis.fetch

  return createOpencodeClient({
    ...config,
    fetch,
    baseUrl: server.url,
  })
}
