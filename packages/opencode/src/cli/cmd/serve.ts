import { Server } from "../../server/server"
import { cmd } from "./cmd"
import { withNetworkOptions, resolveNetworkOptions } from "../network"
import { Flag } from "../../flag/flag"
import { Workspace } from "../../control-plane/workspace"
import { Project } from "../../project/project"
import { Installation } from "../../installation"
import { Instance } from "../../project/instance"
import { Config } from "../../config/config"

export const ServeCommand = cmd({
  command: "serve",
  builder: (yargs) => withNetworkOptions(yargs),
  describe: "starts a headless opencode server",
  handler: async (args) => {
    const auth = await Instance.provide({
      directory: process.cwd(),
      fn: async () => (await Config.get()).server?.auth,
    }).catch(() => undefined)
    if (!Flag.OPENCODE_SERVER_PASSWORD && !auth?.methods?.length && !auth?.password) {
      console.log("Warning: no server auth is configured; set server.auth in opencode.json to secure this server.")
    }
    const opts = await resolveNetworkOptions(args)
    const server = Server.listen(opts)
    console.log(`opencode server listening on http://${server.hostname}:${server.port}`)

    await new Promise(() => {})
    await server.stop()
  },
})
