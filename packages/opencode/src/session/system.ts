import { Ripgrep } from "../file/ripgrep"

import { Instance } from "../project/instance"

import PROMPT_ANTHROPIC from "./prompt/anthropic.txt"
import PROMPT_ANTHROPIC_WITHOUT_TODO from "./prompt/qwen.txt"
import PROMPT_BEAST from "./prompt/beast.txt"
import PROMPT_GEMINI from "./prompt/gemini.txt"

import PROMPT_CODEX from "./prompt/codex_header.txt"
import PROMPT_TRINITY from "./prompt/trinity.txt"
import type { Provider } from "@/provider/provider"
import type { Agent } from "@/agent/agent"
import { PermissionNext } from "@/permission"
import { Skill } from "@/skill"

export namespace SystemPrompt {
  export function instructions() {
    return PROMPT_CODEX.trim()
  }

  export function provider(model: Provider.Model) {
    if (model.api.id.includes("gpt-5")) return [PROMPT_CODEX]
    if (model.api.id.includes("gpt-") || model.api.id.includes("o1") || model.api.id.includes("o3"))
      return [PROMPT_BEAST]
    if (model.api.id.includes("gemini-")) return [PROMPT_GEMINI]
    if (model.api.id.includes("claude")) return [PROMPT_ANTHROPIC]
    if (model.api.id.toLowerCase().includes("trinity")) return [PROMPT_TRINITY]
    return [PROMPT_ANTHROPIC_WITHOUT_TODO]
  }

  export async function environment(model: Provider.Model) {
    const project = Instance.project
    return [
      [
        `You are powered by the model named ${model.api.id}. The exact model ID is ${model.providerID}/${model.api.id}`,
        `Here is some useful information about the environment you are running in:`,
        `<env>`,
        `  Working directory: ${Instance.directory}`,
        `  Workspace root folder: ${Instance.worktree}`,
        `  Is directory a git repo: ${project.vcs === "git" ? "yes" : "no"}`,
        `  Platform: ${process.platform}`,
        `  Today's date: ${new Date().toDateString()}`,
        `</env>`,
        `<directories>`,
        `  ${
          project.vcs === "git" && false
            ? await Ripgrep.tree({
                cwd: Instance.directory,
                limit: 50,
              })
            : ""
        }`,
        `</directories>`,
      ].join("\n"),
    ]
  }

  export async function skills(agent: Agent.Info) {
    if (PermissionNext.disabled(["skill"], agent.permission).has("skill")) return

    const list = await Skill.available(agent)

    return [
      "Skills provide specialized instructions and workflows for specific tasks.",
      "Use the skill tool to load a skill when a task matches its description.",
      // the agents seem to ingest the information about skills a bit better if we present a more verbose
      // version of them here and a less verbose version in tool description, rather than vice versa.
      Skill.fmt(list, { verbose: true }),
    ].join("\n")
  }

  export function resourceRef() {
    return [
      "<resource_refs>",
      "Some tool outputs are stored as resource references instead of being returned inline.",
      "Resource references use URIs with the rsrf:// scheme (e.g. rsrf://tool-name/key).",
      "",
      "There are two types of resource references:",
      "1. SENSITIVE — contains secrets, passwords, tokens, or other confidential data.",
      "   The actual content is redacted and never appears in the context window.",
      "2. OVERSIZE — contains large data that was too big to return inline.",
      "   A preview of the first few lines is shown.",
      "",
      "RULES:",
      "- Pass rsrf:// URIs directly as tool arguments. They are automatically resolved to the actual data at execution time.",
      "- NEVER attempt to read, display, echo, log, or print the contents of a SENSITIVE resource ref.",
      "- NEVER pass sensitive URIs to tools that might expose the data (e.g. do not echo them in bash).",
      "- You may refer to oversize resource refs by URI when explaining what data is available.",
      "- If a tool returns a named key (e.g. rsrf://vault/db-password), use that exact URI in subsequent tool calls.",
      "",
      "Example workflow:",
      "1. Tool A returns: rsrf://password-manager/db-pass (sensitive, redacted)",
      '2. You call Tool B with argument: { "password": "rsrf://password-manager/db-pass" }',
      "3. Tool B receives the actual password value automatically — you never see it.",
      "</resource_refs>",
    ].join("\n")
  }
}
