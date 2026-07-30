# Cube MCP Server

[![smithery badge](https://smithery.ai/badge/@isaacwasserman/mcp_cube_server)](https://smithery.ai/server/@isaacwasserman/mcp_cube_server)

MCP Server for interacting with [Cube](https://cube.dev) semantic layers (cubes **and views**).

Adds granular discovery, full-text search, server-side filters, view surfacing,
and file output for large results.

## Tools

### Discovery

| Tool | Purpose |
|------|---------|
| `list_cubes()` | Lightweight catalog of every cube/view: `name, type, title, description, member counts, top members`. **Views are listed first.** Cheap — never dumps members. |
| `describe_cube(name)` | Full detail of one cube/view: measures (with **`agg`** = sum/avg/count/…, `type`, `format`), dimensions (with `type`, `primary_key`), plus user `meta` (e.g. `ai_context`), `folders`, and — for raw cubes — the `connectedComponent` joinability hint. |
| `search_cubes(query, top_k=8)` | Rank cubes/views for a natural-language query. Scores matches on names/titles/descriptions and member names; **curated views are boosted**. Returns candidates with a score and what matched. |
| `get_dimension_values(dimension, search?, limit=50)` | Distinct values of a dimension, ordered by frequency when a `count` measure exists. Avoids exploratory queries before filtering. |
| `describe_data()` | Alias of `list_cubes()`, kept for backward compatibility. |

> `search_cubes` is **lexical**, not semantic: it matches accent-folded, lightly de-pluralized tokens
> (FR/EN), weights cube name/title/description above member matches, and down-weights ubiquitous terms
> (IDF). It does not do cross-language or synonym matching — it returns ranked candidates that the agent
> confirms with `describe_cube`.

### `read_data(query)`

Run a Cube query. The `Query` accepts:

- `measures`, `dimensions`, `timeDimensions`, `order`, `limit`, `offset`, `ungrouped` — as before.
- **`filters`** — list of `{member, operator, values}`. Operators: `equals, notEquals, contains, notContains,
  startsWith, endsWith, gt, gte, lt, lte, set, notSet, inDateRange, notInDateRange, beforeDate, afterDate`.
- **`output`** — `{format: csv|json, to_file: bool}`. Controls how results are returned.
- **`dry_run`** — compile to SQL and list the members/cubes used **without executing** (validates the join path).

**Output behavior**

- Small results are returned **inline** as YAML.
- Large results (more than `auto_file_rows`, default **1000**, or above `max_inline_chars`) are **written to a CSV/JSON
  file** and the tool returns a compact summary: `path, rows, typed columns, aggregates, sample`. Set
  `output.to_file: true` to force this for any size. The file lives on the local filesystem (the MCP runs locally),
  so the client can read it directly.

## Authentication (Convoicar)

Convoicar auth is the **default mode** — with no configuration at all, the server talks to
`https://web.convoicar.fr`. In this mode the server is **locked**: every data tool returns an auth
error until the user logs in to Convoicar. Login is a real browser SSO (OAuth 2.1, Authorization Code + PKCE) on
Convoicar's own login page — the MCP never sees the password.

- **Log in**: run the `login` tool from Claude, or the `mcp-cube-login` command in a terminal. A browser
  opens; after login a branded confirmation page appears (it closes itself after 5 s) and the tools unlock.
- **Log out**: the `logout` tool, or `mcp-cube-login --logout`.
- After login, the MCP exchanges its token for a short-lived, **server-signed Cube JWT** via
  `GET /api/v2/mcp/session` on Convoicar. That JWT carries the user's security context
  (`user_id, email, super_admin, roles, account_ids`). **The Cube signing secret stays on the Convoicar
  server** and is never present on the user's machine.
- Tokens are cached at `~/.config/convoicar-mcp/credentials.json` (mode `0600`) and refreshed automatically.

Auth-mode configuration (env) — **all optional**:

- `CONVOICAR_AUTH` — `1`/`0` to force auth mode on or off. Unset (default): auth mode, unless local
  Cube credentials are supplied (see [standalone](#configuration-standalone--dev-no-auth)).
- `CONVOICAR_URL` — base URL of Convoicar. Default `https://web.convoicar.fr`; override for staging/dev.
- `CONVOICAR_OAUTH_CLIENT_ID` — default `mcp-cube-public-client`.
- `CONVOICAR_OAUTH_PORT` — loopback port for the login callback (default `47823`).

> Server-side prerequisite: Convoicar must expose the OAuth provider and set `CUBE_API_SECRET` +
> `CUBE_ENDPOINT` in its environment, and the public client must be provisioned once per environment
> with `rails convoicar:oauth:setup_mcp_client`.

## Install in Claude Desktop (edit `claude_desktop_config.json`)

Add the server by hand to Claude Desktop's config file, then restart Claude Desktop.

Open **Settings → Developer → Edit Config** (or edit the file directly):

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Add a `convoicar-cube` entry under `mcpServers` (create the file / key if absent). No `env` block is
needed — auth mode and `https://web.convoicar.fr` are the defaults:

```json
{
  "mcpServers": {
    "convoicar-cube": {
      "command": "uvx",
      "args": ["--from", "/absolute/path/to/mcp_cube_server", "mcp_cube_server"]
    }
  }
}
```

To point at another environment, add `"env": { "CONVOICAR_URL": "https://staging.convoicar.fr" }`.

Then restart Claude Desktop and run the `login` tool (a browser opens; a branded Convoicar page
confirms and auto-closes).

> Prerequisites on the user's machine: **`uv` on `PATH`** (provides `uvx`) and **Python 3.11+**.
> On Windows, `uvx` is typically at `C:\Users\<you>\.local\bin\uvx.exe`; give the full path if it is
> not on `PATH`. To pin a published revision instead of a local checkout, use
> `"--from", "git+https://github.com/<org>/mcp_cube_server@<sha>"`.

## Configuration (standalone / dev, no auth)

Supplying **both** Cube credentials below (via env or CLI flag) switches the server to standalone
mode: it signs the Cube JWT itself and never contacts Convoicar. `CONVOICAR_AUTH=1` overrides this
and keeps auth mode; `CONVOICAR_AUTH=0` requires the two credentials and errors out without them.

Credentials (env or CLI flag):

- `--endpoint` / `CUBE_ENDPOINT` — e.g. `http://localhost:4000/cubejs-api/v1`
- `--api_secret` / `CUBE_API_SECRET` — signs the JWT
- `CUBE_TOKEN_PAYLOAD` — optional JSON claims; extra `--key value` flags are merged into the token payload

Output tuning (env or CLI flag):

- `--output_dir` / `CUBE_OUTPUT_DIR` — where result files are written (default: a temp dir)
- `--auto_file_rows` / `CUBE_AUTO_FILE_ROWS` — row threshold for file mode (default `1000`)
- `--max_inline_chars` / `CUBE_MAX_INLINE_CHARS` — size threshold for file mode (default `100000`)

### Add to Claude Code

```bash
claude mcp add cube -s project -- \
  uvx --from /path/to/mcp_cube_server mcp_cube_server \
  --endpoint http://localhost:4000/cubejs-api/v1 \
  --api_secret <CUBEJS_API_SECRET>
```

## Resources

- `context://data_description` — the lightweight catalog (application-controlled version of `list_cubes`).
