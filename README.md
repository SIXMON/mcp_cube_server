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

## Configuration

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
