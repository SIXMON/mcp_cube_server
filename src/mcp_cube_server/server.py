from __future__ import annotations
from typing import Any, Literal, Optional, Union
from mcp.server.fastmcp import FastMCP
import jwt
from pydantic import BaseModel, Field
import requests
import json
import logging
import functools
import yaml
import uuid
import time
import os
import re
import csv
import math
import difflib
import tempfile
import unicodedata


def data_to_yaml(data: Any) -> str:
    return yaml.dump(data, indent=2, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Text utilities for search (accent-folding, tokenization)
# ---------------------------------------------------------------------------
def _fold(text: Optional[str]) -> str:
    """Lowercase and strip diacritics so 'référence' matches 'reference'."""
    if not text:
        return ""
    norm = unicodedata.normalize("NFKD", text)
    return norm.encode("ascii", "ignore").decode("ascii").lower()


def _stem(token: str) -> str:
    """Crude, language-agnostic de-pluralization, applied to BOTH index and query

    - '-es' after a sibilant (s/x/z) → drop 'es' (statuses->status, boxes->box, addresses->address)
    - trailing 's'/'x' on tokens >= 4 chars → drop it (orders->order, status->statu)
    Deliberately applied symmetrically: it trades a little precision for recall, which is the right
    bias for a lexical search that an agent then narrows with describe_cube()."""
    if len(token) >= 5 and token.endswith("es") and token[-3] in "sxz":
        token = token[:-2]
    if len(token) >= 4 and token[-1] in ("s", "x"):
        token = token[:-1]
    return token


def _terms(text: Optional[str]) -> set[str]:
    return {_stem(t) for t in re.findall(r"[a-z0-9]+", _fold(text))}


# Common French/English function words that match almost everything and only add noise to search.
_STOPWORDS = {
    "de", "des", "du", "le", "la", "les", "un", "une", "et", "ou", "au", "aux", "en", "par", "pour",
    "sur", "dans", "avec", "sans", "ce", "ces", "cet", "cette", "son", "sa", "ses", "mon", "ma", "mes",
    "ton", "ta", "tes", "qui", "que", "quoi", "dont", "est", "ne", "pas", "plus", "moins", "chaque",
    "tous", "toute", "toutes", "tout", "vs", "via", "selon", "entre",
    "the", "of", "by", "per", "for", "to", "in", "on", "and", "or", "an", "is", "are", "as", "at",
    "with", "without", "from", "each", "all", "into", "over",
}


def _query_terms(query: str) -> set[str]:
    """Tokenize a search query, dropping 1-char tokens and stopwords.

    Returns an empty set for an all-stopword query (so search reports 'no match, reformulate'
    rather than matching boilerplate everywhere)."""
    return {t for t in _terms(query) if len(t) >= 2 and t not in _STOPWORDS}


class CubeClient:
    Route = Literal["meta", "load", "sql"]
    max_wait_time = 10
    request_backoff = 1
    request_timeout = 30  # seconds — avoid indefinite hangs (cf. ebragas fork)
    token_ttl = 3600  # seconds — generated tokens carry iat/exp
    meta_ttl = 60  # seconds — /meta is cached to avoid a round-trip on every tool call

    def __init__(self, endpoint: Optional[str], api_secret: Optional[str], token_payload: dict,
                 logger: logging.Logger, auth=None):
        # In auth mode (`auth` set) the Cube endpoint and JWT come from the auth server per-user,
        # so this client never holds the Cube signing secret. In dev/standalone mode it signs
        # locally with `api_secret`, as before.
        self.auth = auth
        self._static_endpoint = endpoint
        self.api_secret = api_secret
        self.token_payload = token_payload or {}
        self.token = None
        self.logger = logger
        self._meta_cache: Optional[dict] = None
        self._meta_at = 0.0
        if self.auth is None:
            self._refresh_token()
            meta = self._fetch_meta()
            if meta.get("error"):
                logger.warning("Cube /meta unavailable at startup: %s", meta.get("error"))

    # -- auth ----------------------------------------------------------------
    def _generate_token(self):
        payload = dict(self.token_payload)
        if "exp" not in payload:  # don't override a caller-supplied expiry
            now = int(time.time())
            payload.setdefault("iat", now)
            payload["exp"] = now + self.token_ttl
        return jwt.encode(payload, self.api_secret, algorithm="HS256")

    def _refresh_token(self):
        if self.auth is not None:
            self.auth.invalidate_cube()  # force a fresh Cube token from the auth server on next call
        else:
            self.token = self._generate_token()

    def _endpoint(self) -> str:
        return self.auth.cube_endpoint() if self.auth is not None else (self._static_endpoint or "")

    def _auth_value(self) -> str:
        return self.auth.cube_token() if self.auth is not None else (self.token or "")

    # -- http ----------------------------------------------------------------
    @staticmethod
    def _parse(response) -> dict:
        """Parse a response body as JSON once, degrading gracefully on non-JSON bodies."""
        try:
            return response.json()
        except ValueError:
            return {"error": f"Non-JSON response (HTTP {response.status_code})", "body": response.text[:500]}

    def _request(self, route: "CubeClient.Route", **params) -> dict:
        request_time = time.time()
        headers = {"Authorization": self._auth_value()}
        url = f"{self._endpoint().rstrip('/')}/{route}"
        serialized_params = {k: json.dumps(v) for k, v in params.items()}

        try:
            response = requests.get(url, headers=headers, params=serialized_params, timeout=self.request_timeout)
            payload = self._parse(response)

            # Handle "continue wait" responses
            while payload.get("error") == "Continue wait":
                if time.time() - request_time > self.max_wait_time:
                    self.logger.error("Request timed out after %ss", self.max_wait_time)
                    return {"error": "Request timed out. The request may be too complex."}
                self.logger.warning("Request incomplete, polling again in %ss", self.request_backoff)
                time.sleep(self.request_backoff)
                response = requests.get(url, headers=headers, params=serialized_params, timeout=self.request_timeout)
                payload = self._parse(response)

            # 401/403 is usually an auth problem (expired/missing token or missing security-context
            # claim), not an expiry of the query. Refresh the token (in auth mode this re-fetches a
            # fresh Cube JWT from the auth server) and retry once; if it still fails the caller sees the error.
            if response.status_code in (401, 403):
                self.logger.warning("%s from Cube — refreshing token and retrying once", response.status_code)
                self._refresh_token()
                headers = {"Authorization": self._auth_value()}
                url = f"{self._endpoint().rstrip('/')}/{route}"
                response = requests.get(url, headers=headers, params=serialized_params, timeout=self.request_timeout)
                payload = self._parse(response)

            if response.status_code != 200 and "error" not in payload:
                payload = {"error": f"HTTP {response.status_code}", "body": response.text[:500]}
            return payload

        except Exception as e:
            # A requests exception embeds the full request URL — and the query, filter values
            # included, travels as a URL parameter. The exception type plus the route says what
            # broke without writing business data to a log that outlives the request.
            self.logger.error("Request to %s failed: %s", route, type(e).__name__)
            self.logger.debug("Request failure detail: %s", e)
            return {"error": f"Request failed: {e}"}

    # -- meta (cached) -------------------------------------------------------
    def _fetch_meta(self) -> dict:
        meta = self._request("meta")
        self._meta_cache = meta
        self._meta_at = time.time()
        return meta

    def describe(self, refresh: bool = False) -> dict:
        if refresh or self._meta_cache is None or (time.time() - self._meta_at) > self.meta_ttl:
            return self._fetch_meta()
        return self._meta_cache

    def cubes(self, refresh: bool = False) -> list[dict]:
        """Cubes AND views from /meta (views carry type == 'view'), cached for meta_ttl seconds."""
        meta = self.describe(refresh=refresh)
        if meta.get("error"):
            return []
        return meta.get("cubes", [])

    def measure_agg(self, refresh: bool = False) -> dict[str, Optional[str]]:
        """Map measure name -> aggType from /meta (the /load annotation omits aggType)."""
        out: dict[str, Optional[str]] = {}
        for entry in self.cubes(refresh=refresh):
            for m in entry.get("measures", []):
                if m.get("name"):
                    out[m["name"]] = m.get("aggType")
        return out

    def sql(self, query: dict) -> dict:
        """Compile a query to SQL without executing it (dry-run / validation)."""
        return self._request("sql", query=query)

    def _cast_numerics(self, response: dict) -> dict:
        if response.get("data") and response.get("annotation"):
            numeric_keys = set()
            dimensions_and_measures = dict(
                response["annotation"].get("dimensions", {}), **response["annotation"].get("measures", {})
            )
            for column_name, column in dimensions_and_measures.items():
                if column.get("type") == "number":
                    numeric_keys.add(column_name)
            for row in response["data"]:
                for key in numeric_keys:
                    try:
                        row[key] = float(row[key])
                        if row[key].is_integer():
                            row[key] = int(row[key])
                    except (ValueError, TypeError):
                        pass
        return response

    def query(self, query: dict, cast_numerics: bool = True) -> dict:
        response = self._request("load", query=query)
        if cast_numerics:
            response = self._cast_numerics(response)
        return response

    def query_paginated(self, query: dict, page_size: int, max_rows: int, cast_numerics: bool = True) -> dict:
        """Fetch a large result by paging on offset, transparently working around Cube's per-query
        row cap. Honors the query's `limit` (None = fetch all up to max_rows) and starting `offset`.
        Returns {data, annotation, truncated} or {error} (with partial data if a later page failed)."""
        base = {k: v for k, v in query.items() if k not in ("limit", "offset")}
        requested = query.get("limit")
        offset = query.get("offset") or 0
        all_data: list[dict] = []
        annotation: dict = {}
        truncated = False
        while True:
            page_limit = page_size
            if requested is not None:
                remaining = requested - len(all_data)
                if remaining <= 0:
                    break
                page_limit = min(page_size, remaining)
            page_limit = min(page_limit, max(1, max_rows - len(all_data)))
            resp = self.query({**base, "limit": page_limit, "offset": offset}, cast_numerics)
            if resp.get("error"):
                if all_data:
                    return {"data": all_data, "annotation": annotation, "truncated": True, "error": resp["error"]}
                return {"error": resp["error"]}
            page = resp.get("data", [])
            annotation = resp.get("annotation") or annotation
            all_data.extend(page)
            if len(page) < page_limit:  # last page reached
                break
            offset += len(page)
            if len(all_data) >= max_rows:
                truncated = True
                break
        return {"data": all_data, "annotation": annotation, "truncated": truncated}


# ---------------------------------------------------------------------------
# Query models
# ---------------------------------------------------------------------------
class TimeDimension(BaseModel):
    dimension: str = Field(..., description="Name of the time dimension")
    granularity: Optional[Literal["second", "minute", "hour", "day", "week", "month", "quarter", "year"]] = Field(
        None,
        description="Time bucket to group by (e.g. 'month'). OMIT it to use this time dimension as a "
        "period filter only (via dateRange) without grouping or adding a column.",
    )
    dateRange: Union[list[str], str] = Field(
        ...,
        description="Pair of ISO dates [start, end], or a relative range string: 'last N days', 'today', 'yesterday', 'last year', etc.",
    )

    model_config = {"extra": "forbid"}


class Filter(BaseModel):
    member: str = Field(..., description="Dimension or measure to filter on, e.g. 'orders.status'")
    operator: Literal[
        "equals",
        "notEquals",
        "contains",
        "notContains",
        "startsWith",
        "endsWith",
        "gt",
        "gte",
        "lt",
        "lte",
        "set",
        "notSet",
        "inDateRange",
        "notInDateRange",
        "beforeDate",
        "afterDate",
    ] = Field("equals", description="Filter operator (Cube REST semantics)")
    values: Optional[list[Union[str, int, float, bool]]] = Field(
        None, description="Values for the filter. Omit for 'set'/'notSet'."
    )

    model_config = {"extra": "forbid"}


class OutputOptions(BaseModel):
    format: Literal["csv", "json"] = Field("csv", description="File format when results are written to disk.")
    to_file: bool = Field(
        False,
        description="Force writing the full result to a file and returning only a compact summary. "
        "Large results are written to a file automatically even when this is false.",
    )

    model_config = {"extra": "forbid"}


class Query(BaseModel):
    measures: list[str] = Field([], description="Names of measures to query")
    dimensions: list[str] = Field([], description="Names of dimensions to group by")
    timeDimensions: list[TimeDimension] = Field([], description="Time dimensions to group by")
    filters: list[Filter] = Field([], description="Filters applied server-side (member/operator/values)")
    limit: Optional[int] = Field(
        500,
        description="Max rows. Defaults to 500. Set higher (or null) to export more: results beyond "
        "Cube's per-query cap are paginated transparently into a single file.",
    )
    offset: Optional[int] = Field(0, description="Number of rows to skip. Defaults to 0")
    order: dict[str, Literal["asc", "desc"]] = Field(
        {}, description="Optional ordering of the results. The order is sensitive to the order of keys."
    )
    ungrouped: bool = Field(
        False,
        description="Return ungrouped rows instead of grouping by dimensions. Useful to fetch a single row by id.",
    )
    output: Optional[OutputOptions] = Field(
        None, description="Control how the result is returned (inline vs written to a file)."
    )
    dry_run: bool = Field(
        False,
        description="Do not execute: return the compiled SQL and the cubes/members used, to validate joins and gauge the query.",
    )

    model_config = {"extra": "forbid"}

    @staticmethod
    def _coerce_value(v):
        # Cube REST expects filter values as strings; normalize Python bools to JSON-style.
        if isinstance(v, bool):
            return "true" if v else "false"
        return v if isinstance(v, str) else str(v)

    def cube_query(self) -> dict:
        """Build the dict sent to Cube (excludes MCP-only options like output/dry_run)."""
        q: dict[str, Any] = {}
        if self.measures:
            q["measures"] = self.measures
        if self.dimensions:
            q["dimensions"] = self.dimensions
        if self.timeDimensions:
            q["timeDimensions"] = [td.model_dump(exclude_none=True) for td in self.timeDimensions]
        if self.filters:
            filters = []
            for f in self.filters:
                fd: dict[str, Any] = {"member": f.member, "operator": f.operator}
                if f.values is not None:
                    fd["values"] = [self._coerce_value(v) for v in f.values]
                filters.append(fd)
            q["filters"] = filters
        # Cube treats limit:0 as "zero rows"; omit non-positive limits so Cube uses its default.
        if self.limit is not None and self.limit > 0:
            q["limit"] = self.limit
        if self.offset and self.offset > 0:
            q["offset"] = self.offset
        if self.order:
            q["order"] = self.order
        if self.ungrouped:
            q["ungrouped"] = True
        return q


# ---------------------------------------------------------------------------
# Meta helpers (shared by discovery tools)
# ---------------------------------------------------------------------------
def _entry_type(entry: dict) -> str:
    """'view' or 'cube'. Cube's /meta tags views with type == 'view'."""
    return "view" if entry.get("type") == "view" else "cube"


def _member_title(m: dict) -> Optional[str]:
    return m.get("shortTitle") or m.get("title")


def _clean(d: dict) -> dict:
    """Drop None values so the YAML stays terse (no 'agg: null', 'format: null')."""
    return {k: v for k, v in d.items() if v is not None}


def _truncate(text: Optional[str], n: int = 160) -> Optional[str]:
    if not text:
        return text
    text = " ".join(text.split())  # collapse whitespace/newlines
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def _catalog(cubes: list[dict]) -> list[dict]:
    """Lightweight catalog: one small entry per cube/view, views first.

    Descriptions are truncated and member lists reduced to counts so the whole catalog stays well
    under the token limit even for large models (call describe_cube for the full detail of one)."""
    out = []
    for entry in cubes:
        out.append(
            _clean(
                {
                    "name": entry.get("name"),
                    "type": _entry_type(entry),
                    "title": entry.get("title"),
                    "description": _truncate(entry.get("description")),
                    "measures": len(entry.get("measures", [])),
                    "dimensions": len(entry.get("dimensions", [])),
                }
            )
        )
    # views first, then alphabetical
    out.sort(key=lambda e: (e["type"] != "view", e["name"] or ""))
    return out


def _describe_one(entry: dict) -> dict:
    """Full detail for a single cube/view."""
    etype = _entry_type(entry)
    desc: dict[str, Any] = {
        "name": entry.get("name"),
        "type": etype,
        "title": entry.get("title"),
        "description": entry.get("description"),
        "public": entry.get("public"),
    }
    if entry.get("meta"):
        desc["meta"] = entry.get("meta")  # user-defined meta, e.g. ai_context
    if entry.get("folders"):
        desc["folders"] = entry.get("folders")
    if entry.get("hierarchies"):
        desc["hierarchies"] = entry.get("hierarchies")
    if etype == "cube" and entry.get("connectedComponent") is not None:
        # Joinability hint: cubes sharing this value have at least one join path.
        desc["connectedComponent"] = entry.get("connectedComponent")
        desc["joins_hint"] = (
            "To combine this cube with another (e.g. group a measure here by a dimension of another "
            "cube), just list members from both cubes in ONE read_data call — Cube auto-resolves the "
            "join when they share the same connectedComponent. Use dry_run to see/confirm the join path."
        )
    desc["measures"] = [
        _clean(
            {
                "name": m.get("name"),
                "title": _member_title(m),
                "description": m.get("description"),
                "agg": m.get("aggType"),
                "type": m.get("type"),
                "format": m.get("format"),
            }
        )
        for m in entry.get("measures", [])
    ]
    desc["dimensions"] = [
        _clean(
            {
                "name": d.get("name"),
                "title": _member_title(d),
                "description": d.get("description"),
                "type": d.get("type"),
                "primary_key": d.get("primaryKey"),
            }
        )
        for d in entry.get("dimensions", [])
    ]
    if entry.get("segments"):
        desc["segments"] = [{"name": s.get("name"), "title": _member_title(s)} for s in entry.get("segments", [])]
    return _clean(desc)


def _search(cubes: list[dict], query: str, top_k: int) -> list[dict]:
    """Weighted full-text scoring over cubes/views and their members.

    Scored per query TERM (not per member) so wide cubes don't accumulate noise, with cube-level
    fields weighted far above member-level ones. Curated views are boosted.
    """
    qterms = _query_terms(query)
    if not qterms:
        return []

    # Per-cube term sets (cube-level + members), computed once.
    indexed = []
    for entry in cubes:
        name_t = _terms(entry.get("name"))
        title_t = _terms(entry.get("title"))
        desc_t = _terms(entry.get("description"))
        mem_name_idx: dict[str, str] = {}
        mem_desc_idx: dict[str, str] = {}
        for kind in ("measures", "dimensions"):
            for m in entry.get(kind, []):
                mname = m.get("name")
                for t in _terms(m.get("name")) | _terms(m.get("title")) | _terms(m.get("shortTitle")):
                    mem_name_idx.setdefault(t, mname)
                for t in _terms(m.get("description")):
                    mem_desc_idx.setdefault(t, mname)
        indexed.append((entry, name_t, title_t, desc_t, mem_name_idx, mem_desc_idx))

    # IDF weight per query term: a term present in many cubes is downweighted toward 0; a rare term keeps weight ~1.
    n = max(1, len(cubes))
    denom = math.log(n + 1)
    df = {t: 0 for t in qterms}
    for _, name_t, title_t, desc_t, mni, mdi in indexed:
        present = name_t | title_t | desc_t | set(mni) | set(mdi)
        for t in qterms:
            if t in present:
                df[t] += 1
    idf = {t: (math.log((n + 1) / (df[t] + 1)) / denom if denom else 1.0) for t in qterms}

    results = []
    for entry, name_t, title_t, desc_t, mem_name_idx, mem_desc_idx in indexed:
        score = 0.0
        matched_on: set[str] = set()
        for t in qterms:
            w = idf[t]
            # cube-level: take the single strongest field for this term
            if t in name_t:
                score += 6 * w
                matched_on.add("name")
            elif t in title_t:
                score += 5 * w
                matched_on.add("title")
            elif t in desc_t:
                score += 2 * w
                matched_on.add("description")
            # member-level: counted once per term, low weight
            if t in mem_name_idx:
                score += 2 * w
                matched_on.add(f"member:{mem_name_idx[t]}")
            elif t in mem_desc_idx:
                score += 0.5 * w
                matched_on.add(f"member:{mem_desc_idx[t]}")

        if score <= 0:
            continue
        etype = _entry_type(entry)
        if etype == "view":
            score *= 1.5  # prefer curated views when relevance is comparable
        snippet = (entry.get("description") or entry.get("title") or "")[:200]
        results.append(
            {
                "name": entry.get("name"),
                "type": etype,
                "score": round(score, 2),
                "matched_on": sorted(matched_on)[:6],
                "snippet": snippet,
            }
        )
    results.sort(key=lambda r: (-r["score"], r["type"] != "view", r["name"]))
    return results[:top_k]


# Aggregation types for which summing per-group values yields a meaningful grand total.
_ADDITIVE_AGG = {"sum", "count"}


def _column_order(annotation: dict, data: list[dict], fallback: list[str]) -> list[str]:
    """Stable, complete column order: annotation order first, then any extra keys seen in the data.

    Built from the union of all rows' keys (not just data[0]) so heterogeneous rows never lose columns."""
    ann_order = [
        *annotation.get("dimensions", {}),
        *annotation.get("timeDimensions", {}),
        *annotation.get("measures", {}),
    ]
    seen = {k: None for row in data for k in row}  # dict preserves first-seen order (deterministic)
    if not seen:
        return [c for c in (ann_order or fallback) if c]
    # 1) columns the caller explicitly requested, in their order; 2) remaining annotation order; 3) extras.
    ordered = [c for c in fallback if c in seen]
    ordered += [c for c in ann_order if c in seen and c not in ordered]
    ordered += [k for k in seen if k not in ordered]
    return ordered


def _columns(annotation: dict, order: list[str], agg_map: dict) -> list[dict]:
    """Typed column list for a result. aggType comes from /meta (the /load annotation omits it)."""
    dims = annotation.get("dimensions", {})
    meas = annotation.get("measures", {})
    tds = annotation.get("timeDimensions", {})
    cols = []
    for k in order:
        ann = dims.get(k) or meas.get(k) or tds.get(k) or {}
        col = {"name": k, "type": ann.get("type")}
        agg = ann.get("aggType") or agg_map.get(k)
        if agg:
            col["agg"] = agg
        cols.append(col)
    return cols


def _aggregates(data: list[dict], annotation: dict, agg_map: dict) -> dict:
    """Descriptive stats per numeric measure column. `sum` is reported ONLY for additive measures
    (sum/count); for avg/ratio/countDistinct/etc. summing would be misleading, so only min/max/count."""
    out = {}
    for col in annotation.get("measures", {}):
        nums = [r[col] for r in data if isinstance(r.get(col), (int, float)) and not isinstance(r.get(col), bool)]
        if not nums:
            continue
        stats = {"min": min(nums), "max": max(nums), "count": len(nums)}
        if agg_map.get(col) in _ADDITIVE_AGG:
            stats["sum"] = sum(nums)
        out[col] = stats
    return out


def _redact_filters(filters: list) -> list:
    """Strip the values out of a filter list, keeping member and operator.

    Filter values are business data — a customer name, an email, an id — and logs outlive the
    request: they go to stderr (captured by the MCP client) and to --log_dir. Member names and
    operators are enough to reconstruct what a query did.
    """
    out = []
    for entry in filters or []:
        if not isinstance(entry, dict):
            continue
        if "and" in entry or "or" in entry:  # Cube's boolean groups nest filter lists
            out.append({k: _redact_filters(v) if k in ("and", "or") else v for k, v in entry.items()})
            continue
        safe = {k: v for k, v in entry.items() if k != "values"}
        values = entry.get("values")
        if values is not None:
            safe["values"] = f"<{len(values)} redacted>"
        out.append(safe)
    return out


def _loggable_query(cube_query: dict) -> str:
    """Serialize a query for the log: full structure, no filter values."""
    safe = dict(cube_query)
    if safe.get("filters"):
        safe["filters"] = _redact_filters(safe["filters"])
    return json.dumps(safe)


def _write_result_file(data: list[dict], col_order: list[str], output_dir: str, fmt: str) -> str:
    """Write the full result to disk (csv/json) and return the absolute path.
    Results may contain sensitive data, so the directory is 0o700 and files 0o600."""
    os.makedirs(output_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(output_dir, 0o700)  # tighten even if the dir pre-existed
    except OSError:
        pass
    data_id = uuid.uuid4().hex[:12]
    path = os.path.join(output_dir, f"cube_{data_id}.{fmt}")
    # Create with restrictive perms before writing.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        if fmt == "csv":
            w = csv.DictWriter(f, fieldnames=col_order, extrasaction="ignore")
            w.writeheader()
            w.writerows(data)
        else:
            json.dump(data, f, ensure_ascii=False)
    return os.path.abspath(path)


def _explain_error(error) -> str:
    """Turn opaque Cube errors into actionable guidance for an agent."""
    e = str(error)
    low = e.lower()
    if "limit" in low and "exceed" in low:
        return (
            e + " — Cube caps the number of rows per single query. Set a higher `limit` "
            "(or `limit: null` for all rows): read_data paginates past the cap and writes one file."
        )
    return e


def main(credentials, logger, config=None, auth=None):
    config = config or {}
    output_dir = config.get("output_dir") or os.path.join(tempfile.gettempdir(), "mcp_cube_exports")
    auto_file_rows = int(config.get("auto_file_rows", 1000))
    max_inline_chars = int(config.get("max_inline_chars", 100_000))
    sample_rows = int(config.get("sample_rows", 20))
    page_size = int(config.get("page_size", 50_000))  # stays under Cube's per-query row cap
    max_export_rows = int(config.get("max_export_rows", 1_000_000))  # safety ceiling for a single export

    mcp = FastMCP("Cube")
    client = CubeClient(**credentials, logger=logger, auth=auth)

    # Gate: when authentication is enabled, no data tool runs until the user has logged in.
    # Applied as the inner decorator so the tool FastMCP registers is the gated one.
    def require_auth(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if auth is not None and not auth.is_authenticated():
                return auth.auth_error()
            return fn(*args, **kwargs)
        return wrapper

    # -- authentication tools -------------------------------------------------
    @mcp.tool("login")
    def login() -> str:
        """Log in via your browser (SSO). Required before any data tool will run.
        Returns the login link and opens it automatically when this machine allows it; the login
        then completes on its own, so always show the user the link rather than waiting here."""
        if auth is None:
            return "Authentication is disabled on this server (local/dev mode) — data tools are open."
        if auth.is_authenticated():
            user = auth.user() or {}
            who = user.get("email") or user.get("name") or "this account"
            return f"Already logged in as {who}. Call `logout` first to switch account."
        try:
            info = auth.begin_login()
        except Exception as e:  # noqa: BLE001 — surface the reason to the user
            return f"Login failed: {e}"
        # The URL is always returned: MCP clients start the server with a stripped environment,
        # so the automatic browser launch cannot be relied on (and is impossible in a container).
        head = (
            "Your browser should have opened on the login page. If nothing appeared, open this link:"
            if info["opened"]
            else "I could not open a browser from here — open this link to log in:"
        )
        return (
            f"{head}\n\n{info['url']}\n\n"
            "The link is valid 5 minutes. Once the confirmation page appears the data tools "
            "unlock by themselves — just retry your request, or call `login_status` to check."
        )

    @mcp.tool("login_status")
    def login_status() -> str:
        """Where the login stands: logged in, still waiting for the browser round-trip, or failed."""
        if auth is None:
            return "Authentication is disabled on this server (local/dev mode) — data tools are open."
        state = auth.login_status()
        status = state["status"]
        if status == "done":
            user = state.get("user") or {}
            who = user.get("email") or user.get("name") or "your account"
            return f"Logged in as {who}. Cube data tools are unlocked."
        if status == "pending":
            return f"Still waiting for the browser login. Open this link if you have not yet:\n\n{state['url']}"
        if status == "failed":
            return f"Login failed: {state.get('error')}. Call `login` to try again."
        return "Not logged in. Call `login` to start the browser login."

    @mcp.tool("logout")
    def logout() -> str:
        """Log out and lock all data tools until the next login."""
        if auth is None:
            return "Authentication is disabled on this server (local/dev mode)."
        auth.logout()
        return "Logged out. Data tools are locked until you log in again."

    # -- catalog resource (lightweight; replaces the old monolithic dump) -----
    @mcp.resource("context://data_description")
    @require_auth
    def data_description() -> str:
        """Lightweight catalog of cubes and views available in Cube."""
        cubes = client.cubes()
        if not cubes:
            return "Error: catalog unavailable (no cubes returned by /meta)."
        return (
            "Catalog of cubes and views. Use search_cubes() to find one, "
            "describe_cube(name) for full detail, then read_data() to query.\n\n"
            + data_to_yaml(_catalog(cubes))
        )

    # -- discovery tools ------------------------------------------------------
    @mcp.tool("list_cubes")
    @require_auth
    def list_cubes() -> str:
        """List every cube and view (name, type, title, description, member counts). Views, when any
        exist, are listed first (a curated view is usually the best entry point; this model may have none).
        Lightweight on purpose — call describe_cube(name) for the members of one cube/view."""
        cubes = client.cubes()
        if not cubes:
            return "Error: no cubes returned by /meta."
        return data_to_yaml(_catalog(cubes))

    @mcp.tool("describe_data")
    @require_auth
    def describe_data() -> str:
        """Catalog of cubes and views (alias of list_cubes, kept for backward compatibility)."""
        return list_cubes()

    @mcp.tool("describe_cube")
    @require_auth
    def describe_cube(name: str) -> str:
        """Full detail of a single cube or view: measures (with aggregation type & format), dimensions
        (with data type), plus title/description, user meta (e.g. ai_context), folders, and — for raw
        cubes — the connectedComponent joinability hint. This is what you need to write a read_data query."""
        cubes = client.cubes()
        match = next((c for c in cubes if c.get("name") == name), None)
        if match is None:
            names = [n for n in (c.get("name") for c in cubes) if isinstance(n, str)]
            close = difflib.get_close_matches(name, names, n=5, cutoff=0.4)
            hint = f" Did you mean: {', '.join(close)}?" if close else " Use list_cubes() or search_cubes() to find it."
            return f"Error: no cube or view named '{name}'.{hint}"
        return data_to_yaml(_describe_one(match))

    @mcp.tool("search_cubes")
    @require_auth
    def search_cubes(query: str, top_k: int = 8) -> str:
        """Find the most relevant cubes/views for a natural-language query.
        Ranks by matches on names/titles/descriptions and member names; curated views are boosted.
        Returns candidates with a score and what matched — then call describe_cube() on the best one."""
        cubes = client.cubes()
        if not cubes:
            return "Error: no cubes returned by /meta."
        results = _search(cubes, query, top_k)
        if not results:
            return f"No cube/view matched '{query}'. Try other terms or call list_cubes() to browse."
        return data_to_yaml(results)

    @mcp.tool("get_dimension_values")
    @require_auth
    def get_dimension_values(dimension: str, search: Optional[str] = None, limit: int = 50) -> str:
        """List the distinct values of a dimension (e.g. the statuses of 'user.status') so you can filter on
        real values without an exploratory query. Ordered by frequency when the owning cube has a count measure.
        'search' narrows values with a 'contains' filter."""
        limit = max(1, min(limit, 1000))
        cube_name = dimension.split(".")[0]
        entry = next((c for c in client.cubes() if c.get("name") == cube_name), None)
        count_measure = None
        if entry is not None:
            count_measure = next(
                (m.get("name") for m in entry.get("measures", []) if m.get("aggType") == "count"), None
            )
        # Fetch one extra row to know whether the values were truncated.
        q: dict[str, Any] = {"dimensions": [dimension], "limit": limit + 1}
        if count_measure:
            q["measures"] = [count_measure]
            q["order"] = {count_measure: "desc"}
        if search:
            q["filters"] = [{"member": dimension, "operator": "contains", "values": [search]}]
        response = client.query(q)
        if error := response.get("error"):
            return f"Error: {error}"
        rows = response.get("data", [])
        truncated = len(rows) > limit
        rows = rows[:limit]
        if count_measure:
            values = [{"value": r.get(dimension), "count": r.get(count_measure)} for r in rows]
        else:
            values = [r.get(dimension) for r in rows]
        out = {
            "dimension": dimension,
            "ordered_by": count_measure or "value",
            "returned": len(values),
            "truncated": truncated,
            "values": values,
        }
        return data_to_yaml(out)

    # -- query tool -----------------------------------------------------------
    @mcp.tool("read_data")
    @require_auth
    def read_data(query: Query) -> str:
        """Run a Cube query. Supports server-side `filters`. Small results return inline (YAML); large
        results (or `output.to_file`) are written to a CSV/JSON file with a compact summary (path, typed
        columns, aggregates, sample). To export everything, set a high `limit` or `limit: null` — rows
        beyond Cube's per-query cap are paginated transparently into ONE file (no manual merging).
        CROSS-CUBE: you may mix members from different cubes in one query (e.g. a measure from one cube
        grouped by a dimension of another) — Cube resolves the join automatically when they're related.
        Set `dry_run` to validate the join path / see the compiled SQL without executing. For a time
        dimension used only to filter a period, set its dateRange and omit `granularity`."""
        try:
            cube_query = query.cube_query()

            # dry-run: compile to SQL, list members/cubes used, do not execute
            if query.dry_run:
                logger.info("read_data dry_run: %s", _loggable_query(cube_query))
                resp = client.sql(cube_query)
                if error := resp.get("error"):
                    return f"Error (dry_run): {error}"
                sql_block = resp.get("sql", {}) or {}
                sql_pair = sql_block.get("sql") or [None, None]
                members = sorted(set((sql_block.get("aliasNameToMember") or {}).values()))
                return data_to_yaml(
                    {
                        "type": "dry_run",
                        "sql": sql_pair[0] if isinstance(sql_pair, list) else sql_pair,
                        "params": sql_pair[1] if isinstance(sql_pair, list) and len(sql_pair) > 1 else None,
                        "members_used": members,
                        "note": "No data fetched. If this compiled, the join path is valid.",
                    }
                )

            # Large-export intent (limit None or above one page) → page through Cube's row cap
            # transparently into a single result, so the agent never has to merge files by hand.
            paginate = query.limit is None or query.limit > page_size
            logger.info("read_data query=%s paginate=%s", _loggable_query(cube_query), paginate)
            partial_error = None
            if paginate:
                result = client.query_paginated(cube_query, page_size, max_export_rows)
                if result.get("error") and not result.get("data"):
                    return f"Error: {_explain_error(result['error'])}"
                data = result.get("data", [])
                annotation = result.get("annotation", {})
                truncated = bool(result.get("truncated"))
                partial_error = result.get("error")
            else:
                response = client.query(cube_query)
                if error := response.get("error"):
                    logger.error("Error in read_data: %s", error)
                    logger.debug("Cube stack: %s", response.get("stack"))  # may echo SQL + parameters
                    return f"Error: {_explain_error(error)}"
                data = response.get("data", [])
                annotation = response.get("annotation", {})
                truncated = query.limit is not None and len(data) >= query.limit

            logger.info("read_data returned %s rows (truncated=%s)", len(data), truncated)
            agg_map = client.measure_agg()
            col_order = _column_order(annotation, data, query.dimensions + query.measures)
            columns = _columns(annotation, col_order, agg_map)

            # Decide inline vs file WITHOUT serializing the whole result up front.
            want_file = bool(query.output and query.output.to_file)
            too_big = want_file or len(data) > auto_file_rows
            inline_text = None
            if not too_big and data:
                inline_text = data_to_yaml(_clean({"type": "data", "rows": len(data),
                                                   "truncated": truncated or None, "data": data}))
                too_big = len(inline_text) > max_inline_chars

            # ---- file mode: write full result, return only a summary --------
            if too_big:
                fmt = query.output.format if query.output else "csv"
                try:
                    path = _write_result_file(data, col_order, output_dir, fmt)
                except OSError as e:
                    return f"Error: could not write result file in '{output_dir}': {e}"
                reason = "output.to_file was set." if want_file else f"it exceeds the inline threshold ({auto_file_rows} rows / {max_inline_chars} chars)."
                note = (
                    f"Full result ({len(data)} rows) written to file because {reason} "
                    "Read the file at `path` (already on the local filesystem)."
                )
                if truncated:
                    note += f" NOTE: truncated at {len(data)} rows (export ceiling {max_export_rows})."
                if partial_error:
                    note += f" WARNING: a page failed ({partial_error}); data may be incomplete."
                summary = {
                    "type": "data_file",
                    "path": path,
                    "format": fmt,
                    "rows": len(data),
                    "truncated": truncated or None,
                    "columns": columns,
                    "aggregates": _aggregates(data, annotation, agg_map) or None,
                    "sample": data[:sample_rows],
                    "note": note,
                }
                return data_to_yaml(_clean(summary))

            # ---- inline mode (small results) --------------------------------
            if inline_text is None:  # empty result set
                inline_text = data_to_yaml(_clean({"type": "data", "rows": len(data),
                                                   "truncated": truncated or None, "data": data}))
            return inline_text

        except Exception as e:
            logger.error("Error in read_data: %s", str(e))
            return f"Error: {str(e)}"

    logger.info("Starting Cube MCP server")
    mcp.run()
