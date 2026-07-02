"""OAuth 2.1 (Authorization Code + PKCE) client that logs the MCP into Convoicar.

The user authenticates in their browser on Convoicar's real login page (SSO); the MCP
never sees the password. After login the MCP exchanges its access token for a short-lived,
server-signed Cube JWT (carrying the security context) via GET /api/v2/mcp/session — the
Cube signing secret therefore never lives on the user's machine.

Entry points:
  * `ConvoicarAuth`      — used by the MCP server (login/logout tools + Cube token access).
  * `login_cli()`        — the `mcp-cube-login` console command (log in outside a tool call).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import sys
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

import requests

DEFAULT_CLIENT_ID = "mcp-cube-public-client"
DEFAULT_PORT = 47823
DEFAULT_SCOPE = "cube"
CONFIG_DIR = Path(os.path.expanduser("~/.config/convoicar-mcp"))
CREDENTIALS_PATH = CONFIG_DIR / "credentials.json"
_HTTP_TIMEOUT = 30
_LOGIN_TIMEOUT = 300  # seconds to wait for the browser round-trip
_SKEW = 60  # refresh a token this many seconds before it actually expires


class AuthError(Exception):
    """Raised when the user is not logged in or the OAuth exchange fails."""


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class ConvoicarAuth:
    """Holds OAuth tokens for one Convoicar user and vends Cube credentials."""

    def __init__(
        self,
        base_url: str,
        client_id: str = DEFAULT_CLIENT_ID,
        port: int = DEFAULT_PORT,
        scope: str = DEFAULT_SCOPE,
        logger: Optional[logging.Logger] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.port = int(port)
        self.scope = scope
        self.redirect_uri = f"http://127.0.0.1:{self.port}/callback"
        self.logger = logger or logging.getLogger(__name__)
        self._tokens = self._load_tokens()  # persisted OAuth tokens
        self._tokens_mtime = self._file_mtime()
        self._cube: Optional[dict] = None  # {endpoint, token, expires_at}
        self._user: Optional[dict] = None  # last-known identity

    # -- token cache ---------------------------------------------------------
    @staticmethod
    def _file_mtime() -> float:
        try:
            return os.path.getmtime(CREDENTIALS_PATH)
        except OSError:
            return 0.0

    def _load_tokens(self) -> dict:
        try:
            with open(CREDENTIALS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, ValueError):
            return {}

    def _maybe_reload(self) -> None:
        """The credentials file is the source of truth: a `mcp-cube-login` run in another
        process (or a token refresh) updates it, and the running MCP server must notice."""
        mtime = self._file_mtime()
        if mtime != self._tokens_mtime:
            self._tokens = self._load_tokens()
            self._tokens_mtime = mtime

    def _save_tokens(self, data: dict) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(CONFIG_DIR, 0o700)
        except OSError:
            pass
        fd = os.open(CREDENTIALS_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        try:
            os.chmod(CREDENTIALS_PATH, 0o600)  # tighten even if the file pre-existed
        except OSError:
            pass
        self._tokens = data
        self._tokens_mtime = self._file_mtime()

    def _clear_tokens(self) -> None:
        self._tokens = {}
        self._cube = None
        self._user = None
        try:
            os.remove(CREDENTIALS_PATH)
        except FileNotFoundError:
            pass

    # -- OAuth endpoints -----------------------------------------------------
    def _authorize_url(self, challenge: str, state: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{self.base_url}/oauth/authorize?{urllib.parse.urlencode(params)}"

    def _token_request(self, data: dict) -> dict:
        try:
            resp = requests.post(f"{self.base_url}/oauth/token", data=data, timeout=_HTTP_TIMEOUT)
        except requests.RequestException as e:
            raise AuthError(f"Could not reach Convoicar at {self.base_url} ({e}).")
        if resp.status_code != 200:
            raise AuthError(f"Token endpoint returned HTTP {resp.status_code}: {resp.text[:300]}")
        payload = resp.json()
        # Persist tokens with an absolute expiry so we can refresh proactively.
        expires_in = int(payload.get("expires_in", 7200))
        tokens = {
            "access_token": payload["access_token"],
            "refresh_token": payload.get("refresh_token", self._tokens.get("refresh_token")),
            "expires_at": int(time.time()) + expires_in,
            "scope": payload.get("scope", self.scope),
        }
        self._save_tokens(tokens)
        return tokens

    def _exchange_code(self, code: str, verifier: str) -> None:
        self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_verifier": verifier,
            }
        )

    def _refresh(self) -> bool:
        refresh_token = self._tokens.get("refresh_token")
        if not refresh_token:
            return False
        try:
            self._token_request(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self.client_id,
                }
            )
            return True
        except AuthError as e:
            self.logger.warning("Token refresh failed (%s) — login required.", e)
            self._clear_tokens()
            return False

    def _valid_access_token(self) -> Optional[str]:
        self._maybe_reload()
        token = self._tokens.get("access_token")
        if not token:
            return None
        if int(time.time()) < int(self._tokens.get("expires_at", 0)) - _SKEW:
            return token
        return self._tokens["access_token"] if self._refresh() else None

    # -- browser login flow --------------------------------------------------
    def login(self) -> dict:
        """Run the interactive browser login. Returns the user identity dict."""
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(24)
        code = self._run_loopback_flow(challenge, state)
        self._exchange_code(code, verifier)
        self.refresh_session(force=True)  # confirm + cache the Cube token
        return self._user or {}

    def _run_loopback_flow(self, challenge: str, state: str) -> str:
        try:
            server = HTTPServer(("127.0.0.1", self.port), _CallbackHandler)
        except OSError as e:
            raise AuthError(
                f"Could not bind the local callback port {self.port} ({e}). "
                "Close whatever is using it or set CONVOICAR_OAUTH_PORT."
            )
        server.oauth_result = None  # type: ignore[attr-defined]
        server.timeout = 1
        url = self._authorize_url(challenge, state)
        opened = webbrowser.open(url)
        prefix = "Opening your browser to log in to Convoicar…" if opened else "Open this URL to log in to Convoicar:"
        # NEVER write to stdout here: inside the MCP server, stdout is the JSON-RPC channel
        # and any stray text corrupts the protocol. stderr is safe (captured as logs) and also
        # visible when running the `mcp-cube-login` command in a terminal.
        print(f"{prefix}\n{url}\n", file=sys.stderr, flush=True)

        deadline = time.time() + _LOGIN_TIMEOUT
        try:
            while server.oauth_result is None:  # type: ignore[attr-defined]
                if time.time() > deadline:
                    raise AuthError("Timed out waiting for the browser login (5 min).")
                server.handle_request()
        finally:
            server.server_close()

        result = server.oauth_result  # type: ignore[attr-defined]
        if result.get("error"):
            raise AuthError(f"Login failed: {result['error']} {result.get('error_description') or ''}".strip())
        if result.get("state") != state:
            raise AuthError("OAuth state mismatch — aborting for safety.")
        if not result.get("code"):
            raise AuthError("No authorization code received.")
        return result["code"]

    # -- Cube session --------------------------------------------------------
    def refresh_session(self, force: bool = False) -> dict:
        """Fetch (or reuse) a server-signed Cube token for the logged-in user."""
        if not force and self._cube and int(time.time()) < self._cube["expires_at"] - _SKEW:
            return self._cube
        access = self._valid_access_token()
        if not access:
            raise AuthError("Not logged in.")
        try:
            resp = requests.get(
                f"{self.base_url}/api/v2/mcp/session",
                headers={"Authorization": f"Bearer {access}"},
                timeout=_HTTP_TIMEOUT,
            )
        except requests.RequestException as e:
            raise AuthError(f"Could not reach Convoicar at {self.base_url} ({e}).")
        if resp.status_code == 401:
            # Access token rejected: try one refresh, else force re-login.
            if self._refresh():
                return self.refresh_session(force=True)
            self._clear_tokens()
            raise AuthError("Session expired — please log in again.")
        if resp.status_code != 200:
            raise AuthError(f"Convoicar /mcp/session returned HTTP {resp.status_code}: {resp.text[:300]}")
        body = resp.json()
        cube = body.get("cube", {})
        self._user = body.get("user")
        self._cube = {
            "endpoint": cube["endpoint"],
            "token": cube["token"],
            "expires_at": int(time.time()) + int(cube.get("expires_in", 3600)),
        }
        return self._cube

    def cube_endpoint(self) -> str:
        return self.refresh_session()["endpoint"]

    def cube_token(self) -> str:
        return self.refresh_session()["token"]

    def invalidate_cube(self) -> None:
        """Drop the cached Cube token so the next call re-fetches one (used on Cube 401/403)."""
        self._cube = None

    # -- state ---------------------------------------------------------------
    def is_authenticated(self) -> bool:
        return self._valid_access_token() is not None

    def user(self) -> Optional[dict]:
        return self._user

    def logout(self) -> None:
        token = self._tokens.get("access_token")
        if token:
            try:
                requests.post(
                    f"{self.base_url}/oauth/revoke",
                    data={"token": token, "client_id": self.client_id},
                    timeout=_HTTP_TIMEOUT,
                )
            except requests.RequestException:
                pass
        self._clear_tokens()

    def auth_error(self) -> str:
        return (
            "Not logged in to Convoicar. Run the `mcp-cube-login` command in a terminal, "
            "or call the `login` tool, then retry. All data tools stay locked until you are authenticated."
        )


class _CallbackHandler(BaseHTTPRequestHandler):
    """Serves the branded landing page and captures the authorization code."""

    def do_GET(self):  # noqa: N802 (http.server API)
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        qs = urllib.parse.parse_qs(parsed.query)
        result = {
            "code": qs.get("code", [None])[0],
            "state": qs.get("state", [None])[0],
            "error": qs.get("error", [None])[0],
            "error_description": qs.get("error_description", [None])[0],
        }
        self.server.oauth_result = result  # type: ignore[attr-defined]
        ok = bool(result["code"]) and not result["error"]
        body = (_success_page() if ok else _error_page(result)).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence default stderr logging
        return


# ---------------------------------------------------------------------------
# Branded callback pages (self-contained: no external assets, CSP-safe)
# ---------------------------------------------------------------------------
# Convoicar brand palette (from convoicar/app/assets/stylesheets/variables.scss)
_BRAND = "#27C3EB"        # Convoicar primary (cyan)
_INK = "#211f2d"          # dark brand / logo glyph
_SUCCESS = "#66BB6A"      # $brand-success
_DANGER = "#d9534f"       # bootstrap danger

# The Convoicar logo (cyan roundel with white C monogram), inlined as a data URI so the page
# stays self-contained (no external assets, CSP-safe). Source: convoicar logo-convoicar.png,
# trimmed and downscaled to 128px.
_LOGO_DATA_URI = "data:image/png;base64,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"

_CHECK_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" '
    'stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>'
)
_CROSS_ICON = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" '
    'stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>'
)


def _page(title: str, icon: str, heading: str, message: str, accent: str, auto_close: bool = False) -> str:
    # On success we auto-close the tab after a short countdown so the login feels "done"
    # without the user having to close it. Browsers may refuse window.close() on a tab they
    # did not open via script (opened here by navigation) — hence the graceful fallback text.
    if auto_close:
        hint = 'Cette page se fermera automatiquement dans <b id="cd">5</b> s…'
        script = """
  <script>
    (function () {
      var n = 5;
      var cd = document.getElementById('cd');
      var hint = document.getElementById('hint');
      var timer = setInterval(function () {
        n -= 1;
        if (n > 0) { if (cd) cd.textContent = n; return; }
        clearInterval(timer);
        window.close();
        if (hint) hint.textContent = 'Vous pouvez fermer cet onglet et revenir à Claude.';
      }, 1000);
    })();
  </script>"""
    else:
        hint = "Vous pouvez fermer cet onglet et revenir à Claude."
        script = ""
    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Convoicar</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: "Lato", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background:
      radial-gradient(900px 500px at 50% -20%, rgba(39,195,235,0.14) 0%, rgba(39,195,235,0) 60%),
      #F6F5FA;
    color: {_INK}; padding: 24px;
  }}
  .card {{
    position: relative; width: 100%; max-width: 440px; background: #fff;
    border: 1px solid #E4E8EB; border-radius: 20px; padding: 48px 40px 40px;
    text-align: center; overflow: hidden;
    box-shadow: 0 20px 50px rgba(33,31,45,0.10);
  }}
  .card::before {{
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 5px;
    background: {_BRAND};
  }}
  .logo-wrap {{ position: relative; width: 84px; height: 84px; margin: 0 auto 24px; }}
  .logo {{ width: 84px; height: 84px; display: block; }}
  .pip {{
    position: absolute; right: 0; bottom: 0;
    width: 28px; height: 28px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    background: {accent}; border: 3px solid #fff;
  }}
  .pip svg {{ width: 14px; height: 14px; }}
  h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 12px; color: {_INK}; }}
  p {{ font-size: 15px; line-height: 1.55; color: #5b6373; }}
  .hint {{ margin-top: 26px; font-size: 13px; color: #9aa1ad; }}
</style>
</head>
<body>
  <main class="card">
    <div class="logo-wrap">
      <img class="logo" src="{_LOGO_DATA_URI}" alt="Convoicar" width="84" height="84">
      <span class="pip">{icon}</span>
    </div>
    <h1>{heading}</h1>
    <p>{message}</p>
    <p class="hint" id="hint">{hint}</p>
  </main>{script}
</body>
</html>"""


def _success_page() -> str:
    return _page(
        title="Connexion réussie",
        icon=_CHECK_ICON,
        heading="Connexion réussie",
        message="Vous êtes maintenant connecté à Convoicar. L'accès aux données analytiques est débloqué.",
        accent=_SUCCESS,
        auto_close=True,
    )


def _error_page(result: dict) -> str:
    detail = result.get("error_description") or result.get("error") or "Erreur inconnue."
    return _page(
        title="Échec de la connexion",
        icon=_CROSS_ICON,
        heading="Échec de la connexion",
        message=f"La connexion n'a pas abouti : {detail} Relancez la commande de connexion.",
        accent=_DANGER,
    )


# ---------------------------------------------------------------------------
# `mcp-cube-login` console command
# ---------------------------------------------------------------------------
def _auth_from_env() -> ConvoicarAuth:
    base_url = os.getenv("CONVOICAR_URL")
    if not base_url:
        raise SystemExit("CONVOICAR_URL is not set (e.g. https://web.convoicar.fr).")
    return ConvoicarAuth(
        base_url=base_url,
        client_id=os.getenv("CONVOICAR_OAUTH_CLIENT_ID", DEFAULT_CLIENT_ID),
        port=int(os.getenv("CONVOICAR_OAUTH_PORT", str(DEFAULT_PORT))),
    )


def login_cli() -> None:
    """Entry point for the `mcp-cube-login` command."""
    import argparse

    parser = argparse.ArgumentParser(prog="mcp-cube-login", description="Log the Cube MCP into Convoicar.")
    parser.add_argument("--logout", action="store_true", help="Log out and clear cached credentials.")
    args = parser.parse_args()

    auth = _auth_from_env()
    if args.logout:
        auth.logout()
        print("Logged out. Cached credentials removed.")
        return
    try:
        user = auth.login()
    except AuthError as e:
        raise SystemExit(f"Login failed: {e}")
    who = user.get("email") or user.get("name") or f"user #{user.get('id')}"
    print(f"Logged in as {who}. You can now use the Cube MCP tools.")


if __name__ == "__main__":
    login_cli()
