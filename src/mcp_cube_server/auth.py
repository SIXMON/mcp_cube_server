"""OAuth 2.1 (Authorization Code + PKCE) client that logs the MCP into the auth server.

The user authenticates in their browser on the auth server's own login page (SSO); the MCP
never sees the password. After login the MCP exchanges its access token for a short-lived,
server-signed Cube JWT (carrying the security context) via GET /api/v2/mcp/session — the
Cube signing secret therefore never lives on the user's machine.

Entry points:
  * `CubeAuth`     — used by the MCP server (login/logout tools + Cube token access).
  * `login_cli()`  — the `mcp-cube-login` console command (log in outside a tool call).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

import requests

DEFAULT_CLIENT_ID = "mcp-cube-public-client"
DEFAULT_PORT = 47823
# Production auth server. Baked in so end users need no env var at all; override with MCP_CUBE_URL.
DEFAULT_BASE_URL = "https://web.convoicar.fr"
DEFAULT_SCOPE = "cube"
CONFIG_DIR = Path(os.path.expanduser("~/.config/mcp-cube"))
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


# ---------------------------------------------------------------------------
# Opening the user's browser
# ---------------------------------------------------------------------------
def _browser_commands(url: str) -> list[list[str]]:
    """Desktop openers to try by hand, most specific first."""
    cmds: list[list[str]] = []
    for entry in (os.environ.get("BROWSER") or "").split(os.pathsep):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split()
        cmds.append([part.replace("%s", url) for part in parts] if "%s" in entry else parts + [url])
    if sys.platform == "darwin":
        cmds.append(["open", url])
    else:
        cmds += [
            ["xdg-open", url],
            ["gio", "open", url],
            ["x-www-browser", url],
            ["sensible-browser", url],
            ["firefox", url],
            ["google-chrome", url],
            ["chromium", url],
        ]
    return cmds


def _spawn_browser(cmd: list[str], env: Optional[dict], logger: logging.Logger) -> bool:
    if shutil.which(cmd[0]) is None:
        return False
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,  # survive the MCP server, never inherit its stdio
        )
    except OSError as e:
        logger.debug("Browser command %s did not start: %s", cmd[0], e)
        return False
    try:
        # A launcher (xdg-open, gio, open) exits as soon as it hands the URL over; a browser
        # started directly keeps running. Exit 0 or still alive both mean "it worked".
        return proc.wait(timeout=2) == 0
    except subprocess.TimeoutExpired:
        return True


def open_browser(url: str, logger: Optional[logging.Logger] = None, timeout: float = 5.0) -> bool:
    """Best-effort: open `url` in the user's browser. Returns whether one was launched.

    MCP clients spawn the server with a stripped environment, which breaks the stdlib path on
    Linux: CPython only registers GUI browsers when DISPLAY or WAYLAND_DISPLAY is set (see
    webbrowser.register_standard_browsers), so under Claude Desktop `webbrowser.open()` finds no
    browser at all and silently returns False. macOS is immune — it always registers the
    `open`-based handler. So we retry with the desktop openers ourselves, putting a plausible
    DISPLAY back when the client dropped it. Callers must still show the URL: a container or a
    remote MCP has no browser to open at all.

    Bounded by `timeout`, because opening is not reliably quick: when BROWSER is set the stdlib
    uses GenericBrowser, which runs the browser in the foreground and waits for it to *exit*.
    A launch we did not see finish is simply reported as not opened — the URL is shown either way.
    """
    log = logger or logging.getLogger(__name__)
    outcome: dict = {}

    def run() -> None:
        outcome["ok"] = _open_browser_now(url, log)

    thread = threading.Thread(target=run, name="mcp-cube-open-browser", daemon=True)
    thread.start()
    thread.join(timeout)
    if "ok" not in outcome:
        log.debug("Browser launch still pending after %.1fs — falling back to showing the URL.", timeout)
        return False
    return outcome["ok"]


def _open_browser_now(url: str, log: logging.Logger) -> bool:
    try:
        if webbrowser.open(url):
            return True
    except Exception as e:  # noqa: BLE001 — an opener must never break the login
        log.debug("webbrowser.open failed: %s", e)

    if os.name == "nt":
        try:
            os.startfile(url)  # type: ignore[attr-defined]
            return True
        except OSError as e:
            log.debug("os.startfile failed: %s", e)
            return False

    env = None
    if sys.platform != "darwin" and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        # Xwayland answers on :0 as well, so this covers X11 and Wayland sessions alike.
        env = {**os.environ, "DISPLAY": ":0"}
    return any(_spawn_browser(cmd, env, log) for cmd in _browser_commands(url))


class _PendingLogin:
    """One browser login in flight. The loopback round-trip runs in a background thread so the
    `login` tool can return the URL immediately instead of blocking the client for 5 minutes."""

    def __init__(self, url: str, state: str, verifier: str, server: HTTPServer):
        self.url = url
        self.opened = False  # set once the browser launch has been attempted
        self.state = state
        self.verifier = verifier
        self.server = server
        self.status = "pending"  # pending | done | failed
        self.error: Optional[str] = None
        self.user: dict = {}
        self.thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self.status == "pending" and self.thread is not None and self.thread.is_alive()


class CubeAuth:
    """Holds OAuth tokens for one user and vends Cube credentials."""

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
        self._pending: Optional[_PendingLogin] = None  # login awaiting the browser round-trip
        self._login_lock = threading.Lock()

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
            raise AuthError(f"Could not reach the auth server at {self.base_url} ({e}).")
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
    def begin_login(self) -> dict:
        """Start a login *without blocking*: bind the callback server, try to open the browser,
        and hand the URL straight back. The round-trip finishes in a background thread, so a
        client that cannot open a browser (stripped environment, container, remote MCP) can just
        show the link to the user. Returns {url, opened, reused}."""
        with self._login_lock:
            pending = self._pending
            if pending is not None and pending.running:
                # A login is already waiting on the callback port — re-issue its URL rather than
                # racing it for the port.
                return {"url": pending.url, "opened": pending.opened, "reused": True}

            verifier, challenge = _pkce_pair()
            state = secrets.token_urlsafe(24)
            server = self._bind_callback_server()
            url = self._authorize_url(challenge, state)
            pending = _PendingLogin(url=url, state=state, verifier=verifier, server=server)
            pending.thread = threading.Thread(
                target=self._complete_login,
                args=(pending,),
                name="mcp-cube-oauth-callback",
                daemon=True,
            )
            self._pending = pending
            # Listen first, open second: a browser that reaches the callback before anyone is
            # serving it would sit there waiting for a response that never comes.
            pending.thread.start()
            pending.opened = open_browser(url, self.logger)

            prefix = (
                "Opening your browser to log in…"
                if pending.opened
                else "Open this URL to log in:"
            )
            # NEVER write to stdout here: inside the MCP server, stdout is the JSON-RPC channel
            # and any stray text corrupts the protocol. stderr is safe (captured as logs) and also
            # visible when running the `mcp-cube-login` command in a terminal.
            print(f"{prefix}\n{url}\n", file=sys.stderr, flush=True)
            return {"url": url, "opened": pending.opened, "reused": False}

    def login(self, timeout: int = _LOGIN_TIMEOUT) -> dict:
        """Blocking login, used by the `mcp-cube-login` terminal command. Returns the identity."""
        self.begin_login()
        pending = self._pending
        if pending is None:  # pragma: no cover — begin_login always sets it
            raise AuthError("Login could not be started.")
        if pending.thread is not None:
            pending.thread.join(timeout + 5)
        if pending.status != "done":
            raise AuthError(pending.error or "Timed out waiting for the browser login.")
        return pending.user

    def login_status(self) -> dict:
        """Where the current login stands: {status: none|pending|done|failed, url, error, user}."""
        pending = self._pending
        if pending is not None and pending.status == "pending":
            return {"status": "pending", "url": pending.url}
        if self.is_authenticated():
            return {"status": "done", "user": self._user or (pending.user if pending else {}) or {}}
        if pending is not None:
            return {"status": pending.status, "url": pending.url, "error": pending.error}
        return {"status": "none"}

    def _bind_callback_server(self) -> HTTPServer:
        try:
            server = HTTPServer(("127.0.0.1", self.port), _CallbackHandler)
        except OSError as e:
            raise AuthError(
                f"Could not bind the local callback port {self.port} ({e}). "
                "Close whatever is using it or set MCP_CUBE_OAUTH_PORT."
            )
        server.oauth_result = None  # type: ignore[attr-defined]
        server.timeout = 1  # so handle_request() returns and the deadline stays enforceable
        return server

    def _complete_login(self, pending: _PendingLogin) -> None:
        """Background half of the login: wait for the callback, then trade the code for tokens."""
        try:
            code = self._wait_for_code(pending)
            self._exchange_code(code, pending.verifier)
            self.refresh_session(force=True)  # confirm + cache the Cube token
            pending.user = self._user or {}
            pending.status = "done"
        except Exception as e:  # noqa: BLE001 — the thread must never die unnoticed
            pending.status = "failed"
            pending.error = str(e)
            self.logger.warning("Login failed: %s", e)
        finally:
            pending.server.server_close()

    def _wait_for_code(self, pending: _PendingLogin) -> str:
        server = pending.server
        deadline = time.time() + _LOGIN_TIMEOUT
        while server.oauth_result is None:  # type: ignore[attr-defined]
            if time.time() > deadline:
                raise AuthError("Timed out waiting for the browser login (5 min).")
            server.handle_request()

        result = server.oauth_result  # type: ignore[attr-defined]
        if result.get("error"):
            raise AuthError(f"Login failed: {result['error']} {result.get('error_description') or ''}".strip())
        if result.get("state") != pending.state:
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
            raise AuthError(f"Could not reach the auth server at {self.base_url} ({e}).")
        if resp.status_code == 401:
            # Access token rejected: try one refresh, else force re-login.
            if self._refresh():
                return self.refresh_session(force=True)
            self._clear_tokens()
            raise AuthError("Session expired — please log in again.")
        if resp.status_code != 200:
            raise AuthError(f"/mcp/session returned HTTP {resp.status_code}: {resp.text[:300]}")
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
            "Not logged in. Run the `mcp-cube-login` command in a terminal, "
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
_BRAND = "#27C3EB"        # accent (cyan)
_INK = "#211f2d"          # text
_SUCCESS = "#66BB6A"      # success green
_DANGER = "#d9534f"       # error red

# Neutral cube mark, inlined as SVG so the page stays self-contained (no external assets, CSP-safe).
_LOGO_SVG = (
    '<svg class="logo" viewBox="0 0 64 64" role="img" aria-label="Cube" fill="none" '
    f'stroke="{_BRAND}" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M32 5 57 18.5v27L32 59 7 45.5v-27z"/>'
    '<path d="M7 18.5 32 32l25-13.5M32 32v27"/>'
    "</svg>"
)

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
<title>{title}</title>
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
      {_LOGO_SVG}
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
        message="Vous êtes maintenant connecté. L'accès aux données analytiques est débloqué.",
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
def _auth_from_env() -> CubeAuth:
    return CubeAuth(
        base_url=os.getenv("MCP_CUBE_URL") or DEFAULT_BASE_URL,
        client_id=os.getenv("MCP_CUBE_OAUTH_CLIENT_ID", DEFAULT_CLIENT_ID),
        port=int(os.getenv("MCP_CUBE_OAUTH_PORT", str(DEFAULT_PORT))),
    )


def login_cli() -> None:
    """Entry point for the `mcp-cube-login` command."""
    import argparse

    parser = argparse.ArgumentParser(prog="mcp-cube-login", description="Log the Cube MCP in.")
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
