import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.request
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
import uvicorn
import websockets

from wireguard_dashboard.app import create_app
from wireguard_dashboard.config import Settings
from wireguard_dashboard.peers.backend import ReadOnlyFilesystemBackend


def _find_chrome_executable() -> str | None:
    candidates = [
        shutil.which("google-chrome"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        *Path("/home/blur/.agent-browser/browsers").glob("*/chrome"),
        Path("/usr/bin/google-chrome"),
        Path("/usr/bin/chromium"),
    ]
    for c in candidates:
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return str(c)
    return None


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def select_cdp_page_target(targets: list[dict[str, Any]]) -> str | None:
    """Select the first normal browser page target, rejecting non-page and extension targets."""
    for target in targets:
        if target.get("type") != "page":
            continue
        url = str(target.get("url", ""))
        if url.startswith("chrome-extension://") or url.startswith("chrome-devtools://"):
            continue
        ws_url = target.get("webSocketDebuggerUrl")
        if ws_url and isinstance(ws_url, str):
            return ws_url
    return None


class CDPClient:
    """Minimal async Chrome DevTools Protocol client over WebSockets."""

    def __init__(self, ws_url: str) -> None:
        self.ws_url = ws_url
        self._ws: Any = None
        self._msg_id = 0
        self.network_requests: list[str] = []
        self.console_messages: list[str] = []
        self.csp_violations: list[str] = []

    async def connect(self) -> None:
        self._ws = await websockets.connect(self.ws_url)
        # Enable relevant CDP domains
        await self.send("Network.enable")
        await self.send("Page.enable")
        await self.send("Runtime.enable")
        await self.send("Log.enable")

    async def close(self) -> None:
        if self._ws:
            await self._ws.close()

    async def send(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._msg_id += 1
        call_id = self._msg_id
        payload = {"id": call_id, "method": method, "params": params or {}}
        await self._ws.send(json.dumps(payload))

        while True:
            raw = await self._ws.recv()
            data = json.loads(raw)
            if "method" in data:
                evt = data["method"]
                p = data.get("params", {})
                if evt == "Network.requestWillBeSent":
                    self.network_requests.append(p.get("request", {}).get("url", ""))
                elif evt == "Runtime.consoleAPICalled":
                    text = " ".join(str(arg.get("value", "")) for arg in p.get("args", []))
                    self.console_messages.append(text)
                elif evt == "Log.entryAdded":
                    entry = p.get("entry", {})
                    msg = entry.get("text", "")
                    if "Content Security Policy" in msg or "CSP" in msg:
                        self.csp_violations.append(msg)
                continue

            if data.get("id") == call_id:
                assert isinstance(data, dict)
                return data

    async def evaluate(self, expression: str) -> Any:
        res = await self.send(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
        )
        if "error" in res:
            raise RuntimeError(f"CDP evaluation error: {res['error']}")
        result_payload = res.get("result", {})
        if "exceptionDetails" in result_payload:
            raise RuntimeError(f"JS evaluation error: {result_payload['exceptionDetails']}")
        return result_payload.get("result", {}).get("value")

    async def wait_for_condition(
        self,
        expression: str,
        timeout: float = 10.0,
        interval: float = 0.05,
        description: str = "condition",
    ) -> Any:
        start = time.monotonic()
        last_error = None
        while time.monotonic() - start < timeout:
            try:
                val = await self.evaluate(expression)
                if val:
                    return val
            except Exception as e:
                last_error = e
            await asyncio.sleep(interval)
        raise TimeoutError(
            f"Timed out waiting for {description} after {timeout}s (last error: {last_error})"
        )

    async def wait_for_selector(
        self,
        selector: str,
        timeout: float = 10.0,
        interval: float = 0.05,
    ) -> None:
        expr = f"Boolean(document.querySelector({json.dumps(selector)}))"
        await self.wait_for_condition(
            expr,
            timeout=timeout,
            interval=interval,
            description=f"selector '{selector}'",
        )

    async def navigate_and_wait(
        self,
        url: str,
        expected_path: str,
        ready_selector: str,
        timeout: float = 10.0,
    ) -> None:
        await self.send("Page.navigate", {"url": url})
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                href = await self.evaluate("window.location.href")
                if href and href.startswith("chrome-error://"):
                    raise RuntimeError(f"Browser navigation error encountered: {href}")
                pathname = await self.evaluate("window.location.pathname")
                ready_state = await self.evaluate("document.readyState")
                if pathname == expected_path and ready_state in ("interactive", "complete"):
                    exists = await self.evaluate(
                        f"Boolean(document.querySelector({json.dumps(ready_selector)}))"
                    )
                    if exists:
                        return
            except Exception as e:
                if "Browser navigation error" in str(e):
                    raise
            await asyncio.sleep(0.05)

        try:
            cur_href = await self.evaluate("window.location.href")
            cur_path = await self.evaluate("window.location.pathname")
            cur_state = await self.evaluate("document.readyState")
            title = await self.evaluate("document.title")
        except Exception:
            cur_href = cur_path = cur_state = title = "unknown"

        raise TimeoutError(
            f"Timed out after {timeout}s navigating to {url} "
            f"(expected path '{expected_path}', selector '{ready_selector}'). "
            f"Current state: href='{cur_href}', pathname='{cur_path}', "
            f"readyState='{cur_state}', title='{title}'"
        )


@asynccontextmanager
async def run_test_server_and_browser(
    config_dir: Path,
) -> AsyncGenerator[tuple[CDPClient, str], None]:
    chrome_path = _find_chrome_executable()
    if not chrome_path:
        pytest.skip("Chrome executable not found for browser tests")

    # 1. Setup authenticated session and app
    password = "correct_password"
    session_secret = "b" * 32
    settings = Settings(
        dashboard_password=password,
        session_secret=session_secret,
        auth_disabled=False,
        cookie_secure=False,  # Allow local test over http://
    )
    backend = ReadOnlyFilesystemBackend(config_dir=config_dir)
    app = create_app(settings=settings, peer_backend=backend)

    # 2. Run Uvicorn server in a separate background thread
    server_port = _get_free_port()
    config = uvicorn.Config(app=app, host="127.0.0.1", port=server_port, log_level="warning")
    server = uvicorn.Server(config)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Wait for server to bind
    for _ in range(100):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server_port}/healthz") as r:
                if r.status == 200:
                    break
        except Exception:
            time.sleep(0.05)
    else:
        server.should_exit = True
        server_thread.join(timeout=2)
        raise RuntimeError("Uvicorn test server failed to start")

    # 3. Launch Chrome with unique CDP port and temp user profile
    cdp_port = _get_free_port()
    user_data_dir = config_dir / "chrome_profile"
    user_data_dir.mkdir(exist_ok=True)

    chrome_proc = subprocess.Popen(
        [
            chrome_path,
            "--headless=new",
            f"--remote-debugging-port={cdp_port}",
            "--remote-debugging-address=127.0.0.1",
            f"--user-data-dir={user_data_dir}",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--disable-extensions",
            "--disable-component-extensions-with-background-pages",
            "--disable-default-apps",
            "--disable-background-networking",
            "--disable-sync",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    cdp_client: CDPClient | None = None
    try:
        # Wait for Chrome CDP endpoint with a valid page target
        ws_url: str | None = None
        for _ in range(300):
            if chrome_proc.poll() is not None:
                err_output = ""
                if chrome_proc.stderr:
                    err_output = chrome_proc.stderr.read().decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"Chrome process exited unexpectedly with code "
                    f"{chrome_proc.returncode}: {err_output}"
                )
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json/list") as resp:
                    pages = json.loads(resp.read().decode())
                    if isinstance(pages, list):
                        selected = select_cdp_page_target(pages)
                        if selected:
                            ws_url = selected
                            break
            except Exception:
                pass
            await asyncio.sleep(0.05)

        if not ws_url:
            # Terminate Chrome before reading stderr to avoid blocking on an open pipe
            try:
                os.killpg(os.getpgid(chrome_proc.pid), signal.SIGTERM)
                chrome_proc.wait(timeout=1)
            except Exception:
                try:
                    os.killpg(os.getpgid(chrome_proc.pid), signal.SIGKILL)
                except Exception:
                    pass
            err_output = ""
            if chrome_proc.stderr:
                try:
                    err_output = chrome_proc.stderr.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
            raise RuntimeError(
                f"Chrome CDP page target did not become available on port {cdp_port}. {err_output}"
            )

        cdp_client = CDPClient(ws_url)
        await cdp_client.connect()

        base_url = f"http://127.0.0.1:{server_port}"

        # 1. Navigate to login and wait deterministically for the form and password field
        await cdp_client.navigate_and_wait(
            url=f"{base_url}/login",
            expected_path="/login",
            ready_selector="#password",
            timeout=10.0,
        )

        # 2. Verify CSRF token is present on the form
        csrf_present = await cdp_client.evaluate(
            "Boolean(document.querySelector('.login-card form input[name=\"csrf_token\"]')?.value)"
        )
        if not csrf_present:
            raise RuntimeError("Login page loaded without required CSRF token")

        # 3. Enter password and submit the form
        await cdp_client.evaluate(f"""
            (() => {{
                const pwInput = document.getElementById('password');
                pwInput.value = '{password}';
                pwInput.dispatchEvent(new Event('input', {{ bubbles: true }}));
                document.querySelector('.login-card form').submit();
            }})()
        """)

        # 4. Wait for login completion, redirect to /, and dashboard readiness
        start = time.monotonic()
        login_timeout = 10.0
        while time.monotonic() - start < login_timeout:
            try:
                href = await cdp_client.evaluate("window.location.href")
                if href and href.startswith("chrome-error://"):
                    raise RuntimeError(f"Browser navigation error after login: {href}")

                pathname = await cdp_client.evaluate("window.location.pathname")
                if pathname == "/login":
                    err = await cdp_client.evaluate(
                        "document.querySelector('.alert-error')?.textContent"
                    )
                    if err:
                        raise RuntimeError(f"Login rejected by server: {err.strip()}")
                elif pathname == "/":
                    ready_state = await cdp_client.evaluate("document.readyState")
                    if ready_state in ("interactive", "complete"):
                        has_logout = await cdp_client.evaluate(
                            "Boolean(document.querySelector('.btn-logout'))"
                        )
                        has_dashboard_content = await cdp_client.evaluate(
                            "Boolean(document.querySelector('#peer-search, .empty-state'))"
                        )
                        if has_logout and has_dashboard_content:
                            break
            except Exception as e:
                if any(k in str(e) for k in ("rejected by server", "Browser navigation error")):
                    raise
            await asyncio.sleep(0.05)
        else:
            try:
                cur_path = await cdp_client.evaluate("window.location.pathname")
                cur_state = await cdp_client.evaluate("document.readyState")
                title = await cdp_client.evaluate("document.title")
            except Exception:
                cur_path = cur_state = title = "unknown"
            raise TimeoutError(
                f"Timed out after {login_timeout}s waiting for dashboard readiness after login. "
                f"Current pathname: '{cur_path}', readyState: '{cur_state}', title: '{title}'"
            )

        yield cdp_client, base_url
    finally:
        if cdp_client:
            await cdp_client.close()
        try:
            os.killpg(os.getpgid(chrome_proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            chrome_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(chrome_proc.pid), signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        server.should_exit = True
        server_thread.join(timeout=2)


def test_browser_search_filter_without_network_requests(tmp_path: Path) -> None:
    async def _run() -> None:
        p1 = tmp_path / "peer1"
        p1.mkdir()
        (p1 / "peer1.conf").write_text(
            "[Interface]\nAddress = 10.13.13.2/32\nPrivateKey = KEY_PEER1==\n"
        )

        p2 = tmp_path / "peer_laptop"
        p2.mkdir()
        (p2 / "peer_laptop.conf").write_text(
            "[Interface]\nAddress = 10.13.13.99/32\nPrivateKey = KEY_LAPTOP==\n"
        )

        async with run_test_server_and_browser(tmp_path) as (browser, _):
            # Wait for peer elements to be rendered in the DOM
            sel_p1 = '[data-peer-id="peer1"]'
            sel_lap = '[data-peer-id="peer_laptop"]'
            await browser.wait_for_selector(sel_p1)
            await browser.wait_for_selector(sel_lap)

            # Confirm CSP compliance on page load
            assert browser.csp_violations == [], f"CSP violations found: {browser.csp_violations}"

            # Confirm both peers initially visible
            peer1_vis = await browser.evaluate(
                f"!document.querySelector('{sel_p1}').classList.contains('card-hidden')"
            )
            lap_vis = await browser.evaluate(
                f"!document.querySelector('{sel_lap}').classList.contains('card-hidden')"
            )
            assert peer1_vis is True
            assert lap_vis is True

            # Clear recorded requests before typing
            browser.network_requests.clear()

            # Type "laptop" into search input
            await browser.evaluate("""
                (() => {
                    const input = document.getElementById('peer-search');
                    input.value = 'laptop';
                    input.dispatchEvent(new Event('input'));
                })()
            """)

            # Wait for search filtering to update visibility
            await browser.wait_for_condition(
                f"document.querySelector('{sel_p1}').classList.contains('card-hidden') && "
                f"!document.querySelector('{sel_lap}').classList.contains('card-hidden')",
                timeout=5.0,
                description="peer1 hidden and peer_laptop visible after search 'laptop'",
            )

            # Search by IP "10.13.13.2"
            await browser.evaluate("""
                (() => {
                    const input = document.getElementById('peer-search');
                    input.value = '10.13.13.2';
                    input.dispatchEvent(new Event('input'));
                })()
            """)

            await browser.wait_for_condition(
                f"!document.querySelector('{sel_p1}').classList.contains('card-hidden') && "
                f"document.querySelector('{sel_lap}').classList.contains('card-hidden')",
                timeout=5.0,
                description="peer1 visible and peer_laptop hidden after search '10.13.13.2'",
            )

            # STRICT VERIFICATION: Absolutely NO network requests triggered by search
            reqs = browser.network_requests
            assert len(reqs) == 0, f"Search unexpectedly triggered network requests: {reqs}"

    asyncio.run(_run())


def test_browser_reveal_configuration_explicit_action_and_safe_rendering(tmp_path: Path) -> None:
    async def _run() -> None:
        p1 = tmp_path / "peer1"
        p1.mkdir()
        conf_body = (
            "[Interface]\n"
            "Address = 10.13.13.2/32\n"
            "PrivateKey = TOP_SECRET_PRIVATE_KEY_4444=\n"
            "DNS = 1.1.1.1\n"
        )
        (p1 / "peer1.conf").write_text(conf_body)

        async with run_test_server_and_browser(tmp_path) as (browser, _):
            await browser.wait_for_selector('[data-peer-id="peer1"]')

            # 1. Before reveal: masked preview is shown, code element is empty and hidden
            masked_vis_before = await browser.evaluate(
                "!document.getElementById('conf-masked-peer1').classList.contains('hidden')"
            )
            assert masked_vis_before is True
            code_text_before = await browser.evaluate(
                "document.getElementById('conf-code-peer1').textContent"
            )
            assert code_text_before == ""

            # Copy button is ready for one-click copy
            copy_disabled_before = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-copy').disabled"
            )
            assert copy_disabled_before is False

            browser.network_requests.clear()

            # 2. Click "Reveal Configuration"
            await browser.evaluate("""
                document.querySelector('[data-peer-id="peer1"] .btn-reveal').click();
            """)

            # Wait for on-demand fetch and rendering
            await browser.wait_for_condition(
                "document.getElementById('conf-code-peer1').textContent.includes('TOP_SECRET_PRIVATE_KEY_4444=')",
                timeout=5.0,
                description="revealed configuration content",
            )

            # Verify network request occurred strictly on demand to /peers/peer1/conf
            conf_requests = [req for req in browser.network_requests if "/peers/peer1/conf" in req]
            msg = f"Expected 1 config request, found: {browser.network_requests}"
            assert len(conf_requests) == 1, msg

            # 3. Verify masked placeholder hidden, code block revealed and rendered inertly
            masked_hidden_after = await browser.evaluate(
                "document.getElementById('conf-masked-peer1').classList.contains('hidden')"
            )
            assert masked_hidden_after is True

            reveal_btn_text = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-reveal').textContent.trim()"
            )
            assert reveal_btn_text == "Hide Configuration"

            # 4. Click "Hide Configuration" to verify purging secret and toggling masked view
            await browser.evaluate("""
                document.querySelector('[data-peer-id="peer1"] .btn-reveal').click();
            """)

            # Wait for text purge and masked view restoration
            await browser.wait_for_condition(
                "document.getElementById('conf-code-peer1').textContent === '' && "
                "!document.getElementById('conf-masked-peer1').classList.contains('hidden')",
                timeout=5.0,
                description="purged secret text and restored masked preview",
            )

            reveal_btn_revert = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-reveal').textContent.trim()"
            )
            assert reveal_btn_revert == "Reveal Configuration"

    asyncio.run(_run())


def test_browser_clipboard_copy_success_and_failure_feedback(tmp_path: Path) -> None:
    async def _run() -> None:
        p1 = tmp_path / "peer1"
        p1.mkdir()
        (p1 / "peer1.conf").write_text(
            "[Interface]\nAddress = 10.13.13.2/32\nPrivateKey = COPY_SECRET==\n"
        )

        async with run_test_server_and_browser(tmp_path) as (browser, _):
            await browser.wait_for_selector('[data-peer-id="peer1"]')

            # 1. One-click copy directly from card without clicking Reveal first
            await browser.evaluate("""
                window.__copiedText = null;
                navigator.clipboard.writeText = async (text) => {
                    window.__copiedText = text;
                };
                document.querySelector('[data-peer-id="peer1"] .btn-copy').click();
            """)

            await browser.wait_for_condition(
                "Boolean(window.__copiedText && window.__copiedText.includes('COPY_SECRET=='))",
                timeout=5.0,
                description="clipboard text copied",
            )
            copied_text = await browser.evaluate("window.__copiedText")

            assert "COPY_SECRET==" in copied_text
            assert "[Interface]" in copied_text

            btn_copy_text = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-copy').textContent.trim()"
            )
            assert "Copied" in btn_copy_text

            # 2. Failed copy mock
            await browser.evaluate("""
                navigator.clipboard.writeText = async () => {
                    throw new Error("Clipboard permission denied");
                };
                document.execCommand = () => false;
                document.querySelector('[data-peer-id="peer1"] .btn-copy').click();
            """)

            failed_expr = (
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-copy')"
                ".textContent.includes('Failed')"
            )
            await browser.wait_for_condition(
                failed_expr,
                timeout=5.0,
                description="failed copy button text",
            )

            btn_failed_text = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-copy').textContent.trim()"
            )
            assert "Failed" in btn_failed_text

    asyncio.run(_run())


def test_browser_download_link_attributes(tmp_path: Path) -> None:
    async def _run() -> None:
        p1 = tmp_path / "peer1"
        p1.mkdir()
        (p1 / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

        async with run_test_server_and_browser(tmp_path) as (browser, _):
            await browser.wait_for_selector('[data-peer-id="peer1"]')

            sel_dl = "document.querySelector('[data-peer-id=\"peer1\"] .btn-download')"
            download_href = await browser.evaluate(f"{sel_dl}.getAttribute('href')")
            assert download_href == "/peers/peer1/conf"

            download_attr = await browser.evaluate(f"{sel_dl}.getAttribute('download')")
            assert download_attr == "peer1.conf"

            # Verify zero CSP violations
            err_msg = f"Unexpected CSP violations: {browser.csp_violations}"
            assert browser.csp_violations == [], err_msg

    asyncio.run(_run())


def test_select_cdp_page_target_filters_extensions_and_non_page_targets() -> None:
    targets: list[dict[str, Any]] = [
        {
            "type": "background_page",
            "url": "chrome-extension://nkeimhogjdpnpccoofpliimaahmaaome/background.html",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/ext1",
        },
        {
            "type": "page",
            "url": "chrome-extension://other/options.html",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/ext2",
        },
        {
            "type": "service_worker",
            "url": "https://example.com/sw.js",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/sw",
        },
        {
            "type": "page",
            "url": "about:blank",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/valid",
        },
    ]

    selected = select_cdp_page_target(targets)
    assert selected == "ws://127.0.0.1:9222/devtools/page/valid"


def test_select_cdp_page_target_returns_none_when_no_valid_page_target() -> None:
    assert select_cdp_page_target([]) is None
    assert (
        select_cdp_page_target(
            [
                {
                    "type": "background_page",
                    "url": "chrome-extension://ext/bg.html",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/ext",
                }
            ]
        )
        is None
    )
