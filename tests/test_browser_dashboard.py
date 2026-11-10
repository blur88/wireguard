import asyncio
import json
import os
import shutil
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
        result_payload = res.get("result", {})
        if "exceptionDetails" in result_payload:
            raise RuntimeError(f"JS evaluation error: {result_payload['exceptionDetails']}")
        return result_payload.get("result", {}).get("value")


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
    for _ in range(50):
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
            f"--user-data-dir={user_data_dir}",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    cdp_client: CDPClient | None = None
    try:
        # Wait for Chrome CDP endpoint
        ws_url: str | None = None
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json/list") as resp:
                    pages = json.loads(resp.read().decode())
                    if pages:
                        ws_url = pages[0]["webSocketDebuggerUrl"]
                        break
            except Exception:
                await asyncio.sleep(0.05)

        if not ws_url:
            raise RuntimeError("Chrome CDP endpoint did not become available")

        cdp_client = CDPClient(ws_url)
        await cdp_client.connect()

        # Log in through the standard login page in the browser
        base_url = f"http://127.0.0.1:{server_port}"
        await cdp_client.send("Page.navigate", {"url": f"{base_url}/login"})
        await asyncio.sleep(0.3)
        await cdp_client.evaluate(f"""
            (() => {{
                document.getElementById('password').value = '{password}';
                document.querySelector('.login-card form').submit();
            }})()
        """)

        # Wait for redirect to complete
        for _ in range(40):
            cur = await cdp_client.evaluate("window.location.pathname")
            if cur == "/":
                break
            await asyncio.sleep(0.05)

        yield cdp_client, base_url
    finally:
        if cdp_client:
            await cdp_client.close()
        chrome_proc.terminate()
        try:
            chrome_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            chrome_proc.kill()
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

        async with run_test_server_and_browser(tmp_path) as (browser, base_url):
            # Navigate to dashboard
            await browser.send("Page.navigate", {"url": f"{base_url}/"})
            await asyncio.sleep(0.5)

            # Confirm CSP compliance on page load
            assert browser.csp_violations == [], f"CSP violations found: {browser.csp_violations}"

            # Confirm both peers initially visible
            sel_p1 = "document.querySelector('[data-peer-id=\"peer1\"]')"
            sel_lap = "document.querySelector('[data-peer-id=\"peer_laptop\"]')"
            peer1_vis = await browser.evaluate(f"!{sel_p1}.classList.contains('card-hidden')")
            lap_vis = await browser.evaluate(f"!{sel_lap}.classList.contains('card-hidden')")
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
            await asyncio.sleep(0.1)

            # Assert peer_laptop is visible and peer1 is hidden
            peer1_hidden = await browser.evaluate(f"{sel_p1}.classList.contains('card-hidden')")
            lap_shown = await browser.evaluate(f"!{sel_lap}.classList.contains('card-hidden')")
            assert peer1_hidden is True
            assert lap_shown is True

            # Search by IP "10.13.13.2"
            await browser.evaluate("""
                (() => {
                    const input = document.getElementById('peer-search');
                    input.value = '10.13.13.2';
                    input.dispatchEvent(new Event('input'));
                })()
            """)
            await asyncio.sleep(0.1)

            peer1_shown = await browser.evaluate(f"!{sel_p1}.classList.contains('card-hidden')")
            lap_hidden = await browser.evaluate(f"{sel_lap}.classList.contains('card-hidden')")
            assert peer1_shown is True
            assert lap_hidden is True

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

        async with run_test_server_and_browser(tmp_path) as (browser, base_url):
            await browser.send("Page.navigate", {"url": f"{base_url}/"})
            await asyncio.sleep(0.5)

            # 1. Before reveal: wrapper is hidden and code element is empty
            wrapper_hidden_before = await browser.evaluate(
                "document.getElementById('conf-wrapper-peer1').classList.contains('hidden')"
            )
            assert wrapper_hidden_before is True
            code_text_before = await browser.evaluate(
                "document.getElementById('conf-code-peer1').textContent"
            )
            assert code_text_before == ""

            # Copy button initially disabled
            copy_disabled_before = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-copy').disabled"
            )
            assert copy_disabled_before is True

            browser.network_requests.clear()

            # 2. Click "Reveal Configuration"
            await browser.evaluate("""
                document.querySelector('[data-peer-id="peer1"] .btn-reveal').click();
            """)

            # Wait for on-demand fetch
            for _ in range(30):
                code_text = await browser.evaluate(
                    "document.getElementById('conf-code-peer1').textContent"
                )
                if "TOP_SECRET_PRIVATE_KEY_4444=" in code_text:
                    break
                await asyncio.sleep(0.05)

            # Verify network request occurred strictly on demand to /peers/peer1/conf
            conf_requests = [req for req in browser.network_requests if "/peers/peer1/conf" in req]
            msg = f"Expected 1 config request, found: {browser.network_requests}"
            assert len(conf_requests) == 1, msg

            # 3. Verify wrapper visible and text rendered inertly
            wrapper_shown_after = await browser.evaluate(
                "!document.getElementById('conf-wrapper-peer1').classList.contains('hidden')"
            )
            assert wrapper_shown_after is True

            reveal_btn_text = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-reveal').textContent.trim()"
            )
            assert reveal_btn_text == "Hide Configuration"

            # Copy button is now enabled
            copy_disabled_after = await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-copy').disabled"
            )
            assert copy_disabled_after is False

            # 4. Click "Hide Configuration" to verify toggling back
            await browser.evaluate("""
                document.querySelector('[data-peer-id="peer1"] .btn-reveal').click();
            """)
            await asyncio.sleep(0.1)

            wrapper_hidden_again = await browser.evaluate(
                "document.getElementById('conf-wrapper-peer1').classList.contains('hidden')"
            )
            assert wrapper_hidden_again is True
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

        async with run_test_server_and_browser(tmp_path) as (browser, base_url):
            await browser.send("Page.navigate", {"url": f"{base_url}/"})
            await asyncio.sleep(0.5)

            # Reveal configuration first
            await browser.evaluate(
                "document.querySelector('[data-peer-id=\"peer1\"] .btn-reveal').click();"
            )
            await asyncio.sleep(0.3)

            # 1. Successful copy mock
            await browser.evaluate("""
                window.__copiedText = null;
                navigator.clipboard.writeText = async (text) => {
                    window.__copiedText = text;
                };
                document.querySelector('[data-peer-id="peer1"] .btn-copy').click();
            """)
            await asyncio.sleep(0.1)

            copied_text = await browser.evaluate("window.__copiedText")
            assert "COPY_SECRET==" in copied_text

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
            await asyncio.sleep(0.1)

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

        async with run_test_server_and_browser(tmp_path) as (browser, base_url):
            await browser.send("Page.navigate", {"url": f"{base_url}/"})
            await asyncio.sleep(0.5)

            sel_dl = "document.querySelector('[data-peer-id=\"peer1\"] .btn-download')"
            download_href = await browser.evaluate(f"{sel_dl}.getAttribute('href')")
            assert download_href == "/peers/peer1/conf"

            download_attr = await browser.evaluate(f"{sel_dl}.getAttribute('download')")
            assert download_attr == "peer1.conf"

            # Verify zero CSP violations
            err_msg = f"Unexpected CSP violations: {browser.csp_violations}"
            assert browser.csp_violations == [], err_msg

    asyncio.run(_run())
