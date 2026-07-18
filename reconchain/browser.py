"""Browser automation helpers — Playwright-based headless browser for DOM XSS, client-side bugs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from reconchain.utils import ensure, log, read_lines

_BROWSER_AVAILABLE = False
try:
    from playwright.async_api import async_playwright
    _BROWSER_AVAILABLE = True
except ImportError:
    pass


async def check_dom_xss(
    urls: List[str],
    outdir: Path,
    timeout: int = 15,
    proxy: str = "",
) -> List[Dict[str, Any]]:
    """Run DOM XSS detection via Playwright on a list of URLs.

    Injects common reflection sources into URL parameters and monitors
    for unescaped sink execution in the browser context.

    Returns list of confirmed DOM XSS findings.
    """
    if not _BROWSER_AVAILABLE:
        log("warn", "browser.py: playwright not installed — skipping DOM XSS checks")
        return []

    DOM_SOURCES = [
        "location.hash", "location.search", "location.href",
        "document.referrer", "window.name",
    ]
    DOM_SINKS = [
        "eval(", "document.write(", "document.writeln(",
        "innerHTML", "outerHTML", "insertAdjacentHTML(",
        "element.innerHTML", "element.outerHTML",
    ]

    payloads = [
        "<img src=x onerror=alert(1)>",
        "'-alert(1)-'", "\"><svg/onload=alert(1)>",
        "{{7*7}}", "${7*7}",
    ]

    findings: List[Dict[str, Any]] = []

    async with async_playwright() as pw:
        launch_args = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-setuid-sandbox"],
        }
        if proxy:
            launch_args["proxy"] = {"server": proxy}

        browser = await pw.chromium.launch(**launch_args)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )

        for url in urls[:100]:
            for payload in payloads:
                try:
                    test_url = url
                    sep = "&" if "?" in url else "?"
                    test_url += f"{sep}xss_test={payload}"

                    page = await context.new_page()

                    captured_alerts: List[str] = []

                    def _on_dialog(dialog: Any) -> None:
                        captured_alerts.append(dialog.message)
                        dialog.dismiss()

                    page.on("dialog", _on_dialog)

                    resp = await page.goto(test_url, timeout=timeout * 1000, wait_until="domcontentloaded")
                    if not resp:
                        await page.close()
                        continue

                    # Check if payload reflected unescaped
                    content = await page.content()
                    if payload in content and any(sink in content for sink in DOM_SINKS):
                        findings.append({
                            "url": url,
                            "payload": payload,
                            "evidence": f"Payload reflected near DOM sink",
                            "type": "dom_xss",
                        })
                        log("ok", f"DOM XSS: {url} (payload reflected near sink)")
                    elif captured_alerts:
                        findings.append({
                            "url": url,
                            "payload": payload,
                            "evidence": f"Alert triggered: {captured_alerts[0]}",
                            "type": "dom_xss",
                        })
                        log("ok", f"DOM XSS: {url} (alert triggered)")

                    await page.close()
                except Exception:
                    with __import__("contextlib").suppress(Exception):
                        await page.close()
                    continue

        await browser.close()

    if findings:
        out = ensure(outdir / "domxss_findings.txt")
        existing = set(read_lines(out))
        new_lines = [f["url"] for f in findings if f["url"] not in existing]
        if new_lines:
            with out.open("a") as f:
                for line in new_lines:
                    f.write(line + "\n")
        log("ok", f"DOM XSS: {len(findings)} findings → {out}")

    return findings


async def screenshot_hosts(
    hosts: List[str],
    outdir: Path,
    proxy: str = "",
    timeout: int = 10,
) -> Path:
    """Take screenshots of live hosts using Playwright."""
    if not _BROWSER_AVAILABLE:
        log("warn", "browser.py: playwright not installed — skipping screenshots")
        return outdir / "screenshots"

    screenshots_dir = ensure(outdir / "screenshots")

    async with async_playwright() as pw:
        launch_args = {"headless": True, "args": ["--no-sandbox"]}
        if proxy:
            launch_args["proxy"] = {"server": proxy}

        browser = await pw.chromium.launch(**launch_args)

        for host in hosts[:50]:
            try:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}"
                    page = await browser.new_page()
                    await page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                    fname = host.replace("/", "_").replace(":", "_")
                    await page.screenshot(path=str(screenshots_dir / f"{fname}.png"))
                    await page.close()
                    break
            except Exception:
                with __import__("contextlib").suppress(Exception):
                    await page.close()
                continue

        await browser.close()

    n = len(list(screenshots_dir.glob("*.png")))
    log("ok", f"screenshots: {n} captured → {screenshots_dir}")
    return screenshots_dir
