"""
reconchain.bot — Discord/Slack companion bot for live scan management.

Provides real-time finding notifications and interactive commands via
Discord or Slack. Subscribes to the event bus for live updates.

Usage:
    # From CLI:
    reconchain -d example.com --bot --bot-platform discord

    # Programmatic:
    from reconchain.bot import start_bot
    await start_bot(platform="discord", token="...", channel_id="...")
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from collections import defaultdict
from threading import Thread
from typing import Any, Dict, List, Optional

from reconchain.events import bus
from reconchain.utils import log

# --- Severity colors for embeds ---
SEVERITY_COLORS = {
    "critical": 0xF85149,
    "high": 0xF0883E,
    "medium": 0xD29922,
    "low": 0x8B949E,
    "info": 0x8B949E,
}

SEVERITY_EMOJI = {
    "critical": "\u26a0\ufe0f",
    "high": "\U0001f534",
    "medium": "\U0001f7e1",
    "low": "\u26ab",
    "info": "\u26ab",
}


def _guess_severity(text: str) -> str:
    t = text.lower()
    if any(w in t for w in ["rce", "critical", "remote code", "sql injection"]):
        return "critical"
    if any(w in t for w in ["xss", "ssrf", "lfi", "idor", "sqli", "high"]):
        return "high"
    if any(w in t for w in ["medium", "redirect", "cors", "open redirect"]):
        return "medium"
    return "low"


class BotState:
    """Shared state for the bot."""

    def __init__(self) -> None:
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.findings_buffer: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.last_post_time: Dict[str, float] = {}
        self.stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.phase_status: Dict[str, Dict[str, str]] = defaultdict(dict)


_bot_state = BotState()


# --- Discord Bot Implementation ---


async def _run_discord_bot(
    token: str,
    channel_id: str,
    mention_on_critical: bool = True,
    guild_id: Optional[str] = None,
) -> None:
    """Run a Discord bot using raw WebSocket (no discord.py dependency)."""
    try:
        import aiohttp
    except ImportError:
        log("err", "err: discord bot requires 'aiohttp' package: pip install aiohttp")
        return

    API = "https://discord.com/api/v10"
    HEADERS = {"Authorization": f"Bot {token}", "Content-Type": "application/json"}

    async with aiohttp.ClientSession() as session:
        # Get bot info
        async with session.get(f"{API}/users/@me", headers=HEADERS) as resp:
            if resp.status != 200:
                log("err", f"err: Discord auth failed (HTTP {resp.status})")
                return
            bot_info = await resp.json()
            log("ok", f"ok: Discord bot connected as {bot_info['username']}")

        channel_id_int = int(channel_id)

        async def send_message(content: str, embed: Optional[Dict] = None) -> None:
            payload: Dict[str, Any] = {"content": content}
            if embed:
                payload["embeds"] = [embed]
            async with session.post(
                f"{API}/channels/{channel_id_int}/messages",
                headers=HEADERS,
                json=payload,
            ) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    log("warn", f"warn: Discord send failed ({resp.status}): {body[:200]}")

        async def send_finding(finding: Dict[str, Any]) -> None:
            severity = finding.get("severity", "info")
            emoji = SEVERITY_EMOJI.get(severity, "")
            embed = {
                "title": f"{emoji} {severity.upper()} Finding",
                "description": finding.get("text", "")[:2000],
                "color": SEVERITY_COLORS.get(severity, 0x8B949E),
                "fields": [],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if finding.get("source"):
                embed["fields"].append({"name": "Source", "value": finding["source"], "inline": True})
            if finding.get("phase"):
                embed["fields"].append({"name": "Phase", "value": finding["phase"], "inline": True})

            mention = "@here" if severity in ("critical", "high") and mention_on_critical else ""
            await send_message(mention, embed)

        # --- Event Handlers ---
        def on_finding(event: Any) -> None:
            domain = event.data.get("domain", "unknown")
            finding = {
                "text": event.data.get("text", event.data.get("finding", "")),
                "severity": event.data.get("severity", _guess_severity(event.data.get("text", ""))),
                "source": event.data.get("source", ""),
                "phase": event.data.get("phase", ""),
            }

            # Throttle: max 1 post per 5 seconds per domain
            now = time.time()
            last = _bot_state.last_post_time.get(domain, 0)
            _bot_state.findings_buffer[domain].append(finding)
            _bot_state.stats[domain][finding["severity"]] += 1

            if now - last >= 5 and _bot_state.findings_buffer[domain]:
                buffered = _bot_state.findings_buffer[domain].copy()
                _bot_state.findings_buffer[domain].clear()
                _bot_state.last_post_time[domain] = now
                for f in buffered[-3:]:  # Max 3 per batch
                    asyncio.ensure_future(send_finding(f))

        def on_phase_complete(event: Any) -> None:
            phase = event.data.get("phase", "")
            elapsed = event.data.get("elapsed", 0)
            msg = f"\u2705 Phase `{phase}` completed in {elapsed:.1f}s"
            asyncio.ensure_future(send_message(msg))

        def on_phase_fail(event: Any) -> None:
            phase = event.data.get("phase", "")
            error = event.data.get("error", "unknown error")
            msg = f"\u274c Phase `{phase}` failed: {error[:200]}"
            asyncio.ensure_future(send_message(msg))

        def on_scan_complete(event: Any) -> None:
            data = event.data
            stats = data.get("stats", {})
            embed = {
                "title": "\U0001f389 Scan Complete",
                "description": f"**{data.get('domain', 'unknown')}**",
                "color": 0x3FB950,
                "fields": [
                    {"name": "Duration", "value": data.get("duration", "unknown"), "inline": True},
                    {"name": "Total Findings", "value": str(data.get("total_findings", 0)), "inline": True},
                ],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if stats:
                crit = stats.get("critical", 0)
                high = stats.get("high", 0)
                if crit or high:
                    embed["fields"].append({
                        "name": "Critical/High",
                        "value": f"\u26a0\ufe0f {crit} critical, \U0001f534 {high} high",
                        "inline": False,
                    })
            asyncio.ensure_future(send_message("", embed))

        bus.subscribe("finding.new", on_finding)
        bus.subscribe("phase.complete", on_phase_complete)
        bus.subscribe("phase.fail", on_phase_fail)
        bus.subscribe("scan.complete", on_scan_complete)

        # --- Discord Gateway WebSocket for commands ---
        try:
            async with session.get(f"{API}/gateway", headers=HEADERS) as resp:
                gw_data = await resp.json()
                ws_url = gw_data["url"]
        except Exception as exc:
            log("err", f"err: failed to get Discord gateway: {exc}")
            return

        async with session.ws_connect(f"{ws_url}?v=10&encoding=json") as ws:
            # Identify
            identify = {
                "op": 2,
                "d": {
                    "token": token,
                    "intents": (1 << 0) | (1 << 9),  # GUILDS + MESSAGE_CONTENT
                },
            }
            await ws.send_json(identify)

            log("ok", "ok: Discord bot connected to gateway")

            # Heartbeat + command listener
            seq = 0
            heartbeat_interval = 41250  # default, updated by HELLO
            last_heartbeat = 0

            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    op = data.get("op")

                    if op == 10:  # HELLO
                        heartbeat_interval = data["d"]["heartbeat_interval"]
                    elif op == 11:  # HEARTBEAT_ACK
                        pass
                    elif op == 0:  # DISPATCH
                        seq = data.get("s", seq)
                        event_type = data.get("t", "")

                        if event_type == "MESSAGE_CREATE":
                            m = data["d"]
                            if m["author"].get("bot"):
                                continue
                            if int(m["channel_id"]) != channel_id_int:
                                continue

                            content = m["content"].strip()
                            if not content.startswith("!"):
                                continue

                            cmd = content.split()[0].lower()
                            args = content.split()[1:]

                            if cmd == "!status":
                                domain = args[0] if args else "latest"
                                scans = _bot_state.active_scans
                                if domain == "latest" and scans:
                                    domain = list(scans.keys())[-1]
                                info = scans.get(domain, {})
                                status = info.get("status", "unknown")
                                phases_done = info.get("phases_done", 0)
                                phases_total = info.get("phases_total", "?")
                                stats = _bot_state.stats.get(domain, {})
                                embed = {
                                    "title": f"Scan Status: {domain}",
                                    "description": f"Status: **{status}**\nPhases: {phases_done}/{phases_total}",
                                    "color": 0x58A6FF if status == "running" else 0x3FB950,
                                }
                                if stats:
                                    fields = []
                                    for sev in ["critical", "high", "medium", "low"]:
                                        if stats[sev]:
                                            fields.append({"name": sev.upper(), "value": str(stats[sev]), "inline": True})
                                    if fields:
                                        embed["fields"] = fields
                                await send_message("", embed)

                            elif cmd == "!findings":
                                domain = args[0] if args else "latest"
                                sev_filter = args[1] if len(args) > 1 else ""
                                findings = _bot_state.findings_buffer.get(
                                    domain if domain != "latest" else
                                    (list(_bot_state.findings_buffer.keys())[-1] if _bot_state.findings_buffer else ""),
                                    [],
                                )
                                if sev_filter:
                                    findings = [f for f in findings if f.get("severity") == sev_filter]
                                if not findings:
                                    await send_message("No findings available.")
                                else:
                                    lines = []
                                    for f in findings[-10:]:
                                        emoji = SEVERITY_EMOJI.get(f.get("severity", ""), "")
                                        lines.append(f"{emoji} `{f.get('phase', '?')}` {f.get('text', '')[:100]}")
                                    await send_message("\n".join(lines))

                            elif cmd == "!targets":
                                if not _bot_state.active_scans:
                                    await send_message("No active scans.")
                                else:
                                    lines = ["**Active Targets:**"]
                                    for domain, info in _bot_state.active_scans.items():
                                        status = info.get("status", "?")
                                        icon = "\U0001f7e2" if status == "running" else "\u26ab"
                                        lines.append(f"{icon} `{domain}` — {status}")
                                    await send_message("\n".join(lines))

                            elif cmd == "!help":
                                help_text = (
                                    "**ReconChain Bot Commands:**\n"
                                    "`!status [domain]` — Scan progress\n"
                                    "`!findings [domain] [severity]` — List findings\n"
                                    "`!targets` — List active scan targets\n"
                                    "`!help` — This message"
                                )
                                await send_message(help_text)

                elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSED):
                    break

                # Periodic heartbeat
                now = time.time() * 1000
                if now - last_heartbeat > heartbeat_interval:
                    await ws.send_json({"op": 1, "d": seq})
                    last_heartbeat = now


# --- Slack Bot Implementation ---


async def _run_slack_bot(
    token: str,
    channel_id: str,
    mention_on_critical: bool = True,
) -> None:
    """Run a Slack bot using Socket Mode or webhook."""
    try:
        import aiohttp
    except ImportError:
        log("err", "err: slack bot requires 'aiohttp' package: pip install aiohttp")
        return

    API = "https://api.slack.com/api"
    HEADERS = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async with aiohttp.ClientSession() as session:
        # Test auth
        async with session.get(f"{API}/auth.test", headers=HEADERS) as resp:
            body = await resp.json()
            if not body.get("ok"):
                log("err", f"err: Slack auth failed: {body.get('error', 'unknown')}")
                return
            log("ok", f"ok: Slack bot connected as {body.get('user', 'unknown')}")

        async def send_message(text: str, blocks: Optional[List] = None) -> None:
            payload: Dict[str, Any] = {"channel": channel_id, "text": text}
            if blocks:
                payload["blocks"] = blocks
            async with session.post(
                f"{API}/chat.postMessage", headers=HEADERS, json=payload
            ) as resp:
                body = await resp.json()
                if not body.get("ok"):
                    log("warn", f"warn: Slack send failed: {body.get('error', '')}")

        def on_finding(event: Any) -> None:
            severity = event.data.get("severity", _guess_severity(event.data.get("text", "")))
            emoji = SEVERITY_EMOJI.get(severity, "")
            text = event.data.get("text", event.data.get("finding", ""))
            source = event.data.get("source", "")
            mention = "<!channel>" if severity in ("critical", "high") and mention_on_critical else ""
            msg = f"{mention} {emoji} *{severity.upper()}* `{source}` {text[:300]}"

            now = time.time()
            domain = event.data.get("domain", "default")
            last = _bot_state.last_post_time.get(domain, 0)
            if now - last >= 5:
                _bot_state.last_post_time[domain] = now
                asyncio.ensure_future(send_message(msg))

        def on_scan_complete(event: Any) -> None:
            data = event.data
            msg = (
                f"\U0001f389 *Scan Complete* — `{data.get('domain', '?')}`\n"
                f"Duration: {data.get('duration', '?')} | "
                f"Findings: {data.get('total_findings', 0)}"
            )
            asyncio.ensure_future(send_message(msg))

        bus.subscribe("finding.new", on_finding)
        bus.subscribe("scan.complete", on_scan_complete)

        log("ok", "ok: Slack bot running (event-driven mode)")

        # Keep alive
        while True:
            await asyncio.sleep(60)


# --- Public API ---


async def start_bot(
    platform: str = "discord",
    token: str = "",
    channel_id: str = "",
    mention_on_critical: bool = True,
    **kwargs: Any,
) -> None:
    """Start the companion bot.

    Args:
        platform: "discord" or "slack"
        token: Bot token
        channel_id: Target channel ID
        mention_on_critical: @channel on critical findings
    """
    if not token:
        token = os.environ.get(
            "DISCORD_BOT_TOKEN" if platform == "discord" else "SLACK_BOT_TOKEN", ""
        )
    if not channel_id:
        channel_id = os.environ.get(
            "DISCORD_CHANNEL_ID" if platform == "discord" else "SLACK_CHANNEL_ID", ""
        )

    if not token or not channel_id:
        log("err", f"err: {platform} bot requires token and channel_id")
        return

    log("ok", f"ok: starting {platform} bot...")
    _setup_event_subscriptions()

    if platform == "discord":
        await _run_discord_bot(token, channel_id, mention_on_critical)
    elif platform == "slack":
        await _run_slack_bot(token, channel_id, mention_on_critical)
    else:
        log("err", f"err: unknown bot platform '{platform}'")


def _setup_event_subscriptions() -> None:
    """Ensure event bus subscriptions are set up (idempotent)."""
    pass  # Subscriptions are set up in the platform-specific runners


def start_bot_thread(
    platform: str = "discord",
    token: str = "",
    channel_id: str = "",
    mention_on_critical: bool = True,
) -> None:
    """Start the bot in a background thread (for non-async contexts)."""
    def _thread() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(
                start_bot(platform, token, channel_id, mention_on_critical)
            )
        except Exception as exc:
            log("err", f"err: bot thread failed: {exc}")

    t = Thread(target=_thread, daemon=True, name=f"reconchain-bot-{platform}")
    t.start()
    log("ok", f"ok: {platform} bot thread started")
