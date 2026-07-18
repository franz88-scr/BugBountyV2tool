"""Notification support: Slack, Discord, Telegram webhooks.

Send scan completion summaries to configured channels.
"""
from __future__ import annotations
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from reconchain.utils import log


def _validate_webhook_url(url: str) -> bool:
    """Validate a webhook URL: must be HTTPS, no private/internal IPs."""
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("https",):
        log("warn", f"webhook URL must use https:// (got {parsed.scheme!r}): {url[:60]}")
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    # Block private/internal/loopback IPs (check both literal and resolved)
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            log("warn", f"webhook URL points to private/internal IP ({hostname}): {url[:60]}")
            return False
    except ValueError:
        # Not a literal IP — resolve and check
        import socket
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
                resolved = ipaddress.ip_address(sockaddr[0])
                if resolved.is_private or resolved.is_loopback or resolved.is_reserved or resolved.is_link_local:
                    log("warn", f"webhook hostname resolves to private IP ({resolved}): {url[:60]}")
                    return False
        except (socket.gaierror, OSError):
            log("warn", f"webhook hostname resolution failed: {hostname}")
            return False
    return True


def send_notification(
    message: str,
    *,
    slack_webhook: str = "",
    discord_webhook: str = "",
    telegram_bot_token: str = "",
    telegram_chat_id: str = "",
) -> bool:
    """Send a notification to one or more configured channels.

    Returns True if at least one notification was sent successfully.
    """
    sent = False

    if slack_webhook:
        sent |= _send_slack(slack_webhook, message)
    elif os.environ.get("SLACK_WEBHOOK_URL"):
        sent |= _send_slack(os.environ["SLACK_WEBHOOK_URL"], message)

    if discord_webhook:
        sent |= _send_discord(discord_webhook, message)
    elif os.environ.get("DISCORD_WEBHOOK_URL"):
        sent |= _send_discord(os.environ["DISCORD_WEBHOOK_URL"], message)

    if telegram_bot_token and telegram_chat_id:
        sent |= _send_telegram(telegram_bot_token, telegram_chat_id, message)
    else:
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if bot_token and chat_id:
            sent |= _send_telegram(bot_token, chat_id, message)

    return sent


def send_scan_summary(
    domain: str,
    counts: Dict[str, int],
    duration_seconds: float,
    missing_tools: list,
    *,
    notify_url: str = "",
) -> bool:
    """Build and send a scan completion summary."""
    minutes = int(duration_seconds // 60)
    seconds = int(duration_seconds % 60)
    time_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

    # Find interesting findings
    findings = []
    for key, count in sorted(counts.items()):
        if count > 0 and key not in ("subdomains", "resolved", "live_hosts", "urls"):
            findings.append(f"  {key}: {count}")

    finding_text = "\n".join(findings[:15]) if findings else "  (no findings)"
    missing_text = f"\nMissing tools: {', '.join(missing_tools[:5])}" if missing_tools else ""

    from html import escape as _html_escape
    message = (
        f"<b>ReconChain Scan Complete</b>\n"
        f"Domain: <code>{_html_escape(domain)}</code>\n"
        f"Duration: {time_str}\n"
        f"Subdomains: {counts.get('subdomains', 0)}\n"
        f"Live hosts: {counts.get('live_hosts', 0)}\n"
        f"Findings:\n{finding_text}{missing_text}"
    )

    # Parse --notify URL for protocol detection
    if notify_url:
        if "slack.com" in notify_url:
            return _send_slack(notify_url, message)
        elif "discord.com" in notify_url:
            return _send_discord(notify_url, message)
        elif "api.telegram.org" in notify_url:
            # Extract bot token and chat ID from URL
            # Format: https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT_ID}
            import urllib.parse
            parsed = urllib.parse.urlparse(notify_url)
            params = urllib.parse.parse_qs(parsed.query)
            chat_id = params.get("chat_id", [""])[0]
            # Extract bot token from path: /bot{TOKEN}/sendMessage
            path_parts = parsed.path.strip("/").split("/")
            bot_token = ""
            if len(path_parts) >= 2 and path_parts[0] == "bot":
                bot_token = path_parts[1]
            if bot_token and chat_id:
                return _send_telegram(bot_token, chat_id, message)
            else:
                log("warn", f"Telegram URL must include bot token and chat_id: https://api.telegram.org/botTOKEN/sendMessage?chat_id=CHAT_ID")
                return False

    return send_notification(message)


def _send_slack(webhook_url: str, text: str) -> bool:
    """Send a Slack webhook notification."""
    if not _validate_webhook_url(webhook_url):
        return False
    try:
        payload = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        try:
            return resp.status in (200, 204)
        finally:
            resp.close()
    except Exception as exc:
        log("warn", f"Slack notification failed: {exc}")
        return False


def _send_discord(webhook_url: str, text: str) -> bool:
    """Send a Discord webhook notification."""
    if not _validate_webhook_url(webhook_url):
        return False
    try:
        # Discord uses content field, limit 2000 chars
        content = text[:2000]
        payload = json.dumps({"content": content}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        try:
            return resp.status in (200, 204)
        finally:
            resp.close()
    except Exception as exc:
        log("warn", f"Discord notification failed: {exc}")
        return False


def _send_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    """Send a Telegram bot notification."""
    if not chat_id:
        return False
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        if not _validate_webhook_url(url):
            return False
        # Telegram limit 4096 chars
        payload = json.dumps({
            "chat_id": chat_id,
            "text": text[:4096],
            "parse_mode": "HTML",
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=10)
        try:
            data = json.loads(resp.read())
            return data.get("ok", False)
        finally:
            resp.close()
    except Exception as exc:
        log("warn", f"Telegram notification failed: {exc}")
        return False
