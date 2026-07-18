"""ReconChain exception hierarchy.

All exceptions inherit from ``ReconChainError`` so callers can catch
the entire family with a single ``except`` clause, or target specific
sub-families for granular handling.
"""
from __future__ import annotations


class ReconChainError(Exception):
    """Base exception for all ReconChain errors."""


# ── Configuration ────────────────────────────────────────────────────────────

class ConfigError(ReconChainError):
    """Invalid or missing configuration."""


class InvalidDomainError(ConfigError):
    """Domain argument is not a valid DNS name."""


class InvalidPhaseError(ConfigError):
    """Unknown or invalid phase identifier."""


class InvalidCookieError(ConfigError):
    """Cookie string is empty or malformed after sanitization."""


# ── Pipeline / Lifecycle ─────────────────────────────────────────────────────

class PipelineError(ReconChainError):
    """Errors in pipeline orchestration."""


class OutputPathError(PipelineError):
    """Output directory path is invalid (e.g. exists as a file)."""


class InsufficientResourcesError(PipelineError):
    """System lacks minimum RAM/swap for the scan."""


class PhaseTimeoutError(PipelineError):
    """A scan phase exceeded its time limit."""


class PhaseCrashError(PipelineError):
    """A scan phase raised an unhandled exception."""

    def __init__(self, phase_name: str, cause: Exception | None = None):
        self.phase_name = phase_name
        self.cause = cause
        super().__init__(f"phase {phase_name} crashed: {cause}")
        if cause:
            self.__cause__ = cause


# ── Tool Execution ───────────────────────────────────────────────────────────

class ToolError(ReconChainError):
    """Errors related to external tool execution."""


class ToolNotFoundError(ToolError):
    """Required external binary is not installed."""


class ToolExecutionError(ToolError):
    """Tool exited with a non-zero return code."""

    def __init__(self, tool_name: str, returncode: int, stderr: str = ""):
        self.tool_name = tool_name
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"{tool_name} failed (rc={returncode})")


class ToolTimeoutError(ToolError):
    """Tool execution exceeded the allowed timeout."""

    def __init__(self, tool_name: str, timeout: float):
        self.tool_name = tool_name
        self.timeout = timeout
        super().__init__(f"{tool_name} timed out after {timeout}s")


class CircuitBreakerOpenError(ToolError):
    """Tool auto-disabled after repeated consecutive failures."""

    def __init__(self, tool_name: str, failures: int):
        self.tool_name = tool_name
        self.failures = failures
        super().__init__(f"{tool_name} auto-disabled after {failures} consecutive failures")


# ── Network ──────────────────────────────────────────────────────────────────

class NetworkError(ReconChainError):
    """Network-level errors (connections, DNS, timeouts)."""


class ProxyError(NetworkError):
    """Proxy configuration or connection failure."""


class HTTP2NotSupportedError(NetworkError):
    """Target server does not support HTTP/2."""


class InteractshError(NetworkError):
    """OOB interaction service failed to start or connect."""


# ── Plugin ───────────────────────────────────────────────────────────────────

class PluginError(ReconChainError):
    """Errors in plugin discovery, loading, or execution."""


class PluginLoadError(PluginError):
    """Failed to import or instantiate a plugin module."""


# ── Report / Output ──────────────────────────────────────────────────────────

class ReportError(ReconChainError):
    """Errors during report or state file generation."""


class StateWriteError(ReportError):
    """Failed to write state.json."""


class ReportGenerationError(ReportError):
    """Failed to generate HTML/Markdown/SARIF/Faraday reports."""


# ── Integration ──────────────────────────────────────────────────────────────

class IntegrationError(ReconChainError):
    """Errors in external service integrations (AI, bots, dashboards)."""


class AIAnalysisError(IntegrationError):
    """AI triage or exploit chain analysis failed."""


class BotError(IntegrationError):
    """Companion bot (Discord/Slack) connection or send failure."""


class DashboardError(IntegrationError):
    """Dashboard server failed to start."""
