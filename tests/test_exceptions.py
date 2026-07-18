"""Tests for the ReconChain exception hierarchy."""
import pytest

from reconchain.exceptions import (
    ReconChainError,
    ConfigError,
    InvalidDomainError,
    InvalidPhaseError,
    InvalidCookieError,
    PipelineError,
    OutputPathError,
    InsufficientResourcesError,
    PhaseTimeoutError,
    PhaseCrashError,
    ToolError,
    ToolNotFoundError,
    ToolExecutionError,
    ToolTimeoutError,
    CircuitBreakerOpenError,
    NetworkError,
    ProxyError,
    HTTP2NotSupportedError,
    InteractshError,
    PluginError,
    PluginLoadError,
    ReportError,
    StateWriteError,
    ReportGenerationError,
    IntegrationError,
    AIAnalysisError,
    BotError,
    DashboardError,
)


class TestExceptionInheritance:
    def test_all_inherit_from_reconchain_error(self):
        exc_classes = [
            ConfigError, InvalidDomainError, InvalidPhaseError, InvalidCookieError,
            PipelineError, OutputPathError, InsufficientResourcesError,
            PhaseTimeoutError, PhaseCrashError,
            ToolError, ToolNotFoundError, ToolExecutionError, ToolTimeoutError,
            CircuitBreakerOpenError,
            NetworkError, ProxyError, HTTP2NotSupportedError, InteractshError,
            PluginError, PluginLoadError,
            ReportError, StateWriteError, ReportGenerationError,
            IntegrationError, AIAnalysisError, BotError, DashboardError,
        ]
        for cls in exc_classes:
            assert issubclass(cls, ReconChainError), f"{cls.__name__} should inherit ReconChainError"

    def test_config_hierarchy(self):
        assert issubclass(InvalidDomainError, ConfigError)
        assert issubclass(InvalidPhaseError, ConfigError)
        assert issubclass(InvalidCookieError, ConfigError)

    def test_pipeline_hierarchy(self):
        assert issubclass(OutputPathError, PipelineError)
        assert issubclass(InsufficientResourcesError, PipelineError)
        assert issubclass(PhaseTimeoutError, PipelineError)
        assert issubclass(PhaseCrashError, PipelineError)

    def test_tool_hierarchy(self):
        assert issubclass(ToolNotFoundError, ToolError)
        assert issubclass(ToolExecutionError, ToolError)
        assert issubclass(ToolTimeoutError, ToolError)
        assert issubclass(CircuitBreakerOpenError, ToolError)

    def test_network_hierarchy(self):
        assert issubclass(ProxyError, NetworkError)
        assert issubclass(HTTP2NotSupportedError, NetworkError)
        assert issubclass(InteractshError, NetworkError)

    def test_plugin_hierarchy(self):
        assert issubclass(PluginLoadError, PluginError)

    def test_report_hierarchy(self):
        assert issubclass(StateWriteError, ReportError)
        assert issubclass(ReportGenerationError, ReportError)

    def test_integration_hierarchy(self):
        assert issubclass(AIAnalysisError, IntegrationError)
        assert issubclass(BotError, IntegrationError)
        assert issubclass(DashboardError, IntegrationError)


class TestExceptionAttributes:
    def test_tool_execution_error_attributes(self):
        e = ToolExecutionError("nmap", 1, "connection refused")
        assert e.tool_name == "nmap"
        assert e.returncode == 1
        assert e.stderr == "connection refused"
        assert "nmap" in str(e)
        assert "rc=1" in str(e)

    def test_tool_timeout_error_attributes(self):
        e = ToolTimeoutError("massdns", 600)
        assert e.tool_name == "massdns"
        assert e.timeout == 600
        assert "600s" in str(e)

    def test_circuit_breaker_attributes(self):
        e = CircuitBreakerOpenError("subfinder", 3)
        assert e.tool_name == "subfinder"
        assert e.failures == 3
        assert "3 consecutive" in str(e)

    def test_phase_crash_error_causes(self):
        try:
            original = ValueError("boom")
            raise PhaseCrashError("01-RECON", original) from original
        except PhaseCrashError as e:
            assert e.phase_name == "01-RECON"
            assert e.cause is original
            assert isinstance(e.__cause__, ValueError)

    def test_phase_crash_error_no_cause(self):
        e = PhaseCrashError("04-SCAN")
        assert e.phase_name == "04-SCAN"
        assert e.cause is None


class TestExceptionMessageFormatting:
    def test_base_exception_message(self):
        e = ReconChainError("something went wrong")
        assert str(e) == "something went wrong"

    def test_config_error_message(self):
        e = ConfigError("invalid proxy URL")
        assert str(e) == "invalid proxy URL"

    def test_network_error_message(self):
        e = NetworkError("connection timed out")
        assert str(e) == "connection timed out"

    def test_tool_execution_error_message(self):
        e = ToolExecutionError("httpx", 2)
        assert "httpx" in str(e)
        assert "rc=2" in str(e)

    def test_tool_timeout_error_message(self):
        e = ToolTimeoutError("nuclei", 1800)
        assert "nuclei" in str(e)
        assert "1800s" in str(e)

    def test_circuit_breaker_message(self):
        e = CircuitBreakerOpenError("dnsx", 5)
        assert "dnsx" in str(e)
        assert "5" in str(e)


class TestExceptionCatchable:
    def test_catch_specific_as_base(self):
        with pytest.raises(ToolError):
            raise ToolExecutionError("x", 1)

    def test_catch_config_family(self):
        with pytest.raises(ConfigError):
            raise InvalidDomainError("bad.com")

    def test_catch_pipeline_family(self):
        with pytest.raises(PipelineError):
            raise InsufficientResourcesError("not enough RAM")

    def test_catch_reconchain_error_catches_all(self):
        exceptions_to_test = [
            ConfigError("c"), PipelineError("p"), ToolError("t"),
            NetworkError("n"), PluginError("pl"), ReportError("r"),
            IntegrationError("i"),
        ]
        for exc in exceptions_to_test:
            with pytest.raises(ReconChainError):
                raise exc

    def test_catchable_from_package(self):
        from reconchain import ReconChainError as RCE
        with pytest.raises(RCE):
            raise ToolExecutionError("test", 1)


class TestPluginErrorFromPluginModule:
    def test_plugin_error_raised(self):
        import asyncio
        from pathlib import Path
        from reconchain.plugin import PhasePlugin
        from reconchain.exceptions import PluginError
        plugin = PhasePlugin()
        with pytest.raises(PluginError, match="must implement run"):
            asyncio.run(
                plugin.run(Path("/tmp"), None, set(), set(), {}, False)
            )
