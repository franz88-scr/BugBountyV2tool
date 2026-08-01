"""Tests for compliance report generation (PCI-DSS / HIPAA / SOC2)."""

import json
from pathlib import Path

import pytest

from vulnforge.compliance import (
    ALL_CONTROLS,
    ComplianceControl,
    Framework,
    assess_control,
    generate_all_compliance_reports,
    generate_compliance_report,
    get_frameworks,
)


def _make_control(**overrides):
    fields = {
        "framework": Framework.PCI_DSS,
        "control_id": "TEST-01",
        "title": "Test control",
        "description": "A synthetic control for tests.",
        "category": "access_control",
        "finding_types": ["xss"],
        "severity_mapping": {"high": "non_compliant", "medium": "partial"},
    }
    fields.update(overrides)
    return ComplianceControl(**fields)


class TestAssessControl:
    def test_no_matching_findings_is_compliant(self) -> None:
        status = assess_control(_make_control(), [])
        assert status.status == "compliant"

    def test_matching_high_severity_is_non_compliant(self) -> None:
        ctrl = _make_control()
        findings = [{"category": "xss", "text": "reflected xss", "severity": "high"}]
        status = assess_control(ctrl, findings)
        assert status.status == "non_compliant"
        assert status.findings_matched

    def test_matching_medium_severity_is_partial(self) -> None:
        ctrl = _make_control()
        findings = [{"category": "xss", "text": "low xss", "severity": "medium"}]
        status = assess_control(ctrl, findings)
        assert status.status == "partial"

    def test_non_matching_category_is_compliant(self) -> None:
        ctrl = _make_control()
        findings = [{"category": "sqli", "text": "sqli", "severity": "critical"}]
        assert assess_control(ctrl, findings).status == "compliant"


class TestReports:
    def test_generate_compliance_report(self, tmp_path: Path) -> None:
        (tmp_path / "xss_findings.txt").write_text("XSS at https://example.com/search\n")
        out = generate_compliance_report(tmp_path, Framework.PCI_DSS, domain="example.com")
        data = json.loads(out.read_text())
        assert data["framework"] == "pci_dss"
        assert data["domain"] == "example.com"
        assert data["summary"]["total_controls"] == len(ALL_CONTROLS[Framework.PCI_DSS])
        assert (tmp_path / "compliance_pci_dss.md").exists()

    def test_generate_all_frameworks(self, tmp_path: Path) -> None:
        results = generate_all_compliance_reports(tmp_path, domain="example.com")
        assert set(results) == {"pci_dss", "hipaa", "soc2"}
        for path in results.values():
            assert path.exists()

    def test_non_framework_value_raises(self, tmp_path: Path) -> None:
        with pytest.raises(AttributeError):
            generate_compliance_report(tmp_path, "bogus")  # type: ignore[arg-type]

    def test_get_frameworks(self) -> None:
        fw = get_frameworks()
        assert len(fw) == 3
        assert {f["name"] for f in fw} == {"pci_dss", "hipaa", "soc2"}
        assert all(f["controls_count"] > 0 for f in fw)
