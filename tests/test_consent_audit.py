"""
Tests for ConsentAudit module.
"""

import pytest
from agent_trust.consent_audit import ConsentChainManager, ComplianceChecker
from agent_trust.types import TokenScope, ComplianceStandard
from agent_trust.exceptions import (
    ConsentChainBrokenError,
    ConsentScopeViolation,
)


class TestConsentChainManager:
    """Test consent chain management."""

    def test_create_chain(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, record = mgr.create_chain(
            grantor_id="agent-a",
            grantee_id="agent-b",
            scopes=[TokenScope.READ],
            task_type="data_retrieval",
        )
        
        assert chain_id is not None
        assert record.hop_index == 0
        assert record.signature != ""

    def test_extend_chain(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, _ = mgr.create_chain(
            grantor_id="a",
            grantee_id="b",
            scopes=[TokenScope.READ, TokenScope.WRITE],
            task_type="test",
        )
        
        record2 = mgr.extend_chain(
            chain_id=chain_id,
            grantor_id="b",
            grantee_id="c",
            scopes=[TokenScope.READ],
            task_type="sub_test",
        )
        
        assert record2.hop_index == 1

    def test_scope_escalation_rejected(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, _ = mgr.create_chain(
            grantor_id="a",
            grantee_id="b",
            scopes=[TokenScope.READ],
            task_type="test",
        )
        
        with pytest.raises(ConsentScopeViolation):
            mgr.extend_chain(
                chain_id=chain_id,
                grantor_id="b",
                grantee_id="c",
                scopes=[TokenScope.READ, TokenScope.ADMIN],  # Escalation!
                task_type="test",
            )

    def test_wrong_grantor_rejected(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, _ = mgr.create_chain(
            grantor_id="a",
            grantee_id="b",
            scopes=[TokenScope.READ],
            task_type="test",
        )
        
        with pytest.raises(ConsentChainBrokenError):
            mgr.extend_chain(
                chain_id=chain_id,
                grantor_id="c",  # c is NOT the grantee of previous hop
                grantee_id="d",
                scopes=[TokenScope.READ],
                task_type="test",
            )

    def test_verify_chain(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, _ = mgr.create_chain(
            grantor_id="a",
            grantee_id="b",
            scopes=[TokenScope.READ],
            task_type="test",
        )
        mgr.extend_chain(
            chain_id=chain_id,
            grantor_id="b",
            grantee_id="c",
            scopes=[TokenScope.READ],
            task_type="test",
        )
        
        assert mgr.verify_chain(chain_id)

    def test_chain_summary(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, _ = mgr.create_chain(
            grantor_id="a",
            grantee_id="b",
            scopes=[TokenScope.READ],
            task_type="test",
        )
        
        summary = mgr.get_chain_summary(chain_id)
        assert summary["origin"] == "a"
        assert summary["terminal"] == "b"

    def test_export_audit_trail(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, _ = mgr.create_chain(
            grantor_id="a",
            grantee_id="b",
            scopes=[TokenScope.READ],
            task_type="test",
        )
        
        trail = mgr.export_audit_trail(chain_id)
        assert len(trail) == 1
        assert "granted_at_iso" in trail[0]


class TestComplianceChecker:
    """Test compliance checking."""

    def _make_chain(self):
        mgr = ConsentChainManager("test-secret")
        chain_id, _ = mgr.create_chain(
            grantor_id="a",
            grantee_id="b",
            scopes=[TokenScope.READ],
            task_type="data_retrieval",
            task_description="Fetch user profile",
        )
        mgr.extend_chain(
            chain_id=chain_id,
            grantor_id="b",
            grantee_id="c",
            scopes=[TokenScope.READ],
            task_type="data_fetch",
            task_description="Query database",
        )
        return mgr.get_chain(chain_id)

    def test_gdpr_compliance_passes(self):
        records = self._make_chain()
        checker = ComplianceChecker()
        report = checker.check_gdpr(records)
        
        assert report.passed
        assert report.checks_passed > 0

    def test_soc2_compliance_passes(self):
        records = self._make_chain()
        checker = ComplianceChecker()
        report = checker.check_soc2(records)
        
        assert report.passed

    def test_check_all_standards(self):
        records = self._make_chain()
        checker = ComplianceChecker()
        reports = checker.check_all(records)
        
        assert ComplianceStandard.GDPR in reports
        assert ComplianceStandard.SOC2 in reports
        assert ComplianceStandard.PSD2 in reports
        assert ComplianceStandard.HIPAA in reports
