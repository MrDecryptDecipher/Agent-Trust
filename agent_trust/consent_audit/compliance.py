"""
Compliance checker — validates consent chains against
specific regulatory requirements.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from agent_trust.exceptions import ComplianceViolation
from agent_trust.types import ComplianceStandard, ConsentRecord, TokenScope

logger = logging.getLogger(__name__)


@dataclass
class ComplianceReport:
    """Result of a compliance check."""
    standard: ComplianceStandard
    passed: bool
    checks_performed: int = 0
    checks_passed: int = 0
    violations: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class ComplianceChecker:
    """
    Validates consent chains against regulatory requirements.
    
    Supported standards:
    - GDPR: Data minimization, purpose limitation, consent validity
    - PSD2: Strong customer authentication, transaction logging
    - SOC2: Access controls, audit logging, data integrity
    - HIPAA: Minimum necessary, audit controls, authorization
    
    Usage:
        checker = ComplianceChecker()
        report = checker.check_gdpr(chain_records)
        if not report.passed:
            for v in report.violations:
                print(f"VIOLATION: {v}")
    """

    def check(
        self,
        standard: ComplianceStandard,
        records: list[ConsentRecord],
    ) -> ComplianceReport:
        """Run compliance check for a specific standard."""
        checkers = {
            ComplianceStandard.GDPR: self.check_gdpr,
            ComplianceStandard.PSD2: self.check_psd2,
            ComplianceStandard.SOC2: self.check_soc2,
            ComplianceStandard.HIPAA: self.check_hipaa,
        }
        
        checker = checkers.get(standard)
        if checker is None:
            return ComplianceReport(
                standard=standard,
                passed=False,
                violations=[f"Unsupported standard: {standard.value}"],
            )
        
        return checker(records)

    def check_all(
        self,
        records: list[ConsentRecord],
        standards: Optional[list[ComplianceStandard]] = None,
    ) -> dict[ComplianceStandard, ComplianceReport]:
        """Run compliance checks against multiple standards."""
        if standards is None:
            standards = list(ComplianceStandard)
        
        return {
            std: self.check(std, records)
            for std in standards
        }

    def check_gdpr(
        self, records: list[ConsentRecord]
    ) -> ComplianceReport:
        """
        GDPR compliance check.
        
        Key requirements:
        - Data minimization: scopes must be minimal
        - Purpose limitation: task types must be specific
        - Consent validity: all consents must be current
        - Right to audit: chain must be complete and verifiable
        """
        report = ComplianceReport(
            standard=ComplianceStandard.GDPR,
            passed=True,
        )

        # Check 1: Data minimization (no unnecessary scopes)
        report.checks_performed += 1
        for record in records:
            if TokenScope.ADMIN in record.scopes:
                report.violations.append(
                    f"GDPR Art.5(1)(c) - Data minimization: "
                    f"ADMIN scope at hop {record.hop_index} "
                    f"may violate minimum necessary principle"
                )
                report.passed = False
            elif len(record.scopes) > 3:
                report.recommendations.append(
                    f"Hop {record.hop_index}: {len(record.scopes)} scopes "
                    f"may exceed minimum necessary"
                )
        if report.passed:
            report.checks_passed += 1

        # Check 2: Purpose limitation
        report.checks_performed += 1
        for record in records:
            if not record.task_type:
                report.violations.append(
                    f"GDPR Art.5(1)(b) - Purpose limitation: "
                    f"no task_type specified at hop {record.hop_index}"
                )
                report.passed = False
        if not any("Purpose limitation" in v for v in report.violations):
            report.checks_passed += 1

        # Check 3: Consent validity (not expired)
        report.checks_performed += 1
        for record in records:
            if record.is_expired:
                report.violations.append(
                    f"GDPR Art.7 - Valid consent: "
                    f"consent at hop {record.hop_index} has expired"
                )
                report.passed = False
        if not any("Valid consent" in v for v in report.violations):
            report.checks_passed += 1

        # Check 4: Explicit consent (signature present)
        report.checks_performed += 1
        for record in records:
            if not record.signature:
                report.violations.append(
                    f"GDPR Art.7 - Explicit consent: "
                    f"no signature at hop {record.hop_index}"
                )
                report.passed = False
        if not any("Explicit consent" in v for v in report.violations):
            report.checks_passed += 1

        # Check 5: Chain completeness
        report.checks_performed += 1
        for i, record in enumerate(records):
            if record.hop_index != i:
                report.violations.append(
                    f"GDPR - Audit trail: "
                    f"gap in consent chain at position {i}"
                )
                report.passed = False
        if not any("gap in consent" in v for v in report.violations):
            report.checks_passed += 1

        return report

    def check_psd2(
        self, records: list[ConsentRecord]
    ) -> ComplianceReport:
        """
        PSD2 compliance check.
        
        Key requirements:
        - Strong customer authentication
        - Transaction logging
        - Explicit authorization for each payment operation
        """
        report = ComplianceReport(
            standard=ComplianceStandard.PSD2,
            passed=True,
        )

        # Check 1: All financial operations must be explicitly authorized
        report.checks_performed += 1
        financial_tasks = {"payment", "transfer", "withdraw", "deposit"}
        for record in records:
            task_lower = record.task_type.lower()
            if any(ft in task_lower for ft in financial_tasks):
                if not record.signature:
                    report.violations.append(
                        f"PSD2 Art.97 - SCA: financial operation "
                        f"'{record.task_type}' at hop {record.hop_index} "
                        f"lacks cryptographic authorization"
                    )
                    report.passed = False
        if not any("SCA" in v for v in report.violations):
            report.checks_passed += 1

        # Check 2: Short-lived authorization for sensitive ops
        report.checks_performed += 1
        for record in records:
            ttl = record.expires_at - record.granted_at
            if ttl > 300:  # 5 minutes
                task_lower = record.task_type.lower()
                if any(ft in task_lower for ft in financial_tasks):
                    report.violations.append(
                        f"PSD2 - Time-limited auth: financial consent "
                        f"at hop {record.hop_index} has TTL {ttl}s "
                        f"(max recommended: 300s)"
                    )
                    report.passed = False
        if not any("Time-limited" in v for v in report.violations):
            report.checks_passed += 1

        # Check 3: Transaction logging completeness
        report.checks_performed += 1
        for record in records:
            if not record.task_description:
                report.recommendations.append(
                    f"PSD2 - Logging: hop {record.hop_index} lacks "
                    f"task_description for audit purposes"
                )
        report.checks_passed += 1  # Recommendations don't fail

        return report

    def check_soc2(
        self, records: list[ConsentRecord]
    ) -> ComplianceReport:
        """
        SOC2 Type II compliance check.
        
        Key requirements:
        - Access controls
        - Audit logging
        - Data integrity
        """
        report = ComplianceReport(
            standard=ComplianceStandard.SOC2,
            passed=True,
        )

        # Check 1: Access controls (principle of least privilege)
        report.checks_performed += 1
        for i in range(1, len(records)):
            prev_scopes = set(records[i - 1].scopes)
            curr_scopes = set(records[i].scopes)
            if not curr_scopes.issubset(prev_scopes):
                escalated = curr_scopes - prev_scopes
                report.violations.append(
                    f"SOC2 CC6.1 - Least privilege: scope escalation "
                    f"at hop {records[i].hop_index}: "
                    f"{[s.value for s in escalated]}"
                )
                report.passed = False
        if not any("Least privilege" in v for v in report.violations):
            report.checks_passed += 1

        # Check 2: Complete audit trail
        report.checks_performed += 1
        for record in records:
            if not record.signature:
                report.violations.append(
                    f"SOC2 CC7.2 - Audit: missing signature "
                    f"at hop {record.hop_index}"
                )
                report.passed = False
        if not any("Audit" in v for v in report.violations):
            report.checks_passed += 1

        # Check 3: Data integrity (chain linkage)
        report.checks_performed += 1
        for i in range(1, len(records)):
            if records[i].parent_consent_id != records[i - 1].consent_id:
                report.violations.append(
                    f"SOC2 CC8.1 - Integrity: broken chain linkage "
                    f"at hop {records[i].hop_index}"
                )
                report.passed = False
        if not any("Integrity" in v for v in report.violations):
            report.checks_passed += 1

        return report

    def check_hipaa(
        self, records: list[ConsentRecord]
    ) -> ComplianceReport:
        """
        HIPAA compliance check.
        
        Key requirements:
        - Minimum necessary standard
        - Audit controls
        - Authorization
        """
        report = ComplianceReport(
            standard=ComplianceStandard.HIPAA,
            passed=True,
        )

        # Check 1: Minimum necessary
        report.checks_performed += 1
        for record in records:
            if TokenScope.ADMIN in record.scopes:
                report.violations.append(
                    f"HIPAA §164.502(b) - Minimum necessary: "
                    f"ADMIN scope at hop {record.hop_index} "
                    f"likely exceeds minimum necessary"
                )
                report.passed = False
        if not any("Minimum necessary" in v for v in report.violations):
            report.checks_passed += 1

        # Check 2: Audit controls
        report.checks_performed += 1
        if not records:
            report.violations.append(
                "HIPAA §164.312(b) - Audit controls: "
                "no consent records found"
            )
            report.passed = False
        else:
            all_signed = all(r.signature for r in records)
            if not all_signed:
                report.violations.append(
                    "HIPAA §164.312(b) - Audit controls: "
                    "not all records are signed"
                )
                report.passed = False
            else:
                report.checks_passed += 1

        # Check 3: Authorization validity
        report.checks_performed += 1
        for record in records:
            if record.is_expired:
                report.violations.append(
                    f"HIPAA §164.508 - Authorization: "
                    f"expired consent at hop {record.hop_index}"
                )
                report.passed = False
        if not any("Authorization" in v for v in report.violations):
            report.checks_passed += 1

        return report
