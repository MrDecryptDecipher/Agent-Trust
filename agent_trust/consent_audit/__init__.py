"""
ConsentAudit — Legally Compliant Consent Chain for Every Agent Decision

Solves Gap 6: No Compliance Layer.

Builds cryptographically signed consent chains for every
delegation hop, producing compliance-ready audit trails
for GDPR, PSD2, SOC2, and HIPAA.
"""

from agent_trust.consent_audit.chain import ConsentChainManager
from agent_trust.consent_audit.signer import ConsentSigner
from agent_trust.consent_audit.compliance import ComplianceChecker

__all__ = ["ConsentChainManager", "ConsentSigner", "ComplianceChecker"]
