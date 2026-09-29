"""Client module for EnterpriseContextPermissionBoundaryAuditor (100% Python Standard Library)."""
import json
import time
import re
from typing import Dict, Any, List, Optional

class EnterpriseContextPermissionBoundaryAuditor:
    """Enforces enterprise data clearance boundaries, preventing confidential HR, payroll,
    or strategic IP leakage when work agents ingest multi-source enterprise documents."""
    
    CLEARANCE_HIERARCHY = {
        "PUBLIC": 0,
        "INTERNAL": 1,
        "CONFIDENTIAL": 2,
        "RESTRICTED_EXECUTIVE": 3
    }
    
    ROLE_CLEARANCES = {
        "INTERN": "PUBLIC",
        "CONTRACTOR": "INTERNAL",
        "ENGINEERING": "INTERNAL",
        "HR_MANAGER": "CONFIDENTIAL",
        "FINANCE_LEAD": "CONFIDENTIAL",
        "EXECUTIVE": "RESTRICTED_EXECUTIVE"
    }
    
    SENSITIVE_PATTERNS = {
        "SALARY_COMPENSATION": (r"\b(salary|equity grant|annual bonus|\$\d{2,3},\d{3})\b", "CONFIDENTIAL"),
        "MERGER_ACQUISITION": (r"\b(m&a|merger|acquisition target|nda signed|term sheet)\b", "RESTRICTED_EXECUTIVE"),
        "INTERNAL_CREDENTIAL": (r"\b(api_secret|bearer eyJ|private_key|aws_access_key)\b", "RESTRICTED_EXECUTIVE"),
        "EMPLOYEE_PII": (r"\b(\d{3}-\d{2}-\d{4}|passport #)\b", "CONFIDENTIAL")
    }

    def __init__(self):
        self.audit_violations: List[Dict[str, Any]] = []

    def audit_context_ingestion(self, context_text: str, requester_role: str = "ENGINEERING") -> Dict[str, Any]:
        """Evaluates whether the ingested context exceeds the clearance level of the requesting agent role."""
        req_role = requester_role.upper()
        allowed_clearance = self.ROLE_CLEARANCES.get(req_role, "INTERNAL")
        allowed_level = self.CLEARANCE_HIERARCHY[allowed_clearance]
        
        detected_categories = []
        highest_detected_level = 0
        highest_clearance_tag = "PUBLIC"
        
        for category, (regex, tier) in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(regex, context_text, re.IGNORECASE)
            if matches:
                tier_level = self.CLEARANCE_HIERARCHY[tier]
                detected_categories.append({"category": category, "tier": tier, "matches_count": len(matches)})
                if tier_level > highest_detected_level:
                    highest_detected_level = tier_level
                    highest_clearance_tag = tier
                    
        is_violation = highest_detected_level > allowed_level
        if is_violation:
            self.audit_violations.append({
                "timestamp": time.time(),
                "role": req_role,
                "allowed_tier": allowed_clearance,
                "detected_tier": highest_clearance_tag,
                "categories": detected_categories
            })
            
        return {
            "status": "success",
            "requester_role": req_role,
            "allowed_clearance": allowed_clearance,
            "required_clearance": highest_clearance_tag,
            "is_violation": is_violation,
            "detected_sensitive_data": detected_categories,
            "action_recommended": "REDACT_OR_BLOCK" if is_violation else "PERMIT"
        }

    def sanitize_cross_boundary_prompt(self, context_text: str, requester_role: str = "ENGINEERING") -> Dict[str, Any]:
        """Redacts sensitive tokens if context exceeds clearance level, allowing safe partial execution."""
        audit = self.audit_context_ingestion(context_text, requester_role)
        sanitized = context_text
        
        if audit["is_violation"]:
            for cat, (regex, tier) in self.SENSITIVE_PATTERNS.items():
                tier_level = self.CLEARANCE_HIERARCHY[tier]
                req_level = self.CLEARANCE_HIERARCHY[audit["allowed_clearance"]]
                if tier_level > req_level:
                    sanitized = re.sub(regex, f"[REDACTED_{cat}]", sanitized, flags=re.IGNORECASE)
                    
        return {
            "status": "success",
            "was_sanitized": audit["is_violation"],
            "original_length": len(context_text),
            "sanitized_length": len(sanitized),
            "sanitized_text": sanitized
        }

    def get_security_summary(self) -> Dict[str, Any]:
        """Returns total audit metrics and violation count."""
        return {
            "status": "success",
            "total_violations_recorded": len(self.audit_violations),
            "violations_history": self.audit_violations[-5:]
        }
