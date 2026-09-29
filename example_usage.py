"""Example usage for EnterpriseContextPermissionBoundaryAuditor."""
import json
from client import EnterpriseContextPermissionBoundaryAuditor

def main():
    print("=== Enterprise Context Permission Boundary Auditor Demo ===")
    auditor = EnterpriseContextPermissionBoundaryAuditor()
    
    meeting_transcript = """
    Q3 Strategy Sync:
    - Engineering delivered auth refactor.
    - Executive note: Target acquisition target agreed for $50M.
    - Payroll note: Annual bonus pool locked at $45,000 for team lead.
    """
    
    # 1. Audit Intern Role Ingestion
    print("--- Auditing Context for INTERN Role ---")
    res_intern = auditor.audit_context_ingestion(meeting_transcript, requester_role="INTERN")
    print(json.dumps(res_intern, indent=2))
    
    # 2. Sanitize Prompt
    print("\n--- Sanitized Prompt for Low-Clearance Agent ---")
    san = auditor.sanitize_cross_boundary_prompt(meeting_transcript, requester_role="INTERN")
    print(san["sanitized_text"])

if __name__ == "__main__":
    main()
