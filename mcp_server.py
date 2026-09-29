"""MCP JSON-RPC stdio server for genpark-enterprise-context-permission-boundary-auditor-skill."""
import sys
import json
from client import EnterpriseContextPermissionBoundaryAuditor

auditor = EnterpriseContextPermissionBoundaryAuditor()

def handle_call_tool(params):
    name = params.get("name")
    args = params.get("arguments", {})
    if name != "audit_context_permission_boundary":
        return {"error": f"Unknown tool '{name}'"}
        
    action = args.get("action")
    text = args.get("context_text", "")
    role = args.get("requester_role", "ENGINEERING")
    
    if action == "audit_context_ingestion":
        return auditor.audit_context_ingestion(text, role)
    elif action == "sanitize_cross_boundary_prompt":
        return auditor.sanitize_cross_boundary_prompt(text, role)
    elif action == "get_security_summary":
        return auditor.get_security_summary()
    else:
        return {"error": f"Unknown action '{action}'"}

def main():
    if "--test" in sys.argv:
        print("[TEST] Running self-test for EnterpriseContextPermissionBoundaryAuditor...")
        sensitive_sample = "Meeting notes: VP approved salary increase to $185,000 and M&A acquisition target codename Titan."
        
        # Intern request should trigger violation
        res1 = auditor.audit_context_ingestion(sensitive_sample, requester_role="INTERN")
        assert res1["is_violation"] is True
        
        # Redaction test
        san = auditor.sanitize_cross_boundary_prompt(sensitive_sample, requester_role="INTERN")
        assert san["was_sanitized"] is True
        assert "REDACTED" in san["sanitized_text"]
        print(f"[TEST] Success! Redacted snippet: {san['sanitized_text'][:70]}...")
        return

    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")
            
            if method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [
                            {
                                "name": "audit_context_permission_boundary",
                                "description": "Inspect enterprise document/meeting context, detect permission clearance violations, sanitize cross-department prompts, and log audit trail.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "action": {"type": "string", "enum": ["audit_context_ingestion", "sanitize_cross_boundary_prompt", "get_security_summary"]},
                                        "context_text": {"type": "string"},
                                        "requester_role": {"type": "string"}
                                    },
                                    "required": ["action"]
                                }
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                res = handle_call_tool(req.get("params", {}))
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
                }
            else:
                resp = {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            print(json.dumps(resp), flush=True)
        except Exception as e:
            err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(e)}}
            print(json.dumps(err_resp), flush=True)

if __name__ == "__main__":
    main()
