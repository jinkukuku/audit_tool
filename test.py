from audit_modules.linux_audit.account_audit import AccountManagementAudit
import json


config_file = "audit_config.json"
con = {}
with open(config_file, 'r', encoding='utf-8') as f:
    config = json.load(f)
    con = config.get("Windows")
print(con)    
a=AccountManagementAudit("Windows",con)


result = a.inspect_file("W-02")
print(result)


