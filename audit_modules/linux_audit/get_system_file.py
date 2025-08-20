import json
from platform_utils import PlatformUtils

class GetSystemFile():
    def __init__(self, os_type):
        self.os_type = os_type
        self.module_name = "시스템 파일 로드"
        self.success_path = []
        self.fail_path = []

    def run_audit(self):
        with open("audit_config.json",'r',encoding='utf-8') as f:
            self.config = json.load(f)
        self.paths = self.config.get(self.os_type).get("Path")
        data = {}
        for path in self.paths:
            command = ["cat", path]
            stdout, stderr, returncode = PlatformUtils.execute_command(command)
            if returncode == 0:
                data[path] = stdout
                self.success_path.append(path)
            else:
                data[path] = f"[Not Load] : {stderr}"
                self.fail_path.append(path)
        with open("file.json",'w',encoding='utf-8') as f:
            json.dump(data,f, ensure_ascii=False, indent=2)

        return [{
            "item": "시스템 파일 로드 결과",
            "status": "INFO",
            "reason": "",
            "current_value": "",
            "evidence": {
                "success_paths": self.success_path,
                "fail_paths": self.fail_path
            }
        }]