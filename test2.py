from platform_utils import PlatformUtils
import json


with open("audit_config.json", 'r', encoding="utf-8") as f:
    data = json.load(f)
array = data.get("Linux").get("Path")


for arr in array :
    command = ["cat", arr]
    stdout, stderr, returncode = PlatformUtils.execute_command(command)
    print(stderr)