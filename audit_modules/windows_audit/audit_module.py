import logging
import os
import re
import subprocess
import winreg


class AuditModule:
    """
    보안 점검 모듈의 추상 베이스 클래스입니다.
    모든 점검 모듈은 이 클래스를 상속받아 run_audit 메서드를 구현해야 합니다.
    """
    def __init__(self, config):
        self.config = config
        self.module_name = self.__class__.__name__
        self.results = []

    def run_audit(self):
        """
        보안 점검을 실행하고 결과를 반환합니다.
        각 점검 항목은 이 메서드 내에서 호출되어야 합니다.
        """
        raise NotImplementedError("run_audit 메서드는 하위 클래스에서 구현되어야 합니다.")

    def _record_result(self, item, status, reason="", current_value="", recommended_value=""):
        """
        점검 결과를 기록합니다.
        """
        self.results.append({
            "module": self.module_name,
            "item": item,
            "status": status,
            "reason": reason,
            "current_value": current_value,
            "recommended_value": recommended_value
        })
        logging.info(f"[{self.module_name}] {item}: {status} - {reason}")

    def _execute_powershell(self, command):
        """
        PowerShell 명령어를 실행하고 결과를 반환합니다.
        """
        try:
            result = subprocess.run(
                ["powershell", "-Command", command],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                encoding='cp949' # Windows 기본 인코딩
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logging.error(f"PowerShell command failed: {e.cmd}\nStdout: {e.stdout}\nStderr: {e.stderr}")
            return None
        except Exception as e:
            logging.error(f"Error executing PowerShell command: {e}")
            return None

    def _get_registry_value(self, hive, subkey, value_name):
        """
        레지스트리 값을 읽어옵니다.
        """
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                value, reg_type = winreg.QueryValueEx(key, value_name)
                return value
        except FileNotFoundError:
            return None # 키 또는 값이 존재하지 않음
        except Exception as e:
            logging.error(f"Error reading registry {subkey}\\{value_name}: {e}")
            return None

    def _get_security_policy_setting(self, policy_name):
        """
        로컬 보안 정책 설정을 가져옵니다.
        secedit 명령어를 사용하여 .inf 파일을 생성하고 파싱합니다.
        """
        temp_inf_file = "temp_security_policy.inf"
        try:
            subprocess.run(
                ["secedit", "/export", "/cfg", temp_inf_file],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True
            )

            with open(temp_inf_file, 'r', encoding='utf-16-le') as f: # UTF-16 LE로 읽기
                content = f.read()

            match = re.search(rf"{policy_name}\s*=\s*(\d+)", content, re.IGNORECASE)
            if match:
                return int(match.group(1))
            return None
        except Exception as e:
            logging.error(f"Error getting security policy '{policy_name}': {e}")
            return None
        finally:
            if os.path.exists(temp_inf_file):
                os.remove(temp_inf_file)

    def _get_service_status(self, service_name):
        """
        서비스의 상태 (Running/Stopped)와 시작 유형 (Auto/Manual/Disabled)을 가져옵니다.
        """
        try:
            # PowerShell Get-Service 명령어를 사용하여 서비스 정보 가져오기
            # Select-Object Status, StartType, Name
            cmd_output = self._execute_powershell(f"Get-Service -Name \"{service_name}\" -ErrorAction SilentlyContinue | Select-Object Status, StartType | Format-List")
            
            if cmd_output:
                status_match = re.search(r"Status\s*:\s*(\w+)", cmd_output)
                start_type_match = re.search(r"StartType\s*:\s*(\w+)", cmd_output)
                
                status = status_match.group(1) if status_match else "Unknown"
                start_type = start_type_match.group(1) if start_type_match else "Unknown"
                return status, start_type
            return "NotFound", "NotFound"
        except Exception as e:
            logging.error(f"서비스 '{service_name}' 상태 확인 중 오류 발생: {e}")
            return "Error", "Error"