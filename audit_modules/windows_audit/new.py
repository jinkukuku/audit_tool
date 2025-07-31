import subprocess
import logging
import re
import os
import winreg # Windows 레지스트리 접근을 위한 모듈
import json # JSON 파싱을 위해 추가

# PlatformUtils는 별도의 파일(platform_utils.py)에 정의되어 있다고 가정합니다.
# from platform_utils import PlatformUtils

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


class AccountManagementAudit(AuditModule):
    """
    Windows 계정 관리 보안 점검을 수행하는 모듈입니다.
    - W-01: 패스워드 정책 설정
    - W-02: 계정 잠금 임계값 설정
    - W-03: Guest 계정 비활성화
    - W-04: Administrator 계정 이름 변경
    - W-46: 불필요한 계정 제거 (수동 점검)
    - W-47: 계정 잠금 기간 설정
    - W-48: 패스워드 복잡성 설정
    - W-49: 패스워드 최소 사용 기간 설정
    - W-50: 패스워드 최대 사용 기간 설정
    - W-51: 패스워드 길이 설정
    - W-52: 패스워드 기록 강제 적용
    - W-53: 계정 잠금 기간 설정
    - W-54: 계정 잠금 횟수 제한
    - W-55: 계정 잠금 다시 설정 기간 설정
    - W-56: 마지막 로그온 시간 기록
    - W-57: 로컬 계정의 빈 암호 사용 제한
    """
    def __init__(self, config):
        super().__init__(config)
        self.account_config = self.config.get('account_management', {})

    def run_audit(self):
        self.results = []
        logging.info(f"Starting {self.module_name} audit...")

        self.check_w01_password_policy()
        self.check_w02_account_lockout_threshold()
        self.check_w03_guest_account_status()
        self.check_w04_admin_account_rename()
        self.check_w46_unnecessary_accounts()
        self.check_w47_account_lockout_duration()
        self.check_w48_password_complexity()
        self.check_w49_password_min_age()
        self.check_w50_password_max_age()
        self.check_w51_password_min_length()
        self.check_w52_password_history()
        self.check_w53_account_lockout_duration_policy() # W-47과 중복될 수 있으나, 정책명에 따라 구분
        self.check_w54_account_lockout_threshold_policy() # W-02과 중복될 수 있으나, 정책명에 따라 구분
        self.check_w55_reset_account_lockout_counter_after()
        self.check_w56_last_logon_time_recording()
        self.check_w57_limit_blank_passwords_for_local_accounts()

        logging.info(f"Completed {self.module_name} audit.")
        return self.results

    def check_w01_password_policy(self):
        """
        W-01: 패스워드 정책 설정 (최소 암호 길이)
        - 점검기준: 최소 암호 길이가 8자 이상으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 또는 'net accounts' 명령어로 확인.
        """
        item = "W-01. 패스워드 정책 설정 (최소 암호 길이)"
        try:
            cmd_output = self._execute_powershell("net accounts")
            if cmd_output:
                match = re.search(r"Minimum password length:\s*(\d+)", cmd_output)
                if match:
                    current_length = int(match.group(1))
                    recommended_length = self.account_config.get('w01_password_policy_min_length', 8)
                    if current_length >= recommended_length:
                        self._record_result(item, "PASS", f"최소 암호 길이가 {current_length}자로 적절하게 설정되어 있습니다.",
                                            current_value=f"{current_length}자", recommended_value=f"{recommended_length}자 이상")
                    else:
                        self._record_result(item, "VULNERABLE", f"최소 암호 길이가 {current_length}자로 너무 짧게 설정되어 있습니다. {recommended_length}자 이상으로 설정하십시오.",
                                            current_value=f"{current_length}자", recommended_value=f"{recommended_length}자 이상")
                else:
                    self._record_result(item, "UNKNOWN", "최소 암호 길이 설정을 확인할 수 없습니다.")
            else:
                self._record_result(item, "ERROR", "net accounts 명령어 실행에 실패했습니다.")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w02_account_lockout_threshold(self):
        """
        W-02: 계정 잠금 임계값 설정
        - 점검기준: 계정 잠금 임계값이 5회 이하로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 또는 'net accounts' 명령어로 확인.
        """
        item = "W-02. 계정 잠금 임계값 설정"
        try:
            cmd_output = self._execute_powershell("net accounts")
            if cmd_output:
                match = re.search(r"Lockout threshold:\s*(\d+)", cmd_output)
                if match:
                    current_threshold = int(match.group(1))
                    recommended_threshold = self.account_config.get('w02_account_lockout_threshold', 5)
                    if current_threshold <= recommended_threshold and current_threshold > 0:
                        self._record_result(item, "PASS", f"계정 잠금 임계값이 {current_threshold}회로 적절하게 설정되어 있습니다.",
                                            current_value=f"{current_threshold}회", recommended_value=f"{recommended_threshold}회 이하 (0 제외)")
                    elif current_threshold == 0:
                        self._record_result(item, "VULNERABLE", "계정 잠금 임계값이 '0'(잠금 없음)으로 설정되어 있습니다. 5회 이하로 설정하십시오.",
                                            current_value="0회", recommended_value=f"{recommended_threshold}회 이하 (0 제외)")
                    else:
                        self._record_result(item, "VULNERABLE", f"계정 잠금 임계값이 {current_threshold}회로 너무 높게 설정되어 있습니다. {recommended_threshold}회 이하로 설정하십시오.",
                                            current_value=f"{current_threshold}회", recommended_value=f"{recommended_threshold}회 이하 (0 제외)")
                else:
                    self._record_result(item, "UNKNOWN", "계정 잠금 임계값 설정을 확인할 수 없습니다.")
            else:
                self._record_result(item, "ERROR", "net accounts 명령어 실행에 실패했습니다.")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w03_guest_account_status(self):
        """
        W-03: Guest 계정 비활성화
        - 점검기준: Guest 계정이 비활성화되어 있는 경우 양호.
        - 점검방법: 'net user Guest' 명령어로 확인.
        """
        item = "W-03. Guest 계정 비활성화"
        try:
            cmd_output = self._execute_powershell("net user Guest")
            if cmd_output and "Account active                 No" in cmd_output:
                self._record_result(item, "PASS", "Guest 계정이 비활성화되어 있습니다.",
                                    current_value="비활성화", recommended_value="비활성화")
            elif cmd_output and "Account active                 Yes" in cmd_output:
                self._record_result(item, "VULNERABLE", "Guest 계정이 활성화되어 있습니다. 비활성화하십시오.",
                                    current_value="활성화", recommended_value="비활성화")
            else:
                self._record_result(item, "UNKNOWN", "Guest 계정 상태를 확인할 수 없습니다.")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w04_admin_account_rename(self):
        """
        W-04: Administrator 계정 이름 변경
        - 점검기준: Administrator 계정의 이름이 변경되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "계정: Administrator 계정 이름 바꾸기" 확인.
        """
        item = "W-04. Administrator 계정 이름 변경"
        # 정책 이름: "Accounts: Rename administrator account"
        # 레지스트리: HKLM\SAM\SAM\Domains\Account\Users\Names\Administrator (이름 변경 시 다른 이름으로 존재)
        # 직접 레지스트리를 읽기 어려우므로, secedit 정책을 통해 확인
        
        # secedit /export /cfg temp.inf 후 "NewAdministratorName" 섹션 확인
        # NewAdministratorName = "새로운이름"
        
        temp_inf_file = "temp_security_policy.inf"
        try:
            subprocess.run(
                ["secedit", "/export", "/cfg", temp_inf_file],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True
            )

            with open(temp_inf_file, 'r', encoding='utf-16-le') as f:
                content = f.read()

            match = re.search(r"NewAdministratorName\s*=\s*\"([^\"]+)\"", content, re.IGNORECASE)
            
            if match:
                current_admin_name = match.group(1)
                if current_admin_name.lower() != "administrator":
                    self._record_result(item, "PASS", f"Administrator 계정 이름이 '{current_admin_name}'으로 변경되어 있습니다.",
                                        current_value=current_admin_name, recommended_value="변경됨")
                else:
                    self._record_result(item, "VULNERABLE", "Administrator 계정 이름이 'Administrator'로 기본 설정되어 있습니다. 변경하십시오.",
                                        current_value=current_admin_name, recommended_value="변경됨")
            else:
                self._record_result(item, "UNKNOWN", "Administrator 계정 이름 변경 정책 설정을 확인할 수 없습니다.")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")
        finally:
            if os.path.exists(temp_inf_file):
                os.remove(temp_inf_file)

    def check_w46_unnecessary_accounts(self):
        """
        W-46: 불필요한 계정 제거
        - 점검기준: 불필요한 시스템 계정 및 사용하지 않는 계정이 제거되어 있는 경우 양호.
        - 점검방법: 'net user' 명령어로 계정 목록 확인. (수동 점검 필요성 제시)
        """
        item = "W-46. 불필요한 계정 제거"
        self._record_result(item, "MANUAL",
                            "불필요한 계정 제거는 자동 점검이 어렵습니다. 'net user' 명령어로 계정 목록을 확인하고 불필요한 계정을 제거하십시오.",
                            current_value="수동 확인 필요", recommended_value="불필요한 계정 제거")

    def check_w47_account_lockout_duration(self):
        """
        W-47: 계정 잠금 기간 설정
        - 점검기준: 계정 잠금 기간이 10분 이상으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "계정 잠금 기간" 확인.
        """
        item = "W-47. 계정 잠금 기간 설정"
        # 정책 이름: "Account lockout duration"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\AccountLockoutDuration (분 단위)
        # 권고: 10분 이상 (0은 잠금 해제 안 함)
        
        policy_value = self._get_security_policy_setting("LockoutDuration")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "계정 잠금 기간 정책 설정을 확인할 수 없습니다.")
            return

        # policy_value는 초 단위로 반환될 수 있음 (secedit의 경우). net accounts는 분 단위.
        # secedit에서 LockoutDuration은 초 단위로 반환됩니다.
        # 10분 = 600초
        if policy_value >= 600 or policy_value == 0: # 0은 "지정된 시간 후 계정 잠금 해제 안 함"으로 양호
            self._record_result(item, "PASS",
                                f"계정 잠금 기간이 {policy_value/60}분({policy_value}초)으로 적절하게 설정되어 있습니다.",
                                current_value=f"{policy_value/60}분", recommended_value="10분 이상 또는 0")
        else:
            self._record_result(item, "VULNERABLE",
                                f"계정 잠금 기간이 {policy_value/60}분({policy_value}초)으로 너무 짧게 설정되어 있습니다. 10분 이상으로 설정하거나 '0'으로 설정하십시오.",
                                current_value=f"{policy_value/60}분", recommended_value="10분 이상 또는 0")

    def check_w48_password_complexity(self):
        """
        W-48: 패스워드 복잡성 설정
        - 점검기준: "암호는 복잡성을 만족해야 함" 정책이 '사용'으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "암호는 복잡성 요구 사항을 만족해야 함" 확인.
        """
        item = "W-48. 패스워드 복잡성 설정"
        # 정책 이름: "Password must meet complexity requirements"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\PasswordComplexity (1: 사용, 0: 사용 안 함)
        
        policy_value = self._get_security_policy_setting("PasswordComplexity")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "패스워드 복잡성 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 1:
            self._record_result(item, "PASS", "패스워드 복잡성 정책이 '사용'으로 설정되어 있습니다.",
                                current_value="사용 (1)", recommended_value="사용 (1)")
        else:
            self._record_result(item, "VULNERABLE", "패스워드 복잡성 정책이 '사용 안 함'으로 설정되어 있습니다. '사용'으로 변경하십시오.",
                                current_value="사용 안 함 (0)", recommended_value="사용 (1)")

    def check_w49_password_min_age(self):
        """
        W-49: 패스워드 최소 사용 기간 설정
        - 점검기준: 패스워드 최소 사용 기간이 1일 이상으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "최소 암호 사용 기간" 확인.
        """
        item = "W-49. 패스워드 최소 사용 기간 설정"
        # 정책 이름: "Minimum password age"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MinimumPasswordAge (일 단위)
        # 권고: 1일 이상 (0은 즉시 변경 가능)
        
        policy_value = self._get_security_policy_setting("MinimumPasswordAge")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "패스워드 최소 사용 기간 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value >= 1:
            self._record_result(item, "PASS", f"패스워드 최소 사용 기간이 {policy_value}일로 적절하게 설정되어 있습니다.",
                                current_value=f"{policy_value}일", recommended_value="1일 이상")
        else:
            self._record_result(item, "VULNERABLE",
                                f"패스워드 최소 사용 기간이 {policy_value}일로 너무 짧게 설정되어 있습니다. 1일 이상으로 설정하십시오.",
                                current_value=f"{policy_value}일", recommended_value="1일 이상")

    def check_w50_password_max_age(self):
        """
        W-50: 패스워드 최대 사용 기간 설정
        - 점검기준: 패스워드 최대 사용 기간이 90일 이내로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "최대 암호 사용 기간" 확인.
        """
        item = "W-50. 패스워드 최대 사용 기간 설정"
        # 정책 이름: "Maximum password age"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge (일 단위)
        # 권고: 90일 이내 (0은 만료되지 않음)
        
        policy_value = self._get_security_policy_setting("MaximumPasswordAge")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "패스워드 최대 사용 기간 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value <= 90 and policy_value > 0:
            self._record_result(item, "PASS", f"패스워드 최대 사용 기간이 {policy_value}일로 적절하게 설정되어 있습니다.",
                                current_value=f"{policy_value}일", recommended_value="90일 이내 (0 제외)")
        elif policy_value == 0:
            self._record_result(item, "VULNERABLE", "패스워드 최대 사용 기간이 '0'(만료되지 않음)으로 설정되어 있습니다. 90일 이내로 설정하십시오.",
                                current_value="0일", recommended_value="90일 이내 (0 제외)")
        else:
            self._record_result(item, "VULNERABLE",
                                f"패스워드 최대 사용 기간이 {policy_value}일로 너무 길게 설정되어 있습니다. 90일 이내로 설정하십시오.",
                                current_value=f"{policy_value}일", recommended_value="90일 이내 (0 제외)")

    def check_w51_password_min_length(self):
        """
        W-51: 패스워드 길이 설정 (W-01과 동일)
        - 점검기준: 최소 암호 길이가 8자 이상으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 또는 'net accounts' 명령어로 확인.
        """
        # W-01과 동일한 점검이므로 W-01을 호출합니다.
        self.check_w01_password_policy()
        self.results[-1]['item'] = "W-51. 패스워드 길이 설정" # 항목명만 변경

    def check_w52_password_history(self):
        """
        W-52: 패스워드 기록 강제 적용
        - 점검기준: "암호 기록 강제 적용" 정책이 24개 암호 이상으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "암호 기록 강제 적용" 확인.
        """
        item = "W-52. 패스워드 기록 강제 적용"
        # 정책 이름: "Enforce password history"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\PasswordHistorySize (개수)
        # 권고: 24개 이상
        
        policy_value = self._get_security_policy_setting("PasswordHistorySize")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "패스워드 기록 강제 적용 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value >= 24:
            self._record_result(item, "PASS", f"패스워드 기록 강제 적용이 {policy_value}개로 적절하게 설정되어 있습니다.",
                                current_value=f"{policy_value}개", recommended_value="24개 이상")
        else:
            self._record_result(item, "VULNERABLE",
                                f"패스워드 기록 강제 적용이 {policy_value}개로 너무 적게 설정되어 있습니다. 24개 이상으로 설정하십시오.",
                                current_value=f"{policy_value}개", recommended_value="24개 이상")

    def check_w53_account_lockout_duration_policy(self):
        """
        W-53: 계정 잠금 기간 설정 (W-47과 동일)
        - 점검기준: 계정 잠금 기간이 10분 이상으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "계정 잠금 기간" 확인.
        """
        # W-47과 동일한 점검이므로 W-47을 호출합니다.
        self.check_w47_account_lockout_duration()
        self.results[-1]['item'] = "W-53. 계정 잠금 기간 설정" # 항목명만 변경

    def check_w54_account_lockout_threshold_policy(self):
        """
        W-54: 계정 잠금 횟수 제한 (W-02와 동일)
        - 점검기준: 계정 잠금 임계값이 5회 이하로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 또는 'net accounts' 명령어로 확인.
        """
        # W-02와 동일한 점검이므로 W-02를 호출합니다.
        self.check_w02_account_lockout_threshold()
        self.results[-1]['item'] = "W-54. 계정 잠금 횟수 제한" # 항목명만 변경

    def check_w55_reset_account_lockout_counter_after(self):
        """
        W-55: 계정 잠금 다시 설정 기간 설정
        - 점검기준: "계정 잠금 카운터 재설정" 정책이 10분 이내로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "계정 잠금 카운터 재설정" 확인.
        """
        item = "W-55. 계정 잠금 다시 설정 기간 설정"
        # 정책 이름: "Reset account lockout counter after"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ResetLockoutCount (초 단위)
        # 권고: 10분 (600초) 이내
        
        policy_value = self._get_security_policy_setting("ResetLockoutCount")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "계정 잠금 카운터 재설정 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value <= 600 and policy_value > 0: # 0은 "재설정 안 함"으로 취약
            self._record_result(item, "PASS",
                                f"계정 잠금 카운터 재설정 기간이 {policy_value/60}분({policy_value}초)으로 적절하게 설정되어 있습니다.",
                                current_value=f"{policy_value/60}분", recommended_value="10분 이내 (0 제외)")
        else:
            self._record_result(item, "VULNERABLE",
                                f"계정 잠금 카운터 재설정 기간이 {policy_value/60}분({policy_value}초)으로 너무 길거나 0으로 설정되어 있습니다. 10분 이내로 설정하십시오.",
                                current_value=f"{policy_value/60}분", recommended_value="10분 이내 (0 제외)")

    def check_w56_last_logon_time_recording(self):
        """
        W-56: 마지막 로그온 시간 기록
        - 점검기준: "대화형 로그온: 마지막 사용자 로그온 표시" 정책이 '사용'으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "대화형 로그온: 마지막 사용자 로그온 표시" 확인.
        """
        item = "W-56. 마지막 로그온 시간 기록"
        # 정책 이름: "Interactive logon: Display last user logon"
        # 레지스트리: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisplayLastLogonInfo (1: 사용, 0: 사용 안 함)
        
        policy_value = self._get_security_policy_setting("DisplayLastLogonInfo")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "마지막 로그온 시간 기록 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 1:
            self._record_result(item, "PASS", "마지막 로그온 시간 기록 정책이 '사용'으로 설정되어 있습니다.",
                                current_value="사용 (1)", recommended_value="사용 (1)")
        else:
            self._record_result(item, "VULNERABLE", "마지막 로그온 시간 기록 정책이 '사용 안 함'으로 설정되어 있습니다. '사용'으로 변경하십시오.",
                                current_value="사용 안 함 (0)", recommended_value="사용 (1)")

    def check_w57_limit_blank_passwords_for_local_accounts(self):
        """
        W-57: 로컬 계정의 빈 암호 사용 제한
        - 점검기준: "계정: 로컬 계정의 빈 암호 사용 제한" 정책이 '사용'으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "계정: 로컬 계정의 빈 암호 사용 제한" 확인.
        """
        item = "W-57. 로컬 계정의 빈 암호 사용 제한"
        # 정책 이름: "Accounts: Limit local account use of blank passwords to console logon only"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse (1: 사용, 0: 사용 안 함)
        
        policy_value = self._get_security_policy_setting("LimitBlankPasswordUse")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "로컬 계정의 빈 암호 사용 제한 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 1:
            self._record_result(item, "PASS", "로컬 계정의 빈 암호 사용 제한 정책이 '사용'으로 설정되어 있습니다.",
                                current_value="사용 (1)", recommended_value="사용 (1)")
        else:
            self._record_result(item, "VULNERABLE", "로컬 계정의 빈 암호 사용 제한 정책이 '사용 안 함'으로 설정되어 있습니다. '사용'으로 변경하십시오.",
                                current_value="사용 안 함 (0)", recommended_value="사용 (1)")


class FilePermissionAudit(AuditModule):
    """
    Windows 파일 및 디렉터리 관리 보안 점검을 수행하는 모듈입니다.
    - W-05: 시스템 파일 접근 통제
    - W-06: 로그 파일 접근 통제
    - W-45: 디스크볼륨 암호화 설정
    """
    def __init__(self, config):
        super().__init__(config)
        self.file_config = self.config.get('file_directory_management', {})

    def run_audit(self):
        self.results = []
        logging.info(f"Starting {self.module_name} audit...")

        self.check_w05_system_file_access_control()
        self.check_w06_log_file_access_control()
        self.check_w45_disk_volume_encryption()

        logging.info(f"Completed {self.module_name} audit.")
        return self.results

    def check_w05_system_file_access_control(self):
        """
        W-05: 시스템 파일 접근 통제
        - 점검기준: 시스템 중요 파일(예: system32, drivers)에 대한 접근 권한이 적절하게 설정되어 있는 경우 양호.
                    Everyone에 쓰기/수정/모든 권한이 부여되지 않은 경우 양호.
        - 점검방법: icacls 명령어로 확인. (수동 점검 필요성 제시)
        """
        item = "W-05. 시스템 파일 접근 통제"
        # 중요 시스템 파일 경로는 config에서 관리하거나, 여기 직접 명시
        # 예시: C:\Windows\System32, C:\Windows\System32\drivers
        
        # 자동 점검은 복잡하므로, 주요 디렉터리에 대한 Everyone 권한만 간단히 확인
        system_dirs_to_check = [
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers')
        ]
        
        vulnerable_dirs = []
        for dir_path in system_dirs_to_check:
            if not os.path.exists(dir_path):
                logging.warning(f"시스템 디렉터리 '{dir_path}'를 찾을 수 없습니다. 점검을 건너뜝니다.")
                continue

            try:
                cmd_output = self._execute_powershell(f"icacls \"{dir_path}\"")
                if cmd_output is None:
                    vulnerable_dirs.append(f"{dir_path} (권한 확인 불가)")
                    continue

                # Everyone에게 쓰기(W), 수정(M), 모든 권한(F)이 있는지 확인
                if re.search(r"Everyone:\(.*?F.*?\)", cmd_output, re.IGNORECASE) or \
                   re.search(r"Everyone:\(.*?M.*?\)", cmd_output, re.IGNORECASE) or \
                   re.search(r"Everyone:\(.*?W.*?\)", cmd_output, re.IGNORECASE):
                    vulnerable_dirs.append(f"{dir_path} (Everyone에 쓰기/수정/모든 권한)")
            except Exception as e:
                logging.error(f"'{dir_path}' 권한 확인 중 오류 발생: {e}")
                vulnerable_dirs.append(f"{dir_path} (점검 오류)")

        if vulnerable_dirs:
            self._record_result(item, "VULNERABLE",
                                f"일부 시스템 중요 디렉터리에 부적절한 권한이 설정되어 있습니다: {', '.join(vulnerable_dirs)}. Everyone에 대한 쓰기/수정/모든 권한을 제거하십시오.",
                                current_value=f"취약 디렉터리: {', '.join(vulnerable_dirs)}",
                                recommended_value="Everyone에 쓰기/수정/모든 권한 없음")
        else:
            self._record_result(item, "PASS", "주요 시스템 디렉터리에 Everyone에 대한 쓰기/수정/모든 권한이 없습니다.",
                                current_value="적절", recommended_value="Everyone에 쓰기/수정/모든 권한 없음")


    def check_w06_log_file_access_control(self):
        """
        W-06: 로그 파일 접근 통제
        - 점검기준: 시스템 로그 파일에 대한 접근 권한이 적절하게 설정되어 있는 경우 양호.
                    Everyone에 쓰기/수정/모든 권한이 부여되지 않은 경우 양호.
        - 점검방법: icacls 명령어로 확인. (수동 점검 필요성 제시)
        """
        item = "W-06. 로그 파일 접근 통제"
        # 주요 로그 파일 경로 (예시)
        log_dirs_to_check = [
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'winevt', 'Logs'), # 이벤트 로그
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Logs') # 기타 시스템 로그
        ]

        vulnerable_log_dirs = []
        for dir_path in log_dirs_to_check:
            if not os.path.exists(dir_path):
                logging.warning(f"로그 디렉터리 '{dir_path}'를 찾을 수 없습니다. 점검을 건너뜝니다.")
                continue

            try:
                cmd_output = self._execute_powershell(f"icacls \"{dir_path}\"")
                if cmd_output is None:
                    vulnerable_log_dirs.append(f"{dir_path} (권한 확인 불가)")
                    continue

                # Everyone에게 쓰기(W), 수정(M), 모든 권한(F)이 있는지 확인
                if re.search(r"Everyone:\(.*?F.*?\)", cmd_output, re.IGNORECASE) or \
                   re.search(r"Everyone:\(.*?M.*?\)", cmd_output, re.IGNORECASE) or \
                   re.search(r"Everyone:\(.*?W.*?\)", cmd_output, re.IGNORECASE):
                    vulnerable_log_dirs.append(f"{dir_path} (Everyone에 쓰기/수정/모든 권한)")
            except Exception as e:
                logging.error(f"'{dir_path}' 권한 확인 중 오류 발생: {e}")
                vulnerable_log_dirs.append(f"{dir_path} (점검 오류)")

        if vulnerable_log_dirs:
            self._record_result(item, "VULNERABLE",
                                f"일부 로그 디렉터리에 부적절한 권한이 설정되어 있습니다: {', '.join(vulnerable_log_dirs)}. Everyone에 대한 쓰기/수정/모든 권한을 제거하십시오.",
                                current_value=f"취약 디렉터리: {', '.join(vulnerable_log_dirs)}",
                                recommended_value="Everyone에 쓰기/수정/모든 권한 없음")
        else:
            self._record_result(item, "PASS", "주요 로그 디렉터리에 Everyone에 대한 쓰기/수정/모든 권한이 없습니다.",
                                current_value="적절", recommended_value="Everyone에 쓰기/수정/모든 권한 없음")

    def check_w45_disk_volume_encryption(self):
        """
        W-45: 디스크볼륨 암호화 설정 (BitLocker)
        - 점검기준: 모든 디스크 볼륨이 암호화되어 있는 경우 양호.
        - 점검방법: 'manage-bde -status' 명령어로 확인.
        """
        item = "W-45. 디스크볼륨 암호화 설정"
        try:
            cmd_output = self._execute_powershell("manage-bde -status")
            if cmd_output:
                lines = cmd_output.splitlines()
                unencrypted_volumes = []
                
                current_volume = None
                for line in lines:
                    if "Volume C:" in line or "Volume D:" in line or "Volume E:" in line: # 주요 드라이브만 확인
                        current_volume = line.strip()
                    elif current_volume and "Conversion Status:" in line:
                        if "Fully Decrypted" in line or "Decryption in Progress" in line:
                            unencrypted_volumes.append(current_volume.split(':')[0]) # "Volume C" -> "C"
                        current_volume = None # 다음 볼륨을 위해 초기화
                
                if not unencrypted_volumes:
                    self._record_result(item, "PASS", "모든 디스크 볼륨이 암호화되어 있습니다.",
                                        current_value="모든 볼륨 암호화됨", recommended_value="모든 볼륨 암호화")
                else:
                    self._record_result(item, "VULNERABLE",
                                        f"다음 디스크 볼륨이 암호화되어 있지 않습니다: {', '.join(unencrypted_volumes)}. 모든 볼륨을 암호화하십시오.",
                                        current_value=f"미암호화 볼륨: {', '.join(unencrypted_volumes)}",
                                        recommended_value="모든 볼륨 암호화")
            else:
                self._record_result(item, "ERROR", "manage-bde -status 명령어 실행에 실패했습니다. BitLocker가 설치되지 않았거나 권한 문제입니다.")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")


class ServiceManagementAudit(AuditModule):
    """
    Windows 서비스 관리 보안 점검을 수행하는 모듈입니다.
    - W-07: 공유 권한 및 사용자 그룹 설정 (공유 폴더 점검 - FilePermissionAudit으로 이동)
    - W-08: 하드디스크 기본 공유 제거 (FilePermissionAudit으로 이동)
    - W-09: 불필요한 서비스 제거
    - W-10: IIS 서비스 구동 점검
    - W-11: IIS 디렉터리 리스팅 제거
    - W-12: IIS CGI 실행 제한
    - W-13: IIS 상위 디렉터리 접근 금지
    - W-14: IIS 불필요한 파일 제거
    - W-15: IIS 웹프로세스 권한 제한
    - W-16: IIS 링크 사용 금지
    - W-17: IIS 파일 업로드 및 다운로드 제한
    - W-18: IIS DB 연결 취약점 점검
    - W-19: IIS 가상 디렉터리 삭제
    - W-20: IIS 데이터파일 ACL 적용
    - W-21: IIS 미사용 스크립트 매핑 제거
    - W-22: IIS Exec 명령어 쉘 호출 진단
    - W-23: IIS WebDAV 비활성화
    - W-24: NetBIOS 바인딩 서비스 구동 점검
    - W-25: FTP 서비스 구동 점검
    - W-26: FTP 디렉터리 접근권한 설정 (FilePermissionAudit으로 이동)
    - W-27: Anonymous FTP 금지
    - W-28: FTP 접근 제어 설정
    - W-29: DNS Zone Transfer 설정
    - W-30: RDS(Remote Data Services) 제거
    - W-58: 터미널 서비스 암호화 수준 설정
    - W-59: IIS 웹 서비스 정보 숨김
    - W-60: SNMP 서비스 구동 점검
    - W-61: SNMP 서비스 커뮤니티스트링의 복잡성 설정
    - W-62: SNMP Access control 설정
    - W-63: DNS 서비스 구동 점검
    - W-64: HTTP/FTP/SMTP 배너 차단
    - W-65: Telnet 보안 설정
    - W-66: 불필요한 ODBC/OLE-DB 데이터소스와 드라이브 제거
    - W-67: 원격터미널 접속 타임아웃 설정
    - W-68: 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검
    """
    def __init__(self, config):
        super().__init__(config)
        self.service_config = self.config.get('service_management', {})

    def run_audit(self):
        """
        서비스 관리 점검 항목들을 실행합니다.
        """
        self.results = [] # 이전 실행 결과 초기화
        logging.info(f"Starting {self.module_name} audit...")

        self.check_w09_unnecessary_services()
        self.check_w10_iis_service_status()
        self.check_w11_iis_directory_listing()
        self.check_w12_iis_cgi_execution_restriction()
        self.check_w13_iis_parent_path_access()
        self.check_w14_iis_unnecessary_files()
        self.check_w15_iis_web_process_privilege()
        self.check_w16_iis_link_usage()
        self.check_w17_iis_file_upload_download_limit()
        self.check_w18_iis_db_connection_vulnerability()
        self.check_w19_iis_virtual_directory_deletion()
        self.check_w20_iis_data_file_acl()
        self.check_w21_iis_unused_script_mapping()
        self.check_w22_iis_exec_command_shell_call()
        self.check_w23_iis_webdav_disable()
        self.check_w24_netbios_binding_service()
        self.check_w25_ftp_service_status()
        self.check_w27_anonymous_ftp()
        self.check_w28_ftp_access_control()
        self.check_w29_dns_zone_transfer()
        self.check_w30_rds_removal()
        self.check_w58_terminal_service_encryption_level()
        self.check_w59_iis_web_service_info_hiding()
        self.check_w60_snmp_service_status()
        self.check_w61_snmp_community_string_complexity()
        self.check_w62_snmp_access_control()
        self.check_w63_dns_service_status()
        self.check_w64_http_ftp_smtp_banner_blocking()
        self.check_w65_telnet_security_settings()
        self.check_w66_unnecessary_odbc_oledb_removal()
        self.check_w67_remote_terminal_timeout()
        self.check_w68_scheduled_tasks_review()

        logging.info(f"Completed {self.module_name} audit.")
        return self.results

    def check_w09_unnecessary_services(self):
        """
        W-09: 불필요한 서비스 제거
        - 점검기준: 일반적으로 불필요한 서비스가 중지되어 있는 경우 양호. 구동 중인 경우 취약.
        - 점검방법: 서비스 관리자 (SERVICES.MSC) 또는 'Get-Service' 명령어로 확인.
        """
        item = "W-09. 불필요한 서비스 제거"
        # PDF에 명시된 "일반적으로 불필요한 서비스" 목록 (일부만 예시)
        unnecessary_services = self.service_config.get('unnecessary_services', [
            "Alerter", "Automatic Updates", "Clipbook", "Computer Browser", "Error Reporting Service",
            "Messenger", "NetMeeting Remote Desktop Sharing", "Remote Registry", "Simple TCP/IP Services",
            "Wireless Zero Configuration", "Print Spooler" # 프린터 없는 경우
        ])

        vulnerable_services = []
        for service in unnecessary_services:
            status, start_type = self._get_service_status(service)
            if status == "Running":
                vulnerable_services.append(f"{service} (상태: {status}, 시작 유형: {start_type})")

        if not vulnerable_services:
            self._record_result(item, "PASS", "불필요하다고 판단되는 서비스가 실행 중이지 않습니다.",
                                current_value="모든 불필요 서비스 중지", recommended_value="불필요 서비스 중지 및 사용 안 함")
        else:
            self._record_result(item, "VULNERABLE",
                                f"다음 불필요한 서비스가 실행 중입니다: {', '.join(vulnerable_services)}. 담당자 인터뷰를 통해 필요 여부를 확인하고 중지 및 사용 안 함으로 설정하십시오.",
                                current_value=f"실행 중: {', '.join([s.split(' ')[0] for s in vulnerable_services])}",
                                recommended_value="불필요 서비스 중지 및 사용 안 함")

    def check_w10_iis_service_status(self):
        """
        W-10: IIS 서비스 구동 점검
        - 점검기준: IIS 서비스가 필요하지 않아 이용하지 않는 경우 양호. 필요하지 않지만 사용하는 경우 취약.
        - 점검방법: 서비스 관리자 (SERVICES.MSC)에서 'World Wide Web Publishing Service' 상태 확인.
        """
        item = "W-10. IIS 서비스 구동 점검"
        # World Wide Web Publishing Service (W3SVC)는 IIS의 핵심 서비스
        status, start_type = self._get_service_status("W3SVC")

        if status == "Stopped" and start_type == "Disabled":
            self._record_result(item, "PASS", "IIS 서비스(World Wide Web Publishing Service)가 중지 및 사용 안 함으로 설정되어 있습니다.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        elif status == "Running":
            self._record_result(item, "VULNERABLE",
                                f"IIS 서비스(World Wide Web Publishing Service)가 실행 중입니다. 필요하지 않다면 중지 및 사용 안 함으로 설정하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        else:
            self._record_result(item, "MANUAL",
                                f"IIS 서비스(World Wide Web Publishing Service) 상태를 확인하십시오. (현재 상태: {status}, 시작 유형: {start_type}) 필요 여부는 담당자 인터뷰를 통해 확인하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")

    def check_w11_iis_directory_listing(self):
        """
        W-11: IIS 디렉터리 리스팅 제거
        - 점검기준: "디렉터리 검색" 체크하지 않음 (IIS 2000, 2003) 또는 "사용 안 함" (IIS 2008 이상)인 경우 양호.
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 확인.
        """
        item = "W-11. IIS 디렉터리 리스팅 제거"
        try:
            # IIS가 설치되어 있는지 먼저 확인
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # appcmd.exe를 사용하여 Default Web Site의 directoryBrowse 설정 확인
            # IIS 7.0 이상 (Windows Server 2008 이상)
            cmd_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default Web Site"" /text:* /section:directoryBrowse")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "IIS 디렉터리 리스팅 설정을 확인할 수 없습니다. (appcmd 실행 실패 또는 IIS 설치 안 됨)")
                return

            # enabled="true" 인지 확인
            if 'enabled="true"' in cmd_output.lower():
                self._record_result(item, "VULNERABLE",
                                    "IIS 디렉터리 리스팅이 활성화되어 있습니다. 비활성화하십시오.",
                                    current_value="활성화 (enabled=true)",
                                    recommended_value="비활성화 (enabled=false)")
            else:
                self._record_result(item, "PASS",
                                    "IIS 디렉터리 리스팅이 비활성화되어 있습니다.",
                                    current_value="비활성화 (enabled=false)",
                                    recommended_value="비활성화 (enabled=false)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w12_iis_cgi_execution_restriction(self):
        """
        W-12: IIS CGI 실행 제한
        - 점검기준: CGI 스크립트 디렉터리(C:\inetpub\scripts)에 Everyone에 모든 권한, 수정 권한, 쓰기 권한이 부여되지 않은 경우 양호.
                    부여되어 있는 경우 취약.
        - 점검방법: icacls 명령어로 C:\inetpub\scripts 디렉터리 권한 확인.
        """
        item = "W-12. IIS CGI 실행 제한"
        cgi_script_dir = os.path.join(os.environ.get('SystemDrive', 'C:'), 'inetpub', 'scripts')

        if not os.path.exists(cgi_script_dir):
            self._record_result(item, "N/A", f"CGI 스크립트 디렉터리 '{cgi_script_dir}'가 존재하지 않습니다. (IIS 초기 구축 시 생성되지 않을 수 있음)")
            return

        try:
            # icacls 명령어를 사용하여 Everyone 권한 확인
            # 'F' (Full Control), 'M' (Modify), 'W' (Write) 권한이 Everyone에 부여되어 있는지 확인
            cmd_output = self._execute_powershell(f"icacls \"{cgi_script_dir}\"")
            
            if cmd_output is None:
                self._record_result(item, "ERROR", f"'{cgi_script_dir}' 디렉터리 권한을 확인할 수 없습니다.")
                return

            is_vulnerable = False
            # Everyone:(F), Everyone:(M), Everyone:(W) 또는 Everyone ALLOW (F), Everyone ALLOW (M), Everyone ALLOW (W)
            if re.search(r"Everyone:\(.*?F.*?\)", cmd_output, re.IGNORECASE) or \
               re.search(r"Everyone:\(.*?M.*?\)", cmd_output, re.IGNORECASE) or \
               re.search(r"Everyone:\(.*?W.*?\)", cmd_output, re.IGNORECASE) or \
               re.search(r"Everyone\s+ALLOW\s+\(F\)", cmd_output, re.IGNORECASE) or \
               re.search(r"Everyone\s+ALLOW\s+\(M\)", cmd_output, re.IGNORECASE) or \
               re.search(r"Everyone\s+ALLOW\s+\(W\)", cmd_output, re.IGNORECASE):
                is_vulnerable = True

            if is_vulnerable:
                self._record_result(item, "VULNERABLE",
                                    f"CGI 스크립트 디렉터리 '{cgi_script_dir}'에 Everyone에 대한 쓰기/수정/모든 권한이 부여되어 있습니다. 해당 권한을 제거하십시오.",
                                    current_value=f"Everyone 권한: {cmd_output.splitlines()[-1]}", # 마지막 라인에 권한 정보가 있을 수 있음
                                    recommended_value="Everyone에 쓰기/수정/모든 권한 없음")
            else:
                self._record_result(item, "PASS",
                                    f"CGI 스크립트 디렉터리 '{cgi_script_dir}'에 Everyone에 대한 쓰기/수정/모든 권한이 부여되어 있지 않습니다.",
                                    current_value=f"Everyone 권한: {cmd_output.splitlines()[-1]}",
                                    recommended_value="Everyone에 쓰기/수정/모든 권한 없음")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w13_iis_parent_path_access(self):
        """
        W-13: IIS 상위 디렉터리 접근 금지
        - 점검기준: 상위 디렉터리 접근 기능이 제거된 경우 양호. 제거되지 않은 경우 취약.
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 "부모 경로 사용" (enableParentPaths) 설정 확인.
        """
        item = "W-13. IIS 상위 디렉터리 접근 금지"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # appcmd.exe를 사용하여 Default Web Site의 asp enableParentPaths 설정 확인
            cmd_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default Web Site"" /text:* /section:asp")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "IIS 상위 디렉터리 접근 설정을 확인할 수 없습니다. (appcmd 실행 실패 또는 IIS 설치 안 됨)")
                return

            # enableParentPaths="true" 인지 확인
            if 'enableparentpaths="true"' in cmd_output.lower():
                self._record_result(item, "VULNERABLE",
                                    "IIS 상위 디렉터리 접근(부모 경로 사용)이 활성화되어 있습니다. 비활성화하십시오.",
                                    current_value="활성화 (enableParentPaths=true)",
                                    recommended_value="비활성화 (enableParentPaths=false)")
            else:
                self._record_result(item, "PASS",
                                    "IIS 상위 디렉터리 접근(부모 경로 사용)이 비활성화되어 있습니다.",
                                    current_value="비활성화 (enableParentPaths=false)",
                                    recommended_value="비활성화 (enableParentPaths=false)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w14_iis_unnecessary_files(self):
        """
        W-14: IIS 불필요한 파일 제거
        - 점검기준: IISSamples, IISHelp 등 불필요한 샘플 디렉터리가 존재하지 않는 경우 양호. 존재하는 경우 취약.
        - 점검방법: 특정 경로의 디렉터리 존재 여부 확인.
        """
        item = "W-14. IIS 불필요한 파일 제거"
        unnecessary_iis_dirs = self.service_config.get('unnecessary_iis_directories', [
            os.path.join(os.environ.get('SystemDrive', 'C:'), 'inetpub', 'iissamples'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'help', 'iishelp'),
            os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Common Files', 'System', 'msadc', 'sample'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'Inetsrv', 'IISADMPWD')
        ])

        found_vulnerable_dirs = []
        for dir_path in unnecessary_iis_dirs:
            if os.path.exists(dir_path):
                found_vulnerable_dirs.append(dir_path)

        if found_vulnerable_dirs:
            self._record_result(item, "VULNERABLE",
                                f"불필요한 IIS 샘플 디렉터리가 존재합니다: {', '.join(found_vulnerable_dirs)}. 제거하십시오.",
                                current_value=f"존재: {', '.join(found_vulnerable_dirs)}",
                                recommended_value="제거")
        else:
            self._record_result(item, "PASS", "불필요한 IIS 샘플 디렉터리가 존재하지 않습니다.",
                                current_value="없음",
                                recommended_value="제거")

    def check_w15_iis_web_process_privilege(self):
        """
        W-15: IIS 웹프로세스 권한 제한
        - 점검기준: 웹 프로세스가 웹 서비스 운영에 필요한 최소한 권한으로 설정되어 있는 경우 양호.
                    관리자 권한이 부여된 계정으로 구동되고 있는 경우 취약.
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 Application Pool의 IdentityType 확인.
        """
        item = "W-15. IIS 웹프로세스 권한 제한"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # appcmd.exe를 사용하여 모든 Application Pool의 processModel identityType 확인
            cmd_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config /section:applicationPools")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "IIS Application Pool 설정을 확인할 수 없습니다. (appcmd 실행 실패 또는 IIS 설치 안 됨)")
                return

            # identityType="LocalSystem" 인지 확인
            if 'identitytype="localsystem"' in cmd_output.lower():
                self._record_result(item, "VULNERABLE",
                                    "하나 이상의 IIS Application Pool이 LocalSystem 계정으로 실행되도록 설정되어 있습니다. 최소 권한 계정으로 변경하십시오.",
                                    current_value="LocalSystem 사용",
                                    recommended_value="ApplicationPoolIdentity 또는 NetworkService")
            else:
                self._record_result(item, "PASS",
                                    "모든 IIS Application Pool이 최소 권한 계정으로 설정되어 있습니다.",
                                    current_value="LocalSystem 미사용",
                                    recommended_value="ApplicationPoolIdentity 또는 NetworkService")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w16_iis_link_usage(self):
        """
        W-16: IIS 링크 사용 금지
        - 점검기준: 심볼릭 링크, aliases, 바로가기 등의 사용을 허용하지 않는 경우 양호. 허용하는 경우 취약.
        - 점검방법: 웹 홈 디렉터리 내 .lnk 파일 등 바로가기/링크 파일 존재 여부 확인.
        """
        item = "W-16. IIS 링크 사용 금지"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return
            
            # Default Web Site의 실제 경로 (physicalPath) 확인
            get_path_command = r"C:\Windows\System32\inetsrv\appcmd.exe list app ""Default Web Site/"" /text:* /section:system.applicationHost/sites"
            path_output = self._execute_powershell(get_path_command)
            
            if path_output is None:
                self._record_result(item, "UNKNOWN", "IIS 웹 홈 디렉터리 경로를 확인할 수 없습니다.")
                return

            home_dir_match = re.search(r'physicalPath="([^"]+)"', path_output)
            iis_home_dir = home_dir_match.group(1) if home_dir_match else None

            if not iis_home_dir or not os.path.exists(iis_home_dir):
                self._record_result(item, "UNKNOWN", f"IIS 웹 홈 디렉터리 '{iis_home_dir}'를 찾을 수 없습니다.")
                return

            # 홈 디렉터리 내 .lnk 파일 (바로가기) 존재 여부 확인
            found_links = []
            for root, _, files in os.walk(iis_home_dir):
                for file in files:
                    if file.lower().endswith(".lnk"):
                        found_links.append(os.path.join(root, file))
            
            if found_links:
                self._record_result(item, "VULNERABLE",
                                    f"IIS 웹 홈 디렉터리 내에 바로가기/링크 파일(.lnk)이 존재합니다. 제거하십시오. (발견된 파일: {', '.join(found_links)})",
                                    current_value=f"존재: {len(found_links)}개",
                                    recommended_value="링크 파일 없음")
            else:
                self._record_result(item, "PASS", "IIS 웹 홈 디렉터리 내에 바로가기/링크 파일이 존재하지 않습니다.",
                                    current_value="없음",
                                    recommended_value="링크 파일 없음")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w17_iis_file_upload_download_limit(self):
        """
        W-17: IIS 파일 업로드 및 다운로드 제한
        - 점검기준: 업로드 및 다운로드 용량을 제한하는 경우 양호. 미 제한하는 경우 취약.
                    (권고: 5MB 이하 설정)
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 "응답 버퍼링 제한", "최대 요청 엔터티 본문 제한", "허용되는 최대 콘텐츠 길이" 확인.
        """
        item = "W-17. IIS 파일 업로드 및 다운로드 제한"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # 1. ASP bufferingLimit 및 maxRequestEntityAllowed 확인 (IIS 7.0 이상)
            asp_config_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default Web Site"" /text:* /section:asp")
            
            buffering_limit = None
            max_request_entity = None

            if asp_config_output:
                buffering_match = re.search(r'bufferingLimit="(\d+)"', asp_config_output)
                if buffering_match:
                    buffering_limit = int(buffering_match.group(1))
                
                max_entity_match = re.search(r'maxRequestEntityAllowed="(\d+)"', asp_config_output)
                if max_entity_match:
                    max_request_entity = int(max_entity_match.group(1))

            # 2. Request Filtering maxAllowedContentLength 확인 (IIS 7.0 이상)
            req_filtering_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default Web Site"" /text:* /section:requestFiltering")
            
            max_allowed_content_length = None
            if req_filtering_output:
                max_content_match = re.search(r'maxAllowedContentLength="(\d+)"', req_filtering_output)
                if max_content_match:
                    max_allowed_content_length = int(max_content_match.group(1))

            # 권고 기준: 5MB (5242880 바이트) 이하
            recommended_max_bytes = 5242880 # 5MB

            vulnerable_settings = []
            if buffering_limit is None or buffering_limit == 0 or buffering_limit > recommended_max_bytes:
                vulnerable_settings.append(f"응답 버퍼링 제한 (현재: {buffering_limit} bytes)")
            if max_request_entity is None or max_request_entity == 0 or max_request_entity > recommended_max_bytes:
                vulnerable_settings.append(f"최대 요청 엔터티 본문 제한 (현재: {max_request_entity} bytes)")
            if max_allowed_content_length is None or max_allowed_content_length == 0 or max_allowed_content_length > recommended_max_bytes:
                vulnerable_settings.append(f"허용되는 최대 콘텐츠 길이 (현재: {max_allowed_content_length} bytes)")

            if not vulnerable_settings:
                self._record_result(item, "PASS",
                                    "IIS 파일 업로드 및 다운로드 용량 제한이 적절하게 설정되어 있습니다. (5MB 이하)",
                                    current_value=f"버퍼링: {buffering_limit}, 요청 엔터티: {max_request_entity}, 콘텐츠 길이: {max_allowed_content_length}",
                                    recommended_value="모두 5MB 이하")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"IIS 파일 업로드 및 다운로드 용량 제한 설정이 부적절합니다: {', '.join(vulnerable_settings)}. 각 항목을 5MB 이하로 설정하십시오.",
                                    current_value=f"버퍼링: {buffering_limit}, 요청 엔터티: {max_request_entity}, 콘텐츠 길이: {max_allowed_content_length}",
                                    recommended_value="모두 5MB 이하")

        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w18_iis_db_connection_vulnerability(self):
        """
        W-18: IIS DB 연결 취약점 점검 (.asa, .asax 매핑)
        - 점검기준: .asa, .asax 매핑 시 특정 동작만 가능하도록 제한하거나 매핑이 없을 경우 양호.
                    모든 동작이 가능하도록 설정한 경우 취약.
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 요청 필터링 및 처리기 매핑 확인.
        """
        item = "W-18. IIS DB 연결 취약점 점검"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # 1. 요청 필터링 (.asa, .asax) 확인 (IIS 7.0 이상)
            req_filtering_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default Web Site"" /text:* /section:system.webServer/security/requestFiltering")
            
            is_vulnerable_req_filtering = False
            if req_filtering_output:
                # .asa 또는 .asax가 허용되어 있는지 확인
                if re.search(r'fileExtension=".asa".*?allowed="true"', req_filtering_output, re.IGNORECASE) or \
                   re.search(r'fileExtension=".asax".*?allowed="true"', req_filtering_output, re.IGNORECASE):
                    is_vulnerable_req_filtering = True
                # 또는 .asa, .asax가 아예 등록되어 있지 않은 경우 (기본적으로 거부되지 않으므로 취약)
                if not re.search(r'fileExtension=".asa"', req_filtering_output, re.IGNORECASE) and \
                   not re.search(r'fileExtension=".asax"', req_filtering_output, re.IGNORECASE):
                    is_vulnerable_req_filtering = True # 명시적으로 거부되지 않으면 취약

            # 2. 처리기 매핑 (.asa, .asax) 확인 (IIS 7.0 이상)
            handlers_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default Web Site"" /text:* /section:system.webServer/handlers")
            
            is_vulnerable_handlers = False
            if handlers_output:
                # .asa 또는 .asax에 대한 처리기 매핑이 존재하는지 확인
                if re.search(r'path=".*\.asa"', handlers_output, re.IGNORECASE) or \
                   re.search(r'path=".*\.asax"', handlers_output, re.IGNORECASE):
                    is_vulnerable_handlers = True

            if not is_vulnerable_req_filtering and not is_vulnerable_handlers:
                self._record_result(item, "PASS",
                                    "IIS DB 연결 취약점 관련 .asa, .asax 매핑 설정이 적절합니다. (매핑이 없거나 제한됨)",
                                    current_value="매핑 없음 또는 제한됨",
                                    recommended_value="매핑 없음 또는 제한됨")
            else:
                reason = []
                if is_vulnerable_req_filtering:
                    reason.append("요청 필터링에서 .asa 또는 .asax가 허용되거나 명시적으로 거부되지 않았습니다.")
                if is_vulnerable_handlers:
                    reason.append(".asa 또는 .asax에 대한 처리기 매핑이 존재합니다.")
                
                self._record_result(item, "VULNERABLE",
                                    f"IIS DB 연결 취약점이 존재합니다. .asa, .asax 매핑 설정을 검토하십시오. {'; '.join(reason)}",
                                    current_value="매핑 존재 또는 부적절한 설정",
                                    recommended_value="매핑 없음 또는 제한됨")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w19_iis_virtual_directory_deletion(self):
        """
        W-19: IIS 가상 디렉터리 삭제
        - 점검기준: IIS Admin, IIS Adminpwd 가상 디렉터리가 존재하지 않는 경우 양호 (IIS 6.0 이상 버전 양호).
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 가상 디렉터리 존재 여부 확인.
        """
        item = "W-19. IIS 가상 디렉터리 삭제"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # IIS 6.0 이상에서는 기본적으로 해당 경로가 생성되지 않으므로,
            # Windows Server 2003 이상 버전이면 양호로 간주.
            # 하지만 혹시 모를 수동 생성이나 이전 버전 호환성을 위해 실제 존재 여부를 확인하는 것이 좋습니다.
            
            # appcmd.exe를 사용하여 가상 디렉터리 목록 확인
            # (Get-WebAppPool -Name 'DefaultAppPool').Applications | Select-Object Path, PhysicalPath
            # 또는 appcmd list vdir
            
            cmd_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list vdir")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "IIS 가상 디렉터리 목록을 확인할 수 없습니다.")
                return

            vulnerable_vdirs = []
            if re.search(r'path="/iisadmin"', cmd_output, re.IGNORECASE) or \
               re.search(r'path="/iisadmpwd"', cmd_output, re.IGNORECASE):
                vulnerable_vdirs.append("/iisadmin 또는 /iisadmpwd")
            
            if vulnerable_vdirs:
                self._record_result(item, "VULNERABLE",
                                    f"불필요한 IIS 가상 디렉터리({', '.join(vulnerable_vdirs)})가 존재합니다. 제거하십시오.",
                                    current_value=f"존재: {', '.join(vulnerable_vdirs)}",
                                    recommended_value="제거")
            else:
                self._record_result(item, "PASS", "불필요한 IIS 가상 디렉터리(IISAdmin, IISAdminpwd)가 존재하지 않습니다.",
                                    current_value="없음",
                                    recommended_value="제거")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w20_iis_data_file_acl(self):
        """
        W-20: IIS 데이터파일 ACL 적용
        - 점검기준: 홈 디렉터리 내 하위 파일들에 대해 Everyone 권한이 존재하지 않는 경우 양호 (정적 콘텐츠 파일은 Read 권한만).
                    존재하는 경우 취약.
        - 점검방법: icacls 명령어로 웹 홈 디렉터리 내 파일 권한 확인.
        """
        item = "W-20. IIS 데이터파일 ACL 적용"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            get_path_command = r"C:\Windows\System32\inetsrv\appcmd.exe list app ""Default Web Site/"" /text:* /section:system.applicationHost/sites"
            path_output = self._execute_powershell(get_path_command)
            
            iis_home_dir = None
            home_dir_match = re.search(r'physicalPath="([^"]+)"', path_output)
            if home_dir_match:
                iis_home_dir = home_dir_match.group(1)

            if not iis_home_dir or not os.path.exists(iis_home_dir):
                self._record_result(item, "UNKNOWN", f"IIS 웹 홈 디렉터리 '{iis_home_dir}'를 찾을 수 없습니다.")
                return

            vulnerable_files = []
            for root, _, files in os.walk(iis_home_dir):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    # icacls 명령어로 파일 권한 확인
                    acl_output = self._execute_powershell(f"icacls \"{file_path}\"")
                    
                    if acl_output is None:
                        vulnerable_files.append(f"{file_path} (권한 확인 불가)")
                        continue

                    # Everyone 권한이 있는지 확인
                    if "Everyone:" in acl_output:
                        # 정적 콘텐츠 파일인지 확인 (예: .txt, .jpg, .html)
                        is_static_content = any(file_path.lower().endswith(ext) for ext in ['.txt', '.gif', '.jpg', '.jpeg', '.png', '.html', '.htm', '.css', '.js'])
                        
                        # Everyone에 Read 권한 외에 다른 권한이 있는지 확인
                        # (F) Full Control, (M) Modify, (W) Write, (D) Delete, (C) Change
                        if is_static_content:
                            # 정적 파일인데 Read 권한 외에 다른 권한이 있으면 취약
                            if re.search(r"Everyone:\(.*?F.*?\)", acl_output, re.IGNORECASE) or \
                               re.search(r"Everyone:\(.*?M.*?\)", acl_output, re.IGNORECASE) or \
                               re.search(r"Everyone:\(.*?W.*?\)", acl_output, re.IGNORECASE) or \
                               re.search(r"Everyone:\(.*?D.*?\)", acl_output, re.IGNORECASE) or \
                               re.search(r"Everyone:\(.*?C.*?\)", acl_output, re.IGNORECASE):
                                vulnerable_files.append(f"{file_path} (정적 파일에 Everyone 쓰기/수정/모든 권한)")
                        else:
                            # 동적 파일 또는 기타 파일은 Everyone 권한 자체가 없어야 함
                            if "Everyone:" in acl_output: # Everyone 권한이 아예 없어야 함
                                vulnerable_files.append(f"{file_path} (Everyone 권한 존재)")

            if vulnerable_files:
                self._record_result(item, "VULNERABLE",
                                    f"IIS 데이터 파일에 부적절한 Everyone 권한이 존재합니다. 검토 및 제거하십시오. (취약 파일: {', '.join(vulnerable_files)})",
                                    current_value=f"취약 파일 존재: {len(vulnerable_files)}개",
                                    recommended_value="Everyone 권한 제거 (정적 파일은 Read만 허용)")
            else:
                self._record_result(item, "PASS", "IIS 데이터 파일에 Everyone 권한이 적절하게 제한되어 있습니다.",
                                    current_value="적절",
                                    recommended_value="Everyone 권한 제거 (정적 파일은 Read만 허용)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w21_iis_unused_script_mapping(self):
        """
        W-21: IIS 미사용 스크립트 매핑 제거
        - 점검기준: 취약한 매핑(.htr, .idc, .stm, .shtm, .shtml, .printer, .htw, .ida, .idq)이 존재하지 않는 경우 양호.
                    존재하는 경우 취약.
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 처리기 매핑 확인.
        """
        item = "W-21. IIS 미사용 스크립트 매핑 제거"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # appcmd.exe를 사용하여 모든 처리기 매핑 확인
            cmd_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default Web Site"" /text:* /section:system.webServer/handlers")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "IIS 처리기 매핑 목록을 확인할 수 없습니다.")
                return

            vulnerable_extensions = [
                ".htr", ".idc", ".stm", ".shtm", ".shtml", ".printer", ".htw", ".ida", ".idq"
            ]
            
            found_vulnerable_mappings = []
            for ext in vulnerable_extensions:
                if re.search(rf'path=".*\{ext}"', cmd_output, re.IGNORECASE):
                    found_vulnerable_mappings.append(ext)

            if found_vulnerable_mappings:
                self._record_result(item, "VULNERABLE",
                                    f"미사용 또는 취약한 스크립트 매핑이 존재합니다: {', '.join(found_vulnerable_mappings)}. 제거하십시오.",
                                    current_value=f"존재: {', '.join(found_vulnerable_mappings)}",
                                    recommended_value="제거")
            else:
                self._record_result(item, "PASS", "미사용 또는 취약한 스크립트 매핑이 존재하지 않습니다.",
                                    current_value="없음",
                                    recommended_value="제거")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w22_iis_exec_command_shell_call(self):
        """
        W-22: IIS Exec 명령어 쉘 호출 진단
        - 점검기준: IIS 5.0 버전에서 해당 레지스트리 값이 0이거나, IIS 6.0 버전 이상인 경우 양호.
                    IIS 5.0 버전에서 해당 레지스트리 값이 1인 경우 취약.
        - 점검방법: 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\SSIEnableCmdDirective 확인.
        """
        item = "W-22. IIS Exec 명령어 쉘 호출 진단"
        try:
            # IIS 버전 확인 (PowerShell)
            iis_version_output = self._execute_powershell(r"(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp).MajorVersion")
            iis_major_version = int(iis_version_output) if iis_version_output else 0

            if iis_major_version >= 6: # IIS 6.0 이상
                self._record_result(item, "PASS", "IIS 6.0 이상 버전이므로 Exec 명령어 쉘 호출 취약점에 해당하지 않습니다.",
                                    current_value=f"IIS Major Version: {iis_major_version}",
                                    recommended_value="IIS 6.0 이상")
                return

            # IIS 5.0 (Windows 2000) 이하 버전일 경우 레지스트리 확인
            # HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\SSIEnableCmdDirective
            # 0: 사용 안 함 (양호), 1: 사용 (취약)
            ssi_enable_cmd_directive = self._get_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\W3SVC\Parameters",
                "SSIEnableCmdDirective"
            )

            if ssi_enable_cmd_directive is None: # 값이 없으면 기본적으로 0으로 간주 (사용 안 함)
                ssi_enable_cmd_directive = 0

            if ssi_enable_cmd_directive == 0:
                self._record_result(item, "PASS",
                                    "IIS Exec 명령어 쉘 호출이 비활성화되어 있습니다.",
                                    current_value="비활성화 (0)",
                                    recommended_value="비활성화 (0)")
            elif ssi_enable_cmd_directive == 1:
                self._record_result(item, "VULNERABLE",
                                    "IIS Exec 명령어 쉘 호출이 활성화되어 있습니다. 비활성화하십시오.",
                                    current_value="활성화 (1)",
                                    recommended_value="비활성화 (0)")
            else:
                self._record_result(item, "UNKNOWN",
                                    f"IIS Exec 명령어 쉘 호출 설정의 알 수 없는 값: {ssi_enable_cmd_directive}",
                                    current_value=str(ssi_enable_cmd_directive),
                                    recommended_value="비활성화 (0)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w23_iis_webdav_disable(self):
        """
        W-23: IIS WebDAV 비활성화
        - 점검기준: IIS 서비스를 사용하지 않거나, DisableWebDAV 값이 1로 설정, 또는 Windows 2003 이상에서 WebDAV가 금지된 경우 양호.
        - 점검방법: 서비스 관리자, IIS 관리자 또는 applicationhost.config 파일 확인.
        """
        item = "W-23. IIS WebDAV 비활성화"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "PASS", "IIS 서비스가 실행 중이지 않아 WebDAV 취약점에 해당하지 않습니다.")
                return

            # 1. DisableWebDAV 레지스트리 값 확인 (Windows 2000)
            # HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\DisableWebDAV
            # 0: 사용 (취약), 1: 사용 안 함 (양호)
            disable_webdav = self._get_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\W3SVC\Parameters",
                "DisableWebDAV"
            )

            if disable_webdav == 1:
                self._record_result(item, "PASS", "WebDAV가 레지스트리를 통해 비활성화되어 있습니다.",
                                    current_value="DisableWebDAV=1", recommended_value="DisableWebDAV=1")
                return

            # 2. IIS 7.0 이상 (Windows Server 2008 이상)의 WebDAV 설정 확인
            # applicationhost.config 파일에서 <webdav><authoring enabled="true" /> 확인
            apphost_config_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'inetsrv', 'config', 'applicationHost.config')
            
            if os.path.exists(apphost_config_path):
                with open(apphost_config_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if '<webdav>' in content.lower() and 'authoring enabled="true"' in content.lower():
                    self._record_result(item, "VULNERABLE",
                                        "IIS WebDAV가 활성화되어 있습니다. 비활성화하십시오.",
                                        current_value="WebDAV enabled=true",
                                        recommended_value="WebDAV enabled=false")
                else:
                    self._record_result(item, "PASS", "IIS WebDAV가 비활성화되어 있습니다.",
                                        current_value="WebDAV enabled=false",
                                        recommended_value="WebDAV enabled=false")
            else:
                self._record_result(item, "UNKNOWN", "applicationHost.config 파일을 찾을 수 없어 WebDAV 설정을 확인할 수 없습니다.")

        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w24_netbios_binding_service(self):
        """
        W-24: NetBIOS 바인딩 서비스 구동 점검
        - 점검기준: TCP/IP와 NetBIOS 간의 바인딩이 제거되어 있는 경우 양호. 제거되어 있지 않은 경우 취약.
        - 점검방법: 네트워크 연결 속성 또는 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\NetBT\parameters\Interfaces\[인터페이스명]\NetbiosOptions 확인.
        """
        item = "W-24. NetBIOS 바인딩 서비스 구동 점검"
        try:
            # NetbiosOptions 레지스트리 값 확인
            # HKLM\SYSTEM\CurrentControlSet\Services\NetBT\parameters\Interfaces\[인터페이스명]\NetbiosOptions
            # 0: 기본값 (DHCP 서버 설정 사용), 1: 사용, 2: 사용 안 함 (권고)
            
            # 모든 네트워크 인터페이스에 대해 확인해야 하므로, 인터페이스 목록을 가져와야 합니다.
            # PowerShell: Get-NetAdapter | Select-Object Name, InterfaceGuid
            
            # NetbiosOptions 값을 직접 확인하는 것이 가장 정확합니다.
            # 모든 네트워크 어댑터의 NetbiosOptions 값을 확인
            cmd_output = self._execute_powershell(r"Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\* | Select-Object -ExpandProperty NetbiosOptions | ConvertTo-Json")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "NetBIOS 바인딩 설정을 확인할 수 없습니다.")
                return
            
            netbios_options = json.loads(cmd_output)
            
            is_vulnerable = False
            current_values = []
            for option in netbios_options:
                current_values.append(str(option))
                if option != 2: # 2는 사용 안 함 (권고)
                    is_vulnerable = True
            
            if not is_vulnerable:
                self._record_result(item, "PASS",
                                    "모든 네트워크 인터페이스에서 NetBIOS over TCP/IP 바인딩이 비활성화되어 있습니다.",
                                    current_value=f"NetbiosOptions: {', '.join(current_values)}",
                                    recommended_value="모두 2 (사용 안 함)")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"하나 이상의 네트워크 인터페이스에서 NetBIOS over TCP/IP 바인딩이 활성화되어 있거나 기본값으로 설정되어 있습니다. (현재 값: {', '.join(current_values)}). 비활성화하십시오.",
                                    current_value=f"NetbiosOptions: {', '.join(current_values)}",
                                    recommended_value="모두 2 (사용 안 함)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w25_ftp_service_status(self):
        """
        W-25: FTP 서비스 구동 점검
        - 점검기준: FTP 서비스를 사용하지 않는 경우 또는 secure FTP 서비스를 사용하는 경우 양호.
                    FTP 서비스를 사용하는 경우 취약.
        - 점검방법: 서비스 관리자에서 'FTP Publishing Service' 상태 확인.
        """
        item = "W-25. FTP 서비스 구동 점검"
        status, start_type = self._get_service_status("FTPSVC") # FTP Publishing Service

        if status == "Stopped" and start_type == "Disabled":
            self._record_result(item, "PASS", "FTP Publishing Service가 중지 및 사용 안 함으로 설정되어 있습니다.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        elif status == "Running":
            self._record_result(item, "VULNERABLE",
                                f"FTP Publishing Service가 실행 중입니다. 필요하지 않다면 중지 및 사용 안 함으로 설정하십시오. (Secure FTP 사용 권고)",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함 또는 Secure FTP 사용")
        else:
            self._record_result(item, "MANUAL",
                                f"FTP Publishing Service 상태를 확인하십시오. (현재 상태: {status}, 시작 유형: {start_type}) 필요 여부는 담당자 인터뷰를 통해 확인하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함 또는 Secure FTP 사용")

    def check_w27_anonymous_ftp(self):
        """
        W-27: Anonymous FTP 금지
        - 점검기준: FTP 서비스를 사용하지 않거나, "익명 연결 허용"이 체크되지 않은 경우 양호.
                    FTP 서비스를 사용하거나, "익명 연결 허용"이 체크되어 있는 경우 취약.
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 FTP 인증 "익명 인증" 상태 확인.
        """
        item = "W-27. Anonymous FTP 금지"
        try:
            ftp_status, _ = self._get_service_status("FTPSVC")
            if ftp_status != "Running":
                self._record_result(item, "PASS", "FTP 서비스가 실행 중이지 않아 Anonymous FTP 취약점에 해당하지 않습니다.")
                return

            # appcmd.exe를 사용하여 FTP 인증 설정 확인
            # Default FTP Site에 대한 익명 인증 설정 확인
            # (Get-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site' -Filter 'ftpServer/security/authentication').anonymousAuthentication.enabled
            # 또는 appcmd list config "Default FTP Site" /section:ftpServer/security/authentication
            
            cmd_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default FTP Site"" /text:* /section:ftpServer/security/authentication")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "FTP 익명 인증 설정을 확인할 수 없습니다.")
                return

            if 'anonymousauthentication enabled="true"' in cmd_output.lower():
                self._record_result(item, "VULNERABLE",
                                    "Anonymous FTP 접속이 허용되어 있습니다. 비활성화하십시오.",
                                    current_value="익명 인증 활성화",
                                    recommended_value="익명 인증 비활성화")
            else:
                self._record_result(item, "PASS",
                                    "Anonymous FTP 접속이 비활성화되어 있습니다.",
                                    current_value="익명 인증 비활성화",
                                    recommended_value="익명 인증 비활성화")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w28_ftp_access_control(self):
        """
        W-28: FTP 접근 제어 설정
        - 점검기준: 특정 IP 주소에서만 FTP 서버에 접속하도록 접근제어 설정을 적용한 경우 양호.
                    적용하지 않은 경우 취약.
        - 점검방법: IIS 관리자 또는 appcmd 명령어로 FTP IPv4 주소 및 도메인 제한 확인.
        """
        item = "W-28. FTP 접근 제어 설정"
        try:
            ftp_status, _ = self._get_service_status("FTPSVC")
            if ftp_status != "Running":
                self._record_result(item, "N/A", "FTP 서비스가 실행 중이지 않아 FTP 접근 제어 취약점에 해당하지 않습니다.")
                return

            # appcmd.exe를 사용하여 FTP IPv4 주소 및 도메인 제한 확인
            # (Get-WebConfigurationProperty -PSPath 'IIS:\Sites\Default FTP Site' -Filter 'ftpServer/security/ipSecurity').allowUnlisted
            # 또는 appcmd list config "Default FTP Site" /section:ftpServer/security/ipSecurity
            
            cmd_output = self._execute_powershell(r"C:\Windows\System32\inetsrv\appcmd.exe list config ""Default FTP Site"" /text:* /section:ftpServer/security/ipSecurity")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "FTP 접근 제어 설정을 확인할 수 없습니다.")
                return

            # allowUnlisted="true" 이거나, deny rules가 없는 경우 취약
            if 'allowunlisted="true"' in cmd_output.lower() and '<add ipaddress' not in cmd_output.lower():
                self._record_result(item, "VULNERABLE",
                                    "FTP 접근 제어 설정이 적용되지 않았습니다. 특정 IP 주소만 허용하도록 설정하십시오.",
                                    current_value="모든 IP 허용 또는 미설정",
                                    recommended_value="특정 IP만 허용")
            else:
                self._record_result(item, "PASS",
                                    "FTP 접근 제어 설정이 적용되어 있습니다. (특정 IP만 허용 또는 명시적 거부)",
                                    current_value="특정 IP 제한",
                                    recommended_value="특정 IP만 허용")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w29_dns_zone_transfer(self):
        """
        W-29: DNS Zone Transfer 설정
        - 점검기준: DNS 서비스를 사용하지 않거나, 영역 전송 허용을 하지 않는 경우, 또는 특정 서버로만 설정이 되어 있는 경우 양호.
                    위 3개 기준 중 하나라도 해당 되지 않는 경우 취약.
        - 점검방법: DNS 관리자 (DNSMGMT.MSC) 또는 레지스트리 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones\[각 DNS 영역]\SecureSecondaries 확인.
        """
        item = "W-29. DNS Zone Transfer 설정"
        try:
            dns_status, _ = self._get_service_status("DNS") # DNS Server 서비스
            if dns_status != "Running":
                self._record_result(item, "PASS", "DNS 서비스가 실행 중이지 않아 DNS Zone Transfer 취약점에 해당하지 않습니다.")
                return

            # DNS 서버의 모든 Zone 목록 가져오기
            # Get-DnsServerZone | Select-Object ZoneName
            zones_output = self._execute_powershell(r"Get-DnsServerZone | Select-Object -ExpandProperty ZoneName | ConvertTo-Json")
            
            if zones_output is None:
                self._record_result(item, "UNKNOWN", "DNS Zone 목록을 가져올 수 없습니다.")
                return

            dns_zones = json.loads(zones_output)
            
            vulnerable_zones = []
            for zone in dns_zones:
                # 각 Zone의 SecureSecondaries 레지스트리 값 확인
                # 0: 아무 서버로 전송 허용 (비권고)
                # 1: 이름 서버 탭에 나열된 서버로만 전송 허용 (권고)
                # 2: 다음 서버로만 전송 허용 (권고)
                # 3: 영역 전송 비허용 (권고)
                
                secure_secondaries = self._get_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DNS Server\\Zones\\{zone}",
                    "SecureSecondaries"
                )

                if secure_secondaries is None: # 값이 없으면 0으로 간주 (아무 서버로 전송 허용)
                    secure_secondaries = 0

                if secure_secondaries == 0:
                    vulnerable_zones.append(f"{zone} (SecureSecondaries: {secure_secondaries} - 아무 서버로 전송 허용)")
                # 1, 2, 3은 양호
            
            if not vulnerable_zones:
                self._record_result(item, "PASS", "모든 DNS Zone의 Zone Transfer 설정이 적절합니다.",
                                    current_value="적절",
                                    recommended_value="영역 전송 제한 또는 비허용")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"일부 DNS Zone의 Zone Transfer 설정이 취약합니다: {', '.join(vulnerable_zones)}. 설정 변경을 권고합니다.",
                                    current_value=f"취약한 Zone: {', '.join([z.split(' ')[0] for z in vulnerable_zones])}",
                                    recommended_value="영역 전송 제한 또는 비허용")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w30_rds_removal(self):
        """
        W-30: RDS(Remote Data Services) 제거
        - 점검기준: IIS를 사용하지 않거나, Windows 2000 SP4, 2003 SP2 이상 설치, 또는 디폴트 웹 사이트에 MSADC 가상 디렉터리가 존재하지 않는 경우, 또는 해당 레지스트리 값이 존재하지 않는 경우 양호.
        - 점검방법: IIS 서비스 실행 확인 및 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch 확인.
        """
        item = "W-30. RDS(Remote Data Services) 제거"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "PASS", "IIS 서비스가 실행 중이지 않아 RDS 취약점에 해당하지 않습니다.")
                return

            # 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch
            # 이 경로 아래에 RDSServer.DataFactory, AdvancedDataFactory 디렉터리나 VbBusObj.VbBusObjCls 레지스트리 키가 있는지 확인
            
            # PowerShell을 사용하여 레지스트리 키 존재 여부 확인
            # Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\RDSServer.DataFactory
            # Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\AdvancedDataFactory
            # Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\VbBusObj.VbBusObjCls
            
            has_rds_registry = False
            if self._execute_powershell(r"Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\RDSServer.DataFactory").lower() == "true":
                has_rds_registry = True
            if self._execute_powershell(r"Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\AdvancedDataFactory").lower() == "true":
                has_rds_registry = True
            if self._execute_powershell(r"Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch\VbBusObj.VbBusObjCls").lower() == "true":
                has_rds_registry = True

            if not has_rds_registry:
                self._record_result(item, "PASS", "RDS(Remote Data Services) 관련 레지스트리 키가 존재하지 않습니다.",
                                    current_value="RDS 관련 레지스트리 없음",
                                    recommended_value="RDS 제거")
            else:
                self._record_result(item, "VULNERABLE",
                                    "RDS(Remote Data Services) 관련 레지스트리 키가 존재합니다. 필요하지 않다면 제거하십시오.",
                                    current_value="RDS 관련 레지스트리 존재",
                                    recommended_value="RDS 제거")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w58_terminal_service_encryption_level(self):
        """
        W-58: 터미널 서비스 암호화 수준 설정
        - 점검기준: 터미널 서비스 암호화 수준이 "높음" 또는 "FIPS 규격"으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "서버 인증: 터미널 서비스 암호화 수준 설정" 또는 레지스트리 MinEncryptionLevel 확인.
        """
        item = "W-58. 터미널 서비스 암호화 수준 설정"
        try:
            # 레지스트리 HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp\MinEncryptionLevel
            # 1: 호환 가능 (클라이언트 암호화 수준), 2: 낮음, 3: 클라이언트-서버, 4: 높음, 5: FIPS 규격
            # 권고: 4 (높음) 또는 5 (FIPS 규격)
            
            min_encryption_level = self._get_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp",
                "MinEncryptionLevel"
            )

            if min_encryption_level is None:
                self._record_result(item, "UNKNOWN", "터미널 서비스 암호화 수준 설정을 확인할 수 없습니다.")
                return

            if min_encryption_level >= 4: # 4: 높음, 5: FIPS 규격
                self._record_result(item, "PASS",
                                    f"터미널 서비스 암호화 수준이 '{min_encryption_level}'(높음 또는 FIPS 규격)으로 적절하게 설정되어 있습니다.",
                                    current_value=str(min_encryption_level),
                                    recommended_value="4 (높음) 또는 5 (FIPS 규격)")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"터미널 서비스 암호화 수준이 '{min_encryption_level}'(낮음)으로 설정되어 있습니다. '높음' 또는 'FIPS 규격'으로 변경하십시오.",
                                    current_value=str(min_encryption_level),
                                    recommended_value="4 (높음) 또는 5 (FIPS 규격)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w59_iis_web_service_info_hiding(self):
        """
        W-59: IIS 웹 서비스 정보 숨김
        - 점검기준: IIS 웹 서비스 정보가 숨겨져 있는 경우 양호. 노출되어 있는 경우 취약.
        - 점검방법: HTTP 응답 헤더 확인 (curl 또는 PowerShell Invoke-WebRequest)
        """
        item = "W-59. IIS 웹 서비스 정보 숨김"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "N/A", "IIS 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
                return

            # 로컬호스트에 HTTP 요청을 보내 Server 헤더 확인
            # PowerShell: Invoke-WebRequest -Uri http://localhost -UseBasicParsing
            cmd_output = self._execute_powershell(r"Invoke-WebRequest -Uri http://localhost -UseBasicParsing -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Headers | Format-List")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", "로컬 웹 서버 응답 헤더를 가져올 수 없습니다.")
                return

            # Server 헤더에 IIS 버전 정보가 포함되어 있는지 확인
            # 예: Server : Microsoft-IIS/10.0
            if re.search(r"Server\s*:\s*Microsoft-IIS/\d+\.\d+", cmd_output, re.IGNORECASE):
                self._record_result(item, "VULNERABLE",
                                    "IIS 웹 서비스 버전 정보가 HTTP 응답 헤더에 노출되어 있습니다. 정보 노출을 최소화하십시오.",
                                    current_value="버전 정보 노출",
                                    recommended_value="버전 정보 숨김")
            else:
                self._record_result(item, "PASS", "IIS 웹 서비스 버전 정보가 HTTP 응답 헤더에 노출되어 있지 않습니다.",
                                    current_value="버전 정보 숨김",
                                    recommended_value="버전 정보 숨김")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w60_snmp_service_status(self):
        """
        W-60: SNMP 서비스 구동 점검
        - 점검기준: SNMP 서비스가 중지되어 있는 경우 양호. 구동 중인 경우 취약.
        - 점검방법: 서비스 관리자에서 'SNMP Service' 상태 확인.
        """
        item = "W-60. SNMP 서비스 구동 점검"
        status, start_type = self._get_service_status("SNMPTRAP") # SNMP Service (SNMPTRAP)

        if status == "Stopped" and start_type == "Disabled":
            self._record_result(item, "PASS", "SNMP 서비스가 중지 및 사용 안 함으로 설정되어 있습니다.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        elif status == "Running":
            self._record_result(item, "VULNERABLE",
                                f"SNMP 서비스가 실행 중입니다. 필요하지 않다면 중지 및 사용 안 함으로 설정하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        else:
            self._record_result(item, "MANUAL",
                                f"SNMP 서비스 상태를 확인하십시오. (현재 상태: {status}, 시작 유형: {start_type}) 필요 여부는 담당자 인터뷰를 통해 확인하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")

    def check_w61_snmp_community_string_complexity(self):
        """
        W-61: SNMP 서비스 커뮤니티스트링의 복잡성 설정
        - 점검기준: SNMP 서비스 커뮤니티 스트링의 복잡성이 설정되어 있는 경우 양호.
        - 점검방법: 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration 확인. (자동 점검 어려움, 담당자 인터뷰 필요성 제시)
        """
        item = "W-61. SNMP 서비스 커뮤니티스트링의 복잡성 설정"
        
        # SNMP 서비스가 실행 중인지 확인
        snmp_status, _ = self._get_service_status("SNMPTRAP")
        if snmp_status != "Running":
            self._record_result(item, "N/A", "SNMP 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
            return

        # 커뮤니티 스트링 복잡성 자체를 자동 점검하기는 매우 어렵습니다.
        # 일반적으로 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities
        # 또는 TrapConfiguration 아래에 등록된 커뮤니티 스트링을 직접 파싱해야 합니다.
        # 하지만, 'public', 'private'과 같은 기본적이고 취약한 스트링이 아닌지 확인하는 것은 가능합니다.
        
        # SNMP 커뮤니티 스트링 목록 가져오기 (PowerShell)
        # Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities | Select-Object -ExpandProperty Property | ConvertTo-Json
        
        try:
            # PowerShell 경로에 백슬래시가 있으므로 Raw String 사용 (r"...")
            cmd_output = self._execute_powershell(r"Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property | ConvertTo-Json")
            
            if cmd_output is None or cmd_output == "[]":
                self._record_result(item, "MANUAL", "SNMP 커뮤니티 스트링을 확인할 수 없습니다. 담당자 인터뷰를 통해 복잡성 설정 여부를 확인하십시오.",
                                    current_value="확인 불가", recommended_value="복잡한 커뮤니티 스트링 사용")
                return

            community_strings = json.loads(cmd_output)
            
            vulnerable_strings = []
            for s in community_strings:
                if s.lower() in ["public", "private"]:
                    vulnerable_strings.append(s)
                # 추가적으로 너무 짧거나 예측 가능한 패턴의 스트링도 확인할 수 있지만, 여기서는 간단하게 처리
            
            if vulnerable_strings:
                self._record_result(item, "VULNERABLE",
                                    f"SNMP 서비스에 취약한 커뮤니티 스트링({', '.join(vulnerable_strings)})이 사용 중입니다. 복잡한 스트링으로 변경하십시오.",
                                    current_value=f"취약한 스트링: {', '.join(vulnerable_strings)}",
                                    recommended_value="복잡한 커뮤니티 스트링 사용")
            else:
                self._record_result(item, "PASS", "SNMP 서비스 커뮤니티 스트링이 적절하게 설정되어 있습니다.",
                                    current_value="적절",
                                    recommended_value="복잡한 커뮤니티 스트링 사용")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w62_snmp_access_control(self):
        """
        W-62: SNMP Access control 설정
        - 점검기준: SNMP Access control이 적절하게 설정되어 있는 경우 양호.
        - 점검방법: 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers 확인. (자동 점검 어려움, 담당자 인터뷰 필요성 제시)
        """
        item = "W-62. SNMP Access control 설정"
        
        snmp_status, _ = self._get_service_status("SNMPTRAP")
        if snmp_status != "Running":
            self._record_result(item, "N/A", "SNMP 서비스가 실행 중이지 않아 해당 점검을 수행할 수 없습니다.")
            return

        # SNMP PermittedManagers 레지스트리 값 확인
        # HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers
        # 127.0.0.1 (localhost)만 허용하거나 특정 IP만 허용해야 양호
        
        # PowerShell을 사용하여 PermittedManagers 값 가져오기
        # Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers | Select-Object *
        
        try:
            # PowerShell 경로에 백슬래시가 있으므로 Raw String 사용 (r"...")
            cmd_output = self._execute_powershell(r"Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers -ErrorAction SilentlyContinue | Select-Object * | ConvertTo-Json")
            
            if cmd_output is None or cmd_output == "{}": # PermittedManagers 키 자체가 없으면 모든 호스트 허용 (취약)
                self._record_result(item, "VULNERABLE", "SNMP PermittedManagers 설정이 존재하지 않아 모든 호스트의 접근이 허용될 수 있습니다. 접근 제어 설정을 구성하십시오.",
                                    current_value="설정 없음 (모든 호스트 허용)", recommended_value="특정 IP만 허용")
                return

            permitted_managers = json.loads(cmd_output)
            
            # PDF에서는 "특정 IP 주소에서만" 허용하는 것을 권고.
            # 여기서는 127.0.0.1 외의 다른 IP가 허용되어 있는지 확인합니다.
            
            is_vulnerable = False
            allowed_ips = []
            for key, value in permitted_managers.items():
                if key.startswith("0x"): # 레지스트리 값 이름이 0x로 시작하는 경우
                    try:
                        ip_address = value # 값 자체가 IP 주소일 수 있음
                        allowed_ips.append(ip_address)
                        if ip_address != "127.0.0.1": # 로컬호스트 외 다른 IP가 명시적으로 허용된 경우
                            is_vulnerable = True
                    except:
                        pass # IP 주소 형식이 아닌 경우 무시
            
            # 만약 PermittedManagers 키가 존재하지만, 127.0.0.1 외에 다른 IP가 명시적으로 허용되지 않았다면 양호
            if not is_vulnerable and "127.0.0.1" in allowed_ips:
                self._record_result(item, "PASS",
                                    "SNMP Access control이 적절하게 설정되어 있습니다. (127.0.0.1만 허용)",
                                    current_value=f"허용된 IP: {', '.join(allowed_ips)}",
                                    recommended_value="127.0.0.1만 허용")
            elif not allowed_ips: # PermittedManagers 키는 있지만 허용된 IP가 없는 경우
                self._record_result(item, "PASS",
                                    "SNMP Access control이 설정되어 있으나, 명시적으로 허용된 IP가 없습니다. (모든 접근 차단으로 간주)",
                                    current_value="허용된 IP 없음",
                                    recommended_value="특정 IP만 허용")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"SNMP Access control 설정이 부적절합니다. (허용된 IP: {', '.join(allowed_ips)}). 특정 IP만 허용하도록 설정하십시오.",
                                    current_value=f"허용된 IP: {', '.join(allowed_ips)}",
                                    recommended_value="특정 IP만 허용")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w63_dns_service_status(self):
        """
        W-63: DNS 서비스 구동 점검
        - 점검기준: DNS 서비스가 필요하지 않아 이용하지 않는 경우 양호. 필요하지 않지만 사용하는 경우 취약.
        - 점검방법: 서비스 관리자에서 'DNS Server' 상태 확인.
        """
        item = "W-63. DNS 서비스 구동 점검"
        status, start_type = self._get_service_status("DNS") # DNS Server 서비스

        if status == "Stopped" and start_type == "Disabled":
            self._record_result(item, "PASS", "DNS 서비스가 중지 및 사용 안 함으로 설정되어 있습니다.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        elif status == "Running":
            self._record_result(item, "VULNERABLE",
                                f"DNS 서비스가 실행 중입니다. 필요하지 않다면 중지 및 사용 안 함으로 설정하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        else:
            self._record_result(item, "MANUAL",
                                f"DNS 서비스 상태를 확인하십시오. (현재 상태: {status}, 시작 유형: {start_type}) 필요 여부는 담당자 인터뷰를 통해 확인하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")

    def check_w64_http_ftp_smtp_banner_blocking(self):
        """
        W-64: HTTP/FTP/SMTP 배너 차단
        - 점검기준: HTTP/FTP/SMTP 서비스 배너 정보가 노출되지 않는 경우 양호. 노출되는 경우 취약.
        - 점검방법: HTTP (Invoke-WebRequest), FTP (ftp.exe), SMTP (telnet) 등으로 서비스 배너 확인.
        """
        item = "W-64. HTTP/FTP/SMTP 배너 차단"
        vulnerable_banners = []

        # HTTP 배너 확인 (IIS)
        iis_status, _ = self._get_service_status("W3SVC")
        if iis_status == "Running":
            try:
                # Invoke-WebRequest는 기본적으로 Server 헤더를 가져옵니다.
                cmd_output = self._execute_powershell(r"Invoke-WebRequest -Uri http://localhost -UseBasicParsing -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Headers | Format-List")
                if cmd_output and re.search(r"Server\s*:\s*Microsoft-IIS/\d+\.\d+", cmd_output, re.IGNORECASE):
                    vulnerable_banners.append("HTTP (IIS Server 헤더)")
            except Exception as e:
                logging.warning(f"HTTP 배너 확인 중 오류 발생: {e}")

        # FTP 배너 확인
        ftp_status, _ = self._get_service_status("FTPSVC")
        if ftp_status == "Running":
            try:
                # FTP 접속 시 환영 메시지 (배너) 확인
                # PowerShell에서 .NET WebClient를 사용하여 FTP 응답을 가져오는 것은 복잡하므로,
                # 여기서는 'ftp localhost' 명령어를 사용하여 초기 응답을 파싱합니다.
                # 이 방법은 실제 환경에서 제한적일 수 있습니다.
                
                # 임시 파일 생성
                temp_ftp_script = "C:\\temp\\ftp_test_script.txt"
                os.makedirs(os.path.dirname(temp_ftp_script), exist_ok=True)
                with open(temp_ftp_script, 'w', encoding='utf-8') as f:
                    f.write("open localhost\nquit\n")

                ftp_output = subprocess.run(
                    ["ftp", "-s", temp_ftp_script],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    encoding='cp949'
                )
                
                if ftp_output.stdout and "220 Microsoft FTP Service" in ftp_output.stdout:
                    vulnerable_banners.append("FTP (Microsoft FTP Service 배너)")
                
                if os.path.exists(temp_ftp_script):
                    os.remove(temp_ftp_script)

            except Exception as e:
                logging.warning(f"FTP 배너 확인 중 오류 발생: {e}")

        # SMTP 배너 확인 (SMTP Service)
        smtp_status, _ = self._get_service_status("SMTPSVC")
        if smtp_status == "Running":
            try:
                # Telnet을 사용하여 25번 포트에 연결 후 초기 응답 확인
                # PowerShell에서 Telnet 클라이언트를 사용하는 것은 기본적으로 설치되어 있지 않을 수 있습니다.
                # 여기서는 간단한 소켓 통신을 시도하거나, Telnet이 설치되어 있다고 가정하고 명령어를 실행합니다.
                # Test-NetConnection -ComputerName localhost -Port 25
                # 이 명령어는 포트 연결 여부만 확인하고 배너는 직접 가져오지 않습니다.
                
                # 더 정확한 방법은 Python socket 모듈을 사용하는 것이지만, 여기서는 외부 프로세스 실행에 집중
                # telnet localhost 25 명령을 직접 실행하는 것은 어려움
                # 대신, SMTP 서비스가 실행 중이면 배너가 노출될 가능성이 높다고 가정하고 MANUAL로 처리
                vulnerable_banners.append("SMTP (수동 확인 필요)")
            except Exception as e:
                logging.warning(f"SMTP 배너 확인 중 오류 발생: {e}")

        if not vulnerable_banners:
            self._record_result(item, "PASS", "HTTP/FTP/SMTP 서비스 배너 정보가 노출되지 않습니다.",
                                current_value="배너 숨김", recommended_value="배너 숨김")
        else:
            self._record_result(item, "VULNERABLE",
                                f"HTTP/FTP/SMTP 서비스 배너 정보가 노출될 수 있습니다: {', '.join(vulnerable_banners)}. 배너를 숨기십시오.",
                                current_value=f"노출: {', '.join(vulnerable_banners)}",
                                recommended_value="배너 숨김")

    def check_w65_telnet_security_settings(self):
        """
        W-65: Telnet 보안 설정
        - 점검기준: Telnet 서비스가 중지되어 있는 경우 양호. 구동 중인 경우 취약.
        - 점검방법: 서비스 관리자에서 'Telnet' 서비스 상태 확인.
        """
        item = "W-65. Telnet 보안 설정"
        status, start_type = self._get_service_status("TlntSvr") # Telnet 서비스 이름

        if status == "Stopped" and start_type == "Disabled":
            self._record_result(item, "PASS", "Telnet 서비스가 중지 및 사용 안 함으로 설정되어 있습니다.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        elif status == "Running":
            self._record_result(item, "VULNERABLE",
                                f"Telnet 서비스가 실행 중입니다. 중지 및 사용 안 함으로 설정하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")
        else:
            self._record_result(item, "MANUAL",
                                f"Telnet 서비스 상태를 확인하십시오. (현재 상태: {status}, 시작 유형: {start_type}) 필요 여부는 담당자 인터뷰를 통해 확인하십시오.",
                                current_value=f"상태: {status}, 시작 유형: {start_type}",
                                recommended_value="중지 및 사용 안 함")

    def check_w66_unnecessary_odbc_oledb_removal(self):
        """
        W-66: 불필요한 ODBC/OLE-DB 데이터소스와 드라이브 제거
        - 점검기준: 불필요한 ODBC/OLE-DB 데이터소스와 드라이브가 제거된 경우 양호.
        - 점검방법: ODBC 데이터 원본 관리자 (odbcad32.exe) 또는 레지스트리 확인. (자동 점검 어려움, 담당자 인터뷰 필요성 제시)
        """
        item = "W-66. 불필요한 ODBC/OLE-DB 데이터소스와 드라이브 제거"
        
        # ODBC 데이터 소스 목록 가져오기 (PowerShell)
        # Get-OdbcDsn | Select-Object Name, DsnType
        # OLE DB 공급자는 레지스트리 HKLM\SOFTWARE\Classes\CLSID\{GUID}\ProgID 등에서 확인 가능
        
        # 자동화된 방법으로 "불필요한" 것을 판단하기는 어렵습니다.
        # 여기서는 ODBC DSN이 존재하는지 여부만 확인하고 담당자 인터뷰를 권고합니다.
        
        try:
            cmd_output = self._execute_powershell(r"Get-OdbcDsn | Select-Object Name, DsnType | ConvertTo-Json")
            
            if cmd_output and cmd_output != "[]":
                odbc_dsns = json.loads(cmd_output)
                dsn_names = [dsn['Name'] for dsn in odbc_dsns]
                
                self._record_result(item, "MANUAL",
                                    f"ODBC 데이터 소스(DSN)가 존재합니다: {', '.join(dsn_names)}. 불필요한 DSN 및 OLE-DB 드라이브가 제거되었는지 담당자 인터뷰를 통해 확인하십시오.",
                                    current_value=f"존재: {', '.join(dsn_names)}",
                                    recommended_value="불필요한 DSN/드라이브 제거")
            else:
                self._record_result(item, "PASS", "불필요한 ODBC 데이터 소스(DSN)가 존재하지 않습니다. (OLE-DB 드라이브는 수동 확인 필요)",
                                    current_value="ODBC DSN 없음",
                                    recommended_value="불필요한 DSN/드라이브 제거")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w67_remote_terminal_timeout(self):
        """
        W-67: 원격터미널 접속 타임아웃 설정
        - 점검기준: 원격터미널 접속 타임아웃이 10분 이하로 설정되어 있는 경우 양호.
                    그 외의 경우 취약.
        - 점검방법: 로컬 보안 정책 "세션 시간 제한" 또는 레지스트리 MaxIdleTime 확인.
        """
        item = "W-67. 원격터미널 접속 타임아웃 설정"
        try:
            # 레지스트리 HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime (밀리초)
            # 또는 HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MaxIdleTime
            
            max_idle_time = self._get_registry_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
                "MaxIdleTime"
            )
            if max_idle_time is None:
                max_idle_time = self._get_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                    "MaxIdleTime"
                )

            if max_idle_time is None:
                self._record_result(item, "UNKNOWN", "원격터미널 접속 타임아웃 설정을 확인할 수 없습니다.")
                return

            # 10분 = 10 * 60 * 1000 = 600000 밀리초
            if max_idle_time <= 600000:
                self._record_result(item, "PASS",
                                    f"원격터미널 접속 타임아웃이 {max_idle_time/60000}분({max_idle_time}ms)으로 적절하게 설정되어 있습니다.",
                                    current_value=f"{max_idle_time/60000}분",
                                    recommended_value="10분 이하")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"원격터미널 접속 타임아웃이 {max_idle_time/60000}분({max_idle_time}ms)으로 너무 길게 설정되어 있습니다. 10분 이하로 설정하는 것을 권고합니다.",
                                    current_value=f"{max_idle_time/60000}분",
                                    recommended_value="10분 이하")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w68_scheduled_tasks_review(self):
        """
        W-68: 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검
        - 점검기준: 예약된 작업 목록을 정기적으로 검사하고 불필요하거나 의심스러운 작업이 없는 경우 양호.
        - 점검방법: 작업 스케줄러 (taskschd.msc) 또는 'schtasks' 명령어로 확인. (자동 점검 어려움, 담당자 인터뷰 필요성 제시)
        """
        item = "W-68. 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검"
        try:
            # schtasks /query /fo LIST 명령어로 모든 예약 작업 목록 가져오기
            cmd_output = self._execute_powershell(r"schtasks /query /fo LIST")
            
            if cmd_output is None:
                self._record_result(item, "ERROR", "예약된 작업 목록을 가져올 수 없습니다.")
                return

            # "TaskName"과 "Task To Run" 또는 "Command" 필드를 파싱하여 의심스러운 패턴 확인
            # 자동화된 판단은 매우 어렵기 때문에, 목록을 제공하고 수동 검토를 권고합니다.
            
            tasks = []
            current_task = {}
            for line in cmd_output.splitlines():
                if line.strip().startswith("TaskName:"):
                    if current_task:
                        tasks.append(current_task)
                    current_task = {"TaskName": line.split(':', 1)[1].strip()}
                elif line.strip().startswith("Task To Run:"):
                    current_task["Task To Run"] = line.split(':', 1)[1].strip()
                elif line.strip().startswith("Command:"): # 일부 버전에서 Task To Run 대신 Command 사용
                    current_task["Task To Run"] = line.split(':', 1)[1].strip()
            if current_task:
                tasks.append(current_task)

            if tasks:
                task_details = []
                for task in tasks:
                    task_details.append(f"이름: {task.get('TaskName', 'N/A')}, 실행 명령: {task.get('Task To Run', 'N/A')}")
                
                self._record_result(item, "MANUAL",
                                    f"예약된 작업이 존재합니다. 의심스러운 명령이 등록되어 있는지 담당자 인터뷰를 통해 확인하십시오. (작업 목록: {'; '.join(task_details)})",
                                    current_value=f"예약 작업 존재: {len(tasks)}개",
                                    recommended_value="불필요/의심스러운 작업 제거")
            else:
                self._record_result(item, "PASS", "예약된 작업이 존재하지 않습니다.",
                                    current_value="예약 작업 없음",
                                    recommended_value="예약 작업 없음")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")


class LogManagementAudit(AuditModule):
    """
    Windows 로그 관리 보안 점검을 수행하는 모듈입니다.
    - W-31: 감사 정책 설정 (로그온, 계정 관리 등)
    - W-32: 로그 파일 크기 및 보존 기간 설정 (보안 로그)
    - W-33: 로그 파일 크기 및 보존 기간 설정 (시스템 로그)
    - W-34: 로그 파일 크기 및 보존 기간 설정 (응용 프로그램 로그)
    - W-35: 이벤트 뷰어 접근 통제 (수동 점검)
    - W-36: 이벤트 로그 백업 (수동 점검)
    """
    def __init__(self, config):
        super().__init__(config)
        self.log_config = self.config.get('log_management', {})

    def run_audit(self):
        self.results = []
        logging.info(f"Starting {self.module_name} audit...")

        self.check_w31_audit_policy_settings()
        self.check_w32_log_file_size_retention("Security")
        self.check_w33_log_file_size_retention("System")
        self.check_w34_log_file_size_retention("Application")
        self.check_w35_event_viewer_access_control()
        self.check_w36_event_log_backup()

        logging.info(f"Completed {self.module_name} audit.")
        return self.results

    def check_w31_audit_policy_settings(self):
        """
        W-31: 감사 정책 설정 (로그온, 계정 관리 등)
        - 점검기준: 주요 감사 정책이 '성공 및 실패'로 설정되어 있는 경우 양호.
        - 점검방법: 'auditpol /get /category:*' 명령어로 확인.
        """
        item = "W-31. 감사 정책 설정"
        recommended_policies = self.log_config.get('w31_audit_policy_settings', {}).get('AuditPolicy', {})
        
        try:
            cmd_output = self._execute_powershell("auditpol /get /category:*")
            if cmd_output is None:
                self._record_result(item, "ERROR", "감사 정책 설정을 확인할 수 없습니다. auditpol 실행 실패.")
                return

            vulnerable_policies = []
            for category, recommended_setting in recommended_policies.items():
                # 예: "Account Logon Events"
                # "  Account Logon Events\n    Success and Failure"
                pattern = rf"{re.escape(category)}\s*\n\s*(Success and Failure|Success|Failure|No Auditing)"
                match = re.search(pattern, cmd_output, re.IGNORECASE)
                
                current_setting = "Unknown"
                if match:
                    current_setting = match.group(1).strip()
                    # "Success and Failure"는 "Success,Failure"로 매핑될 수 있음
                    if "Success and Failure" in current_setting and "Success,Failure" == recommended_setting:
                        current_setting = recommended_setting # 일치하는 것으로 간주
                    elif "No Auditing" in current_setting and "No Auditing" == recommended_setting:
                        current_setting = recommended_setting # 일치하는 것으로 간주
                    elif current_setting.lower() == recommended_setting.lower():
                         pass # 일치
                    else:
                        vulnerable_policies.append(f"{category} (현재: {current_setting}, 권고: {recommended_setting})")
                else:
                    vulnerable_policies.append(f"{category} (현재: 확인 불가, 권고: {recommended_setting})")

            if not vulnerable_policies:
                self._record_result(item, "PASS", "주요 감사 정책이 적절하게 설정되어 있습니다.",
                                    current_value="적절", recommended_value="권고 설정 준수")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"일부 감사 정책이 부적절하게 설정되어 있습니다: {'; '.join(vulnerable_policies)}. 권고 설정으로 변경하십시오.",
                                    current_value="부적절", recommended_value="권고 설정 준수")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w32_log_file_size_retention(self, log_type):
        """
        W-32, W-33, W-34: 로그 파일 크기 및 보존 기간 설정
        - 점검기준: 각 로그(보안, 시스템, 응용 프로그램) 파일 크기가 2GB 이상, 보존 기간이 365일 이상으로 설정되어 있는 경우 양호.
        - 점검방법: 이벤트 뷰어 속성 또는 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\[로그 유형]\MaxSize, Retention 확인.
        """
        item = f"W-XX. {log_type} 로그 파일 크기 및 보존 기간 설정"
        
        # W-32: Security, W-33: System, W-34: Application
        if log_type == "Security":
            item = "W-32. 보안 로그 파일 크기 및 보존 기간 설정"
        elif log_type == "System":
            item = "W-33. 시스템 로그 파일 크기 및 보존 기간 설정"
        elif log_type == "Application":
            item = "W-34. 응용 프로그램 로그 파일 크기 및 보존 기간 설정"
        
        recommended_settings = self.log_config.get('w32_log_file_size_retention', {}).get(log_type, {})
        recommended_max_size_mb = recommended_settings.get('max_size_mb', 2048) # 2GB
        recommended_retention_days = recommended_settings.get('retention_days', 365) # 365일

        try:
            # PowerShell Get-WinEvent -ListLog <LogType> | Format-List
            cmd_output = self._execute_powershell(f"Get-WinEvent -ListLog \"{log_type}\" | Select-Object MaximumSizeInBytes, RetentionDays | Format-List")
            
            if cmd_output is None:
                self._record_result(item, "UNKNOWN", f"{log_type} 로그 파일 설정을 확인할 수 없습니다.")
                return

            max_size_match = re.search(r"MaximumSizeInBytes\s*:\s*(\d+)", cmd_output)
            retention_match = re.search(r"RetentionDays\s*:\s*(\d+)", cmd_output)

            current_max_size_bytes = int(max_size_match.group(1)) if max_size_match else 0
            current_retention_days = int(retention_match.group(1)) if retention_match else 0
            
            current_max_size_mb = current_max_size_bytes / (1024 * 1024)

            is_vulnerable = False
            reasons = []

            if current_max_size_mb < recommended_max_size_mb:
                is_vulnerable = True
                reasons.append(f"최대 크기가 {current_max_size_mb:.0f}MB로 권고치({recommended_max_size_mb}MB)보다 작습니다.")
            
            if current_retention_days < recommended_retention_days and current_retention_days != 0: # 0은 "이벤트 덮어쓰기 안 함"으로 간주 (양호)
                is_vulnerable = True
                reasons.append(f"보존 기간이 {current_retention_days}일로 권고치({recommended_retention_days}일)보다 짧습니다.")
            elif current_retention_days == 0:
                pass # 0은 "이벤트 덮어쓰기 안 함"으로 양호

            if is_vulnerable:
                self._record_result(item, "VULNERABLE",
                                    f"{log_type} 로그 파일 설정이 부적절합니다. {'; '.join(reasons)}. 권고 설정으로 변경하십시오.",
                                    current_value=f"크기: {current_max_size_mb:.0f}MB, 보존: {current_retention_days}일",
                                    recommended_value=f"크기: {recommended_max_size_mb}MB 이상, 보존: {recommended_retention_days}일 이상 또는 0")
            else:
                self._record_result(item, "PASS",
                                    f"{log_type} 로그 파일 크기 및 보존 기간이 적절하게 설정되어 있습니다.",
                                    current_value=f"크기: {current_max_size_mb:.0f}MB, 보존: {current_retention_days}일",
                                    recommended_value=f"크기: {recommended_max_size_mb}MB 이상, 보존: {recommended_retention_days}일 이상 또는 0")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w35_event_viewer_access_control(self):
        """
        W-35: 이벤트 뷰어 접근 통제
        - 점검기준: 이벤트 뷰어에 대한 접근 권한이 적절하게 설정되어 있는 경우 양호.
        - 점검방법: 이벤트 뷰어 속성 또는 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\[로그 유형]\CustomSD 확인. (수동 점검 필요성 제시)
        """
        item = "W-35. 이벤트 뷰어 접근 통제"
        self._record_result(item, "MANUAL",
                            "이벤트 뷰어 접근 통제는 자동 점검이 어렵습니다. 이벤트 뷰어 속성에서 접근 권한이 적절하게 제한되어 있는지 수동으로 확인하십시오.",
                            current_value="수동 확인 필요", recommended_value="적절한 접근 통제")

    def check_w36_event_log_backup(self):
        """
        W-36: 이벤트 로그 백업
        - 점검기준: 이벤트 로그 백업 정책이 수립되어 있고 정기적으로 백업되는 경우 양호.
        - 점검방법: 담당자 인터뷰 또는 백업 스크립트/솔루션 확인. (수동 점검 필요성 제시)
        """
        item = "W-36. 이벤트 로그 백업"
        self._record_result(item, "MANUAL",
                            "이벤트 로그 백업은 자동 점검이 어렵습니다. 이벤트 로그 백업 정책이 수립되어 있고 정기적으로 백업되는지 담당자 인터뷰를 통해 확인하십시오.",
                            current_value="수동 확인 필요", recommended_value="정기적인 백업 정책 수립")


class PatchManagementAudit(AuditModule):
    """
    Windows 패치 관리 보안 점검을 수행하는 모듈입니다.
    - W-41: 최신 보안 패치 적용
    """
    def __init__(self, config):
        super().__init__(config)
        self.patch_config = self.config.get('patch_management', {})

    def run_audit(self):
        self.results = []
        logging.info(f"Starting {self.module_name} audit...")

        self.check_w41_automatic_updates()

        logging.info(f"Completed {self.module_name} audit.")
        return self.results

    def check_w41_automatic_updates(self):
        """
        W-41: 최신 보안 패치 적용 (자동 업데이트 설정)
        - 점검기준: 자동 업데이트가 '사용'으로 설정되어 있는 경우 양호.
        - 점검방법: 로컬 보안 정책 "자동 업데이트 구성" 또는 레지스트리 AUOptions 확인.
        """
        item = "W-41. 최신 보안 패치 적용 (자동 업데이트 설정)"
        # 정책 이름: "Configure Automatic Updates"
        # 레지스트리: HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions
        # 2: 업데이트 다운로드 전 알림, 3: 자동 다운로드 및 설치 알림, 4: 자동 다운로드 및 설치 (권고), 5: 자동 업데이트 사용 안 함 (취약)
        # 권고: 4 (자동 다운로드 및 설치)
        
        policy_value = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "AUOptions"
        )

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "자동 업데이트 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 4:
            self._record_result(item, "PASS", "자동 업데이트가 '자동 다운로드 및 설치'로 적절하게 설정되어 있습니다.",
                                current_value="자동 다운로드 및 설치 (4)", recommended_value="자동 다운로드 및 설치 (4)")
        else:
            self._record_result(item, "VULNERABLE",
                                f"자동 업데이트가 부적절하게 설정되어 있습니다. (현재: {policy_value}). '자동 다운로드 및 설치'로 변경하십시오.",
                                current_value=f"현재: {policy_value}", recommended_value="자동 다운로드 및 설치 (4)")

class SecurityManagementAudit(AuditModule):
    """
    Windows 보안 관리 보안 점검을 수행하는 모듈입니다.
    - W-37: SAM 파일 접근 통제 설정
    - W-38: 화면보호기 설정
    - W-39: 로그온 하지 않고 시스템 종료 허용 해제
    - W-40: 원격 시스템에서 강제로 시스템 종료
    - W-42: SAM 계정과 공유의 익명 열거 허용 안 함
    - W-43: Autologon 기능 제어
    - W-44: 이동식 미디어 포맷 및 꺼내기 허용
    - W-45: 디스크볼륨 암호화 설정 (FilePermissionAudit으로 이동)
    - W-72: Dos 공격 방어 레지스트리 설정
    - W-73: 사용자가 프린터 드라이버를 설치할 수 없게 함
    - W-74: 세션 연결을 중단하기 전에 필요한 유휴시간
    - W-75: 경고 메시지 설정
    - W-76: 사용자별 홈 디렉터리 권한 설정
    - W-77: LAN Manager 인증 수준
    - W-78: 보안 채널 데이터 디지털 암호화 또는 서명
    - W-80: 컴퓨터 계정 암호 최대 사용 기간
    - W-81: 시작프로그램 목록 분석
    - W-82: Windows 인증 모드 사용 (DB 관리 항목이지만, 보안 관리로 분류)
    """
    def __init__(self, config):
        super().__init__(config)
        self.security_config = self.config.get('security_management', {})

    def run_audit(self):
        """
        보안 관리 점검 항목들을 실행합니다.
        """
        self.results = [] # 이전 실행 결과 초기화
        logging.info(f"Starting {self.module_name} audit...")

        self.check_w37_sam_file_access_control()
        self.check_w38_screensaver_settings()
        self.check_w39_shutdown_without_logon()
        self.check_w40_force_shutdown_from_remote()
        self.check_w42_disable_anonymous_sam_shares()
        self.check_w43_autologon_control()
        self.check_w44_removable_media_format_eject()
        # W-45는 FilePermissionAudit으로 이동
        self.check_w72_dos_attack_defense_registry()
        self.check_w73_prevent_printer_driver_installation()
        self.check_w74_smb_session_idle_timeout()
        self.check_w75_warning_message_settings()
        self.check_w76_user_home_directory_permissions()
        self.check_w77_lan_manager_authentication_level()
        self.check_w78_secure_channel_digital_encryption_signing()
        self.check_w80_computer_account_password_max_age()
        self.check_w81_startup_program_analysis()
        self.check_w82_windows_authentication_mode()

        logging.info(f"Completed {self.module_name} audit.")
        return self.results

    def check_w37_sam_file_access_control(self):
        """
        W-37: SAM 파일 접근 통제 설정
        - 점검기준: SAM 파일 접근권한에 Administrator, System 그룹만 모든 권한으로 설정되어 있는 경우 양호.
                    그 외 다른 그룹에 권한이 설정되어 있는 경우 취약.
        - 점검방법: icacls 명령어로 C:\Windows\system32\config\SAM 파일 권한 확인.
        """
        item = "W-37. SAM 파일 접근 통제 설정"
        sam_file_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'config', 'SAM')

        if not os.path.exists(sam_file_path):
            self._record_result(item, "N/A", f"SAM 파일 '{sam_file_path}'이 존재하지 않습니다. 점검을 건너뜝니다.")
            return

        try:
            # icacls 명령어로 SAM 파일 권한 확인
            cmd_output = self._execute_powershell(f"icacls \"{sam_file_path}\"")
            
            if cmd_output is None:
                self._record_result(item, "ERROR", f"'{sam_file_path}' 파일 권한을 확인할 수 없습니다.")
                return

            # 권고: Administrators:(F), SYSTEM:(F)
            # 다른 그룹이나 사용자에게 (F), (M), (W) 등의 권한이 있는지 확인
            
            # Administrators 및 SYSTEM 그룹의 권한을 확인
            admin_full_control = False
            system_full_control = False
            
            if re.search(r"BUILTIN\\Administrators:\(F\)", cmd_output, re.IGNORECASE) or \
               re.search(r"Administrators:\(F\)", cmd_output, re.IGNORECASE):
                admin_full_control = True
            
            if re.search(r"NT AUTHORITY\\SYSTEM:\(F\)", cmd_output, re.IGNORECASE) or \
               re.search(r"SYSTEM:\(F\)", cmd_output, re.IGNORECASE):
                system_full_control = True

            # 다른 사용자/그룹에게 쓰기/수정/모든 권한이 있는지 확인 (Users, Everyone 등)
            # Users, Everyone, Authenticated Users 등에게 (F), (M), (W) 권한이 있는지 확인
            vulnerable_permissions = False
            if re.search(r"(Users|Everyone|Authenticated Users|BUILTIN\\Users):\(([^FMW]*[FMW])", cmd_output, re.IGNORECASE):
                vulnerable_permissions = True

            if admin_full_control and system_full_control and not vulnerable_permissions:
                self._record_result(item, "PASS", "SAM 파일 접근 권한이 Administrator 및 System 그룹으로만 제한되어 있습니다.",
                                    current_value="제한됨", recommended_value="Administrator, System만 모든 권한")
            else:
                self._record_result(item, "VULNERABLE",
                                    "SAM 파일 접근 권한이 부적절하게 설정되어 있습니다. Administrator 및 System 그룹으로만 모든 권한을 제한하십시오.",
                                    current_value=cmd_output.splitlines()[-1], # 마지막 라인에 권한 정보가 있을 수 있음
                                    recommended_value="Administrator, System만 모든 권한")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w38_screensaver_settings(self):
        """
        W-38: 화면보호기 설정
        - 점검기준: 화면보호기가 설정되어 있고, 10분 이내로 잠금 설정이 되어 있는 경우 양호.
                    그 외의 경우 취약.
        - 점검방법: 레지스트리 HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaverIsSecure, ScreenSaverTimeOut 확인.
        """
        item = "W-38. 화면보호기 설정"
        # ScreenSaverIsSecure (0: 비활성, 1: 활성)
        # ScreenSaverTimeOut (초 단위)
        
        # HKEY_CURRENT_USER는 현재 사용자 설정이므로, 시스템 전역 설정을 확인하는 것이 더 적절할 수 있습니다.
        # 그룹 정책을 통해 설정되는 경우 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
        # ScreenSaverIsSecure (REG_SZ, "1" or "0")
        # ScreenSaverTimeOut (REG_SZ, seconds)
        
        # 여기서는 HKLM (Local Machine) 정책을 우선 확인합니다.
        screensaver_secure = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ScreenSaverIsSecure"
        )
        screensaver_timeout = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ScreenSaverTimeOut"
        )

        if screensaver_secure is None or screensaver_timeout is None:
            self._record_result(item, "UNKNOWN", "화면보호기 설정을 확인할 수 없습니다. 그룹 정책 또는 레지스트리 값을 확인하십시오.")
            return

        try:
            screensaver_secure = int(screensaver_secure)
            screensaver_timeout = int(screensaver_timeout)
        except ValueError:
            self._record_result(item, "ERROR", "화면보호기 레지스트리 값 형식이 올바르지 않습니다.")
            return

        # 10분 = 600초
        if screensaver_secure == 1 and screensaver_timeout <= 600:
            self._record_result(item, "PASS",
                                f"화면보호기가 활성화되어 있고, 잠금 시간이 {screensaver_timeout}초(10분 이내)로 적절하게 설정되어 있습니다.",
                                current_value=f"활성, {screensaver_timeout}초",
                                recommended_value="활성, 600초 이하")
        else:
            reason = []
            if screensaver_secure != 1:
                reason.append("화면보호기 잠금이 활성화되어 있지 않습니다.")
            if screensaver_timeout > 600:
                reason.append(f"화면보호기 잠금 시간이 {screensaver_timeout}초로 10분을 초과합니다.")
            
            self._record_result(item, "VULNERABLE",
                                f"화면보호기 설정이 부적절합니다. {'; '.join(reason)}. 화면보호기를 활성화하고 10분 이내로 잠금 시간을 설정하십시오.",
                                current_value=f"활성: {screensaver_secure}, 시간: {screensaver_timeout}초",
                                recommended_value="활성, 600초 이하")

    def check_w39_shutdown_without_logon(self):
        """
        W-39: 로그온 하지 않고 시스템 종료 허용 해제
        - 점검기준: "로그온 하지 않고 시스템 종료 허용" 정책이 '사용 안 함'으로 설정되어 있는 경우 양호.
                    '사용'으로 설정되어 있는 경우 취약.
        - 점검방법: 로컬 보안 정책 "보안 옵션 - 대화형 로그온: 로그온 하지 않고 시스템 종료 허용" 확인.
        """
        item = "W-39. 로그온 하지 않고 시스템 종료 허용 해제"
        # 정책 이름: "Shutdown: Allow system to be shut down without having to log on"
        # 레지스트리: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon
        # 0: 사용 안 함 (양호), 1: 사용 (취약)
        
        policy_value = self._get_security_policy_setting("ShutdownWithoutLogon")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "로그온 하지 않고 시스템 종료 허용 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 0:
            self._record_result(item, "PASS", "로그온 하지 않고 시스템 종료 허용 정책이 '사용 안 함'으로 설정되어 있습니다.",
                                current_value="사용 안 함 (0)", recommended_value="사용 안 함 (0)")
        else:
            self._record_result(item, "VULNERABLE",
                                "로그온 하지 않고 시스템 종료 허용 정책이 '사용'으로 설정되어 있습니다. '사용 안 함'으로 변경하십시오.",
                                current_value="사용 (1)", recommended_value="사용 안 함 (0)")

    def check_w40_force_shutdown_from_remote(self):
        """
        W-40: 원격 시스템에서 강제로 시스템 종료
        - 점검기준: "원격 시스템에서 강제로 시스템 종료" 정책이 'Administrator' 그룹으로만 설정되어 있는 경우 양호.
                    그 외 다른 그룹에 권한이 설정되어 있는 경우 취약.
        - 점검방법: 로컬 보안 정책 "사용자 권한 할당 - 원격 시스템에서 강제로 시스템 종료" 확인.
        """
        item = "W-40. 원격 시스템에서 강제로 시스템 종료"
        # 정책 이름: "Shut down the system" (원격 시스템에서 강제로 시스템 종료 권한은 이 권한을 가진 사용자에게 부여됨)
        # 이 정책은 secedit으로 직접 값을 가져오기 어렵고, 부여된 SID를 파싱해야 합니다.
        # PowerShell: Get-LocalGroupMember -Group "Administrators"
        # 또는 secedit /export /cfg temp.inf 후 "SeShutdownPrivilege" 섹션 확인
        
        temp_inf_file = "temp_security_policy.inf"
        try:
            subprocess.run(
                ["secedit", "/export", "/cfg", temp_inf_file],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True
            )

            with open(temp_inf_file, 'r', encoding='utf-16-le') as f:
                content = f.read()

            # SeRemoteShutdownPrivilege (원격 시스템에서 강제로 시스템 종료)
            # SeShutdownPrivilege (시스템 종료)
            # PDF에서는 "원격 시스템에서 강제로 시스템 종료"라고 명시하고 있으므로 SeRemoteShutdownPrivilege를 찾아야 함
            # 하지만 Windows 보안 정책에서는 "Shut down the system" (SeShutdownPrivilege)이 더 일반적이며,
            # "Force shutdown from a remote system"은 별도의 권한이 아니라, Shut down the system 권한을 가진 사용자가 원격으로 종료할 때 적용됩니다.
            # PDF 내용에 따라 "Shut down the system" 권한을 확인하고 Administrators 그룹만 있는지 확인합니다.
            
            # SeShutdownPrivilege = *S-1-5-32-544 (BUILTIN\Administrators)
            match = re.search(r"SeShutdownPrivilege\s*=\s*(\*S-1-5-32-544(?:,\*S-1-5-32-544)*)", content, re.IGNORECASE)
            
            if match:
                sids_str = match.group(1)
                # Administrators 그룹의 SID는 S-1-5-32-544 입니다.
                # 오직 Administrators 그룹의 SID만 포함되어 있는지 확인합니다.
                if sids_str == "*S-1-5-32-544":
                    self._record_result(item, "PASS",
                                        "원격 시스템에서 강제로 시스템 종료 권한이 'Administrator' 그룹으로만 제한되어 있습니다.",
                                        current_value="Administrator만 허용",
                                        recommended_value="Administrator만 허용")
                else:
                    self._record_result(item, "VULNERABLE",
                                        f"원격 시스템에서 강제로 시스템 종료 권한이 'Administrator' 그룹 외 다른 그룹에도 부여되어 있습니다. (현재 SID: {sids_str}). 'Administrator' 그룹으로만 제한하십시오.",
                                        current_value=f"SID: {sids_str}",
                                        recommended_value="Administrator만 허용")
            else:
                self._record_result(item, "UNKNOWN", "원격 시스템 종료 권한 설정을 확인할 수 없습니다.")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")
        finally:
            if os.path.exists(temp_inf_file):
                os.remove(temp_inf_file)

    def check_w42_disable_anonymous_sam_shares(self):
        """
        W-42: SAM 계정과 공유의 익명 열거 허용 안 함
        - 점검기준: "SAM 계정과 공유의 익명 열거 허용 안 함" 정책이 '사용'으로 설정되어 있는 경우 양호.
                    '사용 안 함'으로 설정되어 있는 경우 취약.
        - 점검방법: 로컬 보안 정책 "보안 옵션 - 네트워크 액세스: SAM 계정 및 공유의 익명 열거를 허용하지 않음" 확인.
        """
        item = "W-42. SAM 계정과 공유의 익명 열거 허용 안 함"
        # 정책 이름: "Network access: Do not allow anonymous enumeration of SAM accounts and shares"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM
        # 1: 사용 (양호), 0: 사용 안 함 (취약)
        
        policy_value = self._get_security_policy_setting("RestrictAnonymousSAM")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "SAM 계정과 공유의 익명 열거 허용 안 함 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 1:
            self._record_result(item, "PASS", "SAM 계정과 공유의 익명 열거 허용 안 함 정책이 '사용'으로 설정되어 있습니다.",
                                current_value="사용 (1)", recommended_value="사용 (1)")
        else:
            self._record_result(item, "VULNERABLE",
                                "SAM 계정과 공유의 익명 열거 허용 안 함 정책이 '사용 안 함'으로 설정되어 있습니다. '사용'으로 변경하십시오.",
                                current_value="사용 안 함 (0)", recommended_value="사용 (1)")

    def check_w43_autologon_control(self):
        """
        W-43: Autologon 기능 제어
        - 점검기준: Autologon 기능이 비활성화되어 있는 경우 양호. 활성화되어 있는 경우 취약.
        - 점검방법: 레지스트리 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon 확인.
        """
        item = "W-43. Autologon 기능 제어"
        # 레지스트리: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
        # AutoAdminLogon (REG_SZ, 0: 비활성, 1: 활성)
        # DefaultUserName, DefaultPassword (존재 여부도 확인)
        
        autoadminlogon = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "AutoAdminLogon"
        )
        default_username = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "DefaultUserName"
        )
        default_password = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "DefaultPassword"
        )

        is_vulnerable = False
        reason = []
        current_values = []

        if autoadminlogon is not None and str(autoadminlogon).lower() == "1":
            is_vulnerable = True
            reason.append("AutoAdminLogon이 '1'(활성)으로 설정되어 있습니다.")
            current_values.append(f"AutoAdminLogon: {autoadminlogon}")
            if default_username:
                current_values.append(f"DefaultUserName: {default_username}")
            if default_password:
                current_values.append(f"DefaultPassword: [존재]")
        else:
            current_values.append(f"AutoAdminLogon: {autoadminlogon if autoadminlogon is not None else '없음/0'}")

        if is_vulnerable:
            self._record_result(item, "VULNERABLE",
                                f"Autologon 기능이 활성화되어 있습니다. {'; '.join(reason)}. 비활성화하십시오.",
                                current_value=f"현재: {', '.join(current_values)}",
                                recommended_value="AutoAdminLogon 비활성화 (0)")
        else:
            self._record_result(item, "PASS", "Autologon 기능이 비활성화되어 있습니다.",
                                current_value=f"현재: {', '.join(current_values)}",
                                recommended_value="AutoAdminLogon 비활성화 (0)")

    def check_w44_removable_media_format_eject(self):
        """
        W-44: 이동식 미디어 포맷 및 꺼내기 허용
        - 점검기준: "이동식 미디어 포맷 및 꺼내기 허용" 정책이 '사용 안 함'으로 설정되어 있는 경우 양호.
                    '사용'으로 설정되어 있는 경우 취약.
        - 점검방법: 로컬 보안 정책 "보안 옵션 - 장치: 이동식 미디어 포맷 및 꺼내기 허용" 확인.
        """
        item = "W-44. 이동식 미디어 포맷 및 꺼내기 허용"
        # 정책 이름: "Devices: Allowed to format and eject removable media"
        # 레지스트리: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD
        # 0: 사용 안 함 (양호), 1: 사용 (취약)
        
        policy_value = self._get_security_policy_setting("AllocateDASD")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "이동식 미디어 포맷 및 꺼내기 허용 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 0:
            self._record_result(item, "PASS", "이동식 미디어 포맷 및 꺼내기 허용 정책이 '사용 안 함'으로 설정되어 있습니다.",
                                current_value="사용 안 함 (0)", recommended_value="사용 안 함 (0)")
        else:
            self._record_result(item, "VULNERABLE",
                                "이동식 미디어 포맷 및 꺼내기 허용 정책이 '사용'으로 설정되어 있습니다. '사용 안 함'으로 변경하십시오.",
                                current_value="사용 (1)", recommended_value="사용 안 함 (0)")

    def check_w72_dos_attack_defense_registry(self):
        """
        W-72: Dos 공격 방어 레지스트리 설정
        - 점검기준: Dos 공격 방어 관련 레지스트리 설정이 적절하게 설정되어 있는 경우 양호.
        - 점검방법: 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableDeadGWDetect, SynAttackProtect, TcpMaxPortsExhausted, TcpMaxHalfOpenRetried, TcpMaxHalfOpen, TcpMaxConnectRetransmissions 등 확인.
        """
        item = "W-72. Dos 공격 방어 레지스트리 설정"
        
        # 주요 Dos 공격 방어 관련 레지스트리 설정 (예시, PDF 내용 기반)
        # 실제로는 더 많은 항목이 있을 수 있습니다.
        
        # 1. EnableDeadGWDetect (데드 게이트웨이 감지)
        # 0: 비활성 (권고), 1: 활성 (취약)
        enable_dead_gw_detect = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "EnableDeadGWDetect"
        )
        
        # 2. SynAttackProtect (SYN Flood 공격 방어)
        # 0: 비활성, 1: 활성 (권고)
        syn_attack_protect = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "SynAttackProtect"
        )

        # 3. TcpMaxHalfOpen (반만 열린 연결 최대값) - Windows 2000/XP/2003
        # 4. TcpMaxHalfOpenRetried (반만 열린 연결 재시도 최대값)
        # 5. TcpMaxConnectRetransmissions (연결 재전송 최대값)
        # 이 값들은 시스템 성능에 영향을 미치므로, 권장 값이 명확하지 않거나 버전별로 다를 수 있습니다.
        # 일반적으로 기본값 유지 또는 특정 값 이하로 설정 권고.
        
        vulnerable_settings = []
        current_values = []

        if enable_dead_gw_detect is None:
            current_values.append("EnableDeadGWDetect: 확인 불가")
            vulnerable_settings.append("EnableDeadGWDetect 설정을 확인할 수 없습니다.")
        elif enable_dead_gw_detect != 0:
            vulnerable_settings.append(f"EnableDeadGWDetect가 활성화되어 있습니다. (현재: {enable_dead_gw_detect})")
            current_values.append(f"EnableDeadGWDetect: {enable_dead_gw_detect}")
        else:
            current_values.append(f"EnableDeadGWDetect: {enable_dead_gw_detect}")

        if syn_attack_protect is None:
            current_values.append("SynAttackProtect: 확인 불가")
            vulnerable_settings.append("SynAttackProtect 설정을 확인할 수 없습니다.")
        elif syn_attack_protect != 1:
            vulnerable_settings.append(f"SynAttackProtect가 비활성화되어 있습니다. (현재: {syn_attack_protect})")
            current_values.append(f"SynAttackProtect: {syn_attack_protect}")
        else:
            current_values.append(f"SynAttackProtect: {syn_attack_protect}")
            
        # 다른 Dos 방어 레지스트리 항목들도 유사하게 점검 로직 추가 가능

        if not vulnerable_settings:
            self._record_result(item, "PASS",
                                "Dos 공격 방어 관련 주요 레지스트리 설정이 적절하게 설정되어 있습니다.",
                                current_value=f"현재: {', '.join(current_values)}",
                                recommended_value="EnableDeadGWDetect=0, SynAttackProtect=1")
        else:
            self._record_result(item, "VULNERABLE",
                                f"Dos 공격 방어 관련 레지스트리 설정이 부적절합니다. {'; '.join(vulnerable_settings)}. 권고 값으로 변경하십시오.",
                                current_value=f"현재: {', '.join(current_values)}",
                                recommended_value="EnableDeadGWDetect=0, SynAttackProtect=1")

    def check_w73_prevent_printer_driver_installation(self):
        """
        W-73: 사용자가 프린터 드라이버를 설치할 수 없게 함
        - 점검기준: "사용자가 프린터 드라이버를 설치할 수 없게 함" 정책이 '사용'으로 설정되어 있는 경우 양호.
                    '사용 안 함'으로 설정되어 있는 경우 취약.
        - 점검방법: 로컬 보안 정책 "장치: 사용자가 프린터 드라이버를 설치할 수 없게 함" 확인.
        """
        item = "W-73. 사용자가 프린터 드라이버를 설치할 수 없게 함"
        # 정책 이름: "Devices: Prevent users from installing printer drivers"
        # 레지스트리: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RestrictDriverInstallation
        # 1: 사용 (양호), 0: 사용 안 함 (취약)
        
        policy_value = self._get_security_policy_setting("RestrictDriverInstallation")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "사용자가 프린터 드라이버를 설치할 수 없게 함 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 1:
            self._record_result(item, "PASS", "사용자가 프린터 드라이버를 설치할 수 없게 함 정책이 '사용'으로 설정되어 있습니다.",
                                current_value="사용 (1)", recommended_value="사용 (1)")
        else:
            self._record_result(item, "VULNERABLE",
                                "사용자가 프린터 드라이버를 설치할 수 없게 함 정책이 '사용 안 함'으로 설정되어 있습니다. '사용'으로 변경하십시오.",
                                current_value="사용 안 함 (0)", recommended_value="사용 (1)")

    def check_w74_smb_session_idle_timeout(self):
        """
        W-74: 세션 연결을 중단하기 전에 필요한 유휴시간
        - 점검기준: "세션 연결을 중단하기 전에 필요한 유휴시간" 정책이 15분 이내로 설정되어 있는 경우 양호.
                    그 외의 경우 취약.
        - 점검방법: 로컬 보안 정책 "네트워크 보안: 세션 연결을 중단하기 전에 필요한 유휴시간" 확인.
        """
        item = "W-74. 세션 연결을 중단하기 전에 필요한 유휴시간"
        # 정책 이름: "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AutoDisconnect (분 단위)
        # 권고: 15분 (900초) 이하
        
        auto_disconnect_minutes = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "AutoDisconnect"
        )

        if auto_disconnect_minutes is None:
            self._record_result(item, "UNKNOWN", "세션 유휴 시간 설정을 확인할 수 없습니다.")
            return

        # 레지스트리 값은 분 단위
        if auto_disconnect_minutes <= 15:
            self._record_result(item, "PASS",
                                f"세션 유휴 시간이 {auto_disconnect_minutes}분(15분 이내)으로 적절하게 설정되어 있습니다.",
                                current_value=f"{auto_disconnect_minutes}분",
                                recommended_value="15분 이하")
        else:
            self._record_result(item, "VULNERABLE",
                                f"세션 유휴 시간이 {auto_disconnect_minutes}분으로 너무 길게 설정되어 있습니다. 15분 이하로 설정하는 것을 권고합니다.",
                                current_value=f"{auto_disconnect_minutes}분",
                                recommended_value="15분 이하")

    def check_w75_warning_message_settings(self):
        """
        W-75: 경고 메시지 설정
        - 점검기준: 로그온 시 경고 메시지가 설정되어 있는 경우 양호.
                    설정되어 있지 않은 경우 취약.
        - 점검방법: 레지스트리 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption, LegalNoticeText 확인.
        """
        item = "W-75. 경고 메시지 설정"
        # LegalNoticeCaption (경고 메시지 제목)
        # LegalNoticeText (경고 메시지 내용)
        
        legal_notice_caption = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "LegalNoticeCaption"
        )
        legal_notice_text = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "LegalNoticeText"
        )

        if legal_notice_caption and legal_notice_text:
            self._record_result(item, "PASS", "로그온 시 경고 메시지가 적절하게 설정되어 있습니다.",
                                current_value=f"제목: '{legal_notice_caption}', 내용: '{legal_notice_text[:50]}...'",
                                recommended_value="경고 메시지 설정")
        else:
            reason = []
            if not legal_notice_caption:
                reason.append("경고 메시지 제목이 설정되어 있지 않습니다.")
            if not legal_notice_text:
                reason.append("경고 메시지 내용이 설정되어 있지 않습니다.")
            
            self._record_result(item, "VULNERABLE",
                                f"로그온 시 경고 메시지가 설정되어 있지 않습니다. {'; '.join(reason)}. 적절한 경고 메시지를 설정하십시오.",
                                current_value=f"제목: '{legal_notice_caption}', 내용: '{legal_notice_text}'",
                                recommended_value="경고 메시지 설정")

    def check_w76_user_home_directory_permissions(self):
        """
        W-76: 사용자별 홈 디렉터리 권한 설정
        - 점검기준: 사용자 홈 디렉터리 권한이 해당 사용자만 모든 권한으로 설정되어 있는 경우 양호.
                    그 외 다른 그룹에 권한이 설정되어 있는 경우 취약.
        - 점검방법: 각 사용자 홈 디렉터리 권한 확인. (자동 점검 어려움, 담당자 인터뷰 필요성 제시)
        """
        item = "W-76. 사용자별 홈 디렉터리 권한 설정"
        
        # 모든 사용자 홈 디렉터리를 자동으로 찾아서 점검하는 것은 복잡합니다.
        # 일반적으로 C:\Users\ 에 있는 각 사용자 폴더를 점검해야 합니다.
        # 여기서는 수동 점검을 권고합니다.
        
        self._record_result(item, "MANUAL",
                            "사용자 홈 디렉터리 권한 설정은 자동 점검이 어렵습니다. 각 사용자 홈 디렉터리에 해당 사용자만 모든 권한을 갖도록 설정되어 있는지 수동으로 확인하십시오.",
                            current_value="수동 확인 필요",
                            recommended_value="해당 사용자만 모든 권한")

    def check_w77_lan_manager_authentication_level(self):
        """
        W-77: LAN Manager 인증 수준
        - 점검기준: "LAN Manager 인증 수준" 정책이 "NTLMv2 응답만 보내기\LM 및 NTLM 거부" 또는 "NTLMv2 응답만 보내기\LM 및 NTLM 거부"로 설정되어 있는 경우 양호.
                    그 외의 경우 취약.
        - 점검방법: 로컬 보안 정책 "네트워크 보안: LAN Manager 인증 수준" 확인.
        """
        item = "W-77. LAN Manager 인증 수준"
        # 정책 이름: "Network security: LAN Manager authentication level"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel
        # 0: LM 및 NTLM 응답 보내기 (취약)
        # 1: LM 및 NTLM 응답 보내기 (협상 시 NTLMv2 세션 보안 사용)
        # 2: NTLMv2 세션 보안을 협상할 수 있으면 LM 및 NTLMv2 응답 보내기 (권고)
        # 3: NTLMv2 응답만 보내기 (권고)
        # 4: NTLMv2 응답만 보내기\LM 및 NTLM 거부 (강력 권고)
        # 5: NTLMv2 응답만 보내기\LM 및 NTLM 거부\NTLMv2 세션 보안 강제 (가장 강력 권고)
        
        policy_value = self._get_security_policy_setting("LmCompatibilityLevel")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "LAN Manager 인증 수준 정책 설정을 확인할 수 없습니다.")
            return

        # 권고: 3, 4, 5
        if policy_value >= 3:
            self._record_result(item, "PASS",
                                f"LAN Manager 인증 수준이 '{policy_value}'(NTLMv2 응답만 보내기 이상)으로 적절하게 설정되어 있습니다.",
                                current_value=str(policy_value),
                                recommended_value="3 이상 (NTLMv2 응답만 보내기 이상)")
        else:
            self._record_result(item, "VULNERABLE",
                                f"LAN Manager 인증 수준이 '{policy_value}'(NTLMv2 응답만 보내기 미만)으로 설정되어 있습니다. '3' 이상으로 변경하십시오.",
                                current_value=str(policy_value),
                                recommended_value="3 이상 (NTLMv2 응답만 보내기 이상)")

    def check_w78_secure_channel_digital_encryption_signing(self):
        """
        W-78: 보안 채널 데이터 디지털 암호화 또는 서명
        - 점검기준: "보안 채널 데이터 디지털 암호화 또는 서명" 정책이 '사용'으로 설정되어 있는 경우 양호.
                    '사용 안 함'으로 설정되어 있는 경우 취약.
        - 점검방법: 로컬 보안 정책 "네트워크 보안: 보안 채널 데이터 디지털 암호화 또는 서명" 확인.
        """
        item = "W-78. 보안 채널 데이터 디지털 암호화 또는 서명"
        # 정책 이름: "Network security: Secure channel: Digitally encrypt or sign secure channel data (always)"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel
        # 1: 사용 (양호), 0: 사용 안 함 (취약)
        
        policy_value = self._get_security_policy_setting("SignSecureChannel")

        if policy_value is None:
            self._record_result(item, "UNKNOWN", "보안 채널 데이터 디지털 암호화 또는 서명 정책 설정을 확인할 수 없습니다.")
            return

        if policy_value == 1:
            self._record_result(item, "PASS", "보안 채널 데이터 디지털 암호화 또는 서명 정책이 '사용'으로 설정되어 있습니다.",
                                current_value="사용 (1)", recommended_value="사용 (1)")
        else:
            self._record_result(item, "VULNERABLE",
                                "보안 채널 데이터 디지털 암호화 또는 서명 정책이 '사용 안 함'으로 설정되어 있습니다. '사용'으로 변경하십시오.",
                                current_value="사용 안 함 (0)", recommended_value="사용 (1)")

    def check_w80_computer_account_password_max_age(self):
        """
        W-80: 컴퓨터 계정 암호 최대 사용 기간
        - 점검기준: "컴퓨터 계정 암호 최대 사용 기간" 정책이 30일 이내로 설정되어 있는 경우 양호.
                    그 외의 경우 취약.
        - 점검방법: 로컬 보안 정책 "계정 정책 - 컴퓨터 계정 암호 최대 사용 기간" 확인.
        """
        item = "W-80. 컴퓨터 계정 암호 최대 사용 기간"
        # 정책 이름: "Domain member: Maximum machine account password age"
        # 레지스트리: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge (일 단위)
        # 권고: 30일 이내
        
        max_password_age_days = self._get_registry_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
            "MaximumPasswordAge"
        )

        if max_password_age_days is None:
            self._record_result(item, "UNKNOWN", "컴퓨터 계정 암호 최대 사용 기간 설정을 확인할 수 없습니다.")
            return

        # 레지스트리 값은 일 단위
        if max_password_age_days <= 30:
            self._record_result(item, "PASS",
                                f"컴퓨터 계정 암호 최대 사용 기간이 {max_password_age_days}일(30일 이내)으로 적절하게 설정되어 있습니다.",
                                current_value=f"{max_password_age_days}일",
                                recommended_value="30일 이내")
        else:
            self._record_result(item, "VULNERABLE",
                                f"컴퓨터 계정 암호 최대 사용 기간이 {max_password_age_days}일로 너무 길게 설정되어 있습니다. 30일 이내로 설정하는 것을 권고합니다.",
                                current_value=f"{max_password_age_days}일",
                                recommended_value="30일 이내")

    def check_w81_startup_program_analysis(self):
        """
        W-81: 시작프로그램 목록 분석
        - 점검기준: 시작프로그램 목록에 불필요하거나 의심스러운 프로그램이 없는 경우 양호.
        - 점검방법: 시작프로그램 폴더, 레지스트리 Run 키, 작업 스케줄러 등 확인. (자동 점검 어려움, 담당자 인터뷰 필요성 제시)
        """
        item = "W-81. 시작프로그램 목록 분석"
        
        # 시작프로그램을 자동으로 분석하여 "불필요하거나 의심스러운" 것을 판단하기는 매우 어렵습니다.
        # 여기서는 주요 시작 위치에 프로그램이 존재하는지 여부만 확인하고 수동 검토를 권고합니다.
        
        startup_locations = []
        
        # 1. 시작 메뉴의 시작프로그램 폴더
        # %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
        # %ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup
        appdata_startup = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        allusers_startup = os.path.join(os.environ.get('ALLUSERSPROFILE', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        
        if os.path.exists(appdata_startup) and os.listdir(appdata_startup):
            startup_locations.append(f"사용자 시작 폴더 ({appdata_startup})")
        if os.path.exists(allusers_startup) and os.listdir(allusers_startup):
            startup_locations.append(f"모든 사용자 시작 폴더 ({allusers_startup})")

        # 2. 레지스트리 Run 키
        # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
        # HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        # HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
        
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hive, subkey in run_keys:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, type = winreg.EnumValue(key, i)
                            startup_locations.append(f"레지스트리 Run 키 ({subkey}\\{name})")
                            i += 1
                        except OSError: # No more values
                            break
            except FileNotFoundError:
                pass # 키가 존재하지 않음
            except Exception as e:
                logging.warning(f"레지스트리 Run 키 확인 중 오류 발생: {subkey} - {e}")

        # 3. 작업 스케줄러 (W-68에서 이미 확인)
        # 여기서는 W-68에서 다루므로 별도로 추가하지 않습니다.

        if startup_locations:
            self._record_result(item, "MANUAL",
                                f"시작프로그램이 다음 위치에서 발견되었습니다: {', '.join(startup_locations)}. 불필요하거나 의심스러운 프로그램이 없는지 담당자 인터뷰를 통해 확인하십시오.",
                                current_value=f"시작프로그램 존재: {len(startup_locations)}개",
                                recommended_value="불필요/의심스러운 시작프로그램 제거")
        else:
            self._record_result(item, "PASS", "주요 시작프로그램 위치에서 의심스러운 항목이 발견되지 않았습니다.",
                                current_value="시작프로그램 없음",
                                recommended_value="불필요/의심스러운 시작프로그램 제거")

    def check_w82_windows_authentication_mode(self):
        """
        W-82: Windows 인증 모드 사용 (SQL Server)
        - 점검기준: SQL Server가 Windows 인증 모드만 사용하도록 설정되어 있는 경우 양호.
                    혼합 모드(SQL Server 및 Windows 인증)로 설정되어 있는 경우 취약.
        - 점검방법: SQL Server Management Studio 또는 레지스트리 HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.x\MSSQLServer\LoginMode 확인.
        """
        item = "W-82. Windows 인증 모드 사용"
        # SQL Server가 설치되어 있어야 점검 가능
        # LoginMode 레지스트리 값:
        # 1: Windows 인증 모드 (권고)
        # 2: 혼합 모드 (SQL Server 및 Windows 인증) (취약)
        
        # SQL Server 인스턴스 목록을 가져와야 합니다.
        # PowerShell: Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL | Select-Object *
        
        try:
            # SQL Server 인스턴스 이름 가져오기
            sql_instances_output = self._execute_powershell("Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property | ConvertTo-Json")
            
            if sql_instances_output is None or sql_instances_output == "[]":
                self._record_result(item, "N/A", "SQL Server 인스턴스를 찾을 수 없어 해당 점검을 수행할 수 없습니다.")
                return

            sql_instances = json.loads(sql_instances_output)
            
            vulnerable_instances = []
            for instance_name in sql_instances:
                # 각 인스턴스별 LoginMode 확인
                # 예: MSSQL10_50.SQLEXPRESS (SQL Server 2008 R2 Express)
                # 레지스트리 경로가 인스턴스 이름에 따라 달라짐
                # HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\{InstanceID}\MSSQLServer\LoginMode
                # InstanceID는 MSSQL.1, MSSQL10_50.SQLEXPRESS 등 다양
                
                # 기본 인스턴스 (MSSQLSERVER)
                login_mode = self._get_registry_value(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SOFTWARE\\Microsoft\\Microsoft SQL Server\\{instance_name}\\MSSQLServer",
                    "LoginMode"
                )

                if login_mode is None:
                    # 명명된 인스턴스의 경우 경로가 다를 수 있음
                    # MSSQL.10_50.SQLEXPRESS 같은 형식
                    # 좀 더 일반적인 경로 탐색 필요
                    
                    # 예를 들어, SQL Server 2019의 기본 인스턴스는 MSSQL15.MSSQLSERVER
                    # Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\MSSQLServer\CurrentVersion | Select-Object CurrentVersion
                    # Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.15\MSSQLServer | Select-Object LoginMode
                    
                    # 현재는 설정 파일에서 인스턴스 경로를 직접 지정하는 것이 더 현실적일 수 있습니다.
                    logging.warning(f"SQL Server 인스턴스 '{instance_name}'의 LoginMode를 찾을 수 없습니다. 수동 확인이 필요합니다.")
                    continue

                if login_mode == 2: # 혼합 모드
                    vulnerable_instances.append(f"{instance_name} (LoginMode: {login_mode} - 혼합 모드)")
            
            if vulnerable_instances:
                self._record_result(item, "VULNERABLE",
                                    f"SQL Server 인스턴스에서 혼합 인증 모드가 사용 중입니다: {', '.join(vulnerable_instances)}. Windows 인증 모드만 사용하도록 변경하십시오.",
                                    current_value=f"취약 인스턴스: {', '.join([i.split(' ')[0] for i in vulnerable_instances])}",
                                    recommended_value="Windows 인증 모드 (LoginMode=1)")
            else:
                self._record_result(item, "PASS", "모든 SQL Server 인스턴스가 Windows 인증 모드를 사용하고 있습니다.",
                                    current_value="Windows 인증 모드",
                                    recommended_value="Windows 인증 모드 (LoginMode=1)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

