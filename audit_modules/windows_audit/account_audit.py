import logging
import os
import re
import subprocess
from audit_modules.windows_audit.audit_module import AuditModule


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
                match = re.search(r"(Minimum password length|최소 암호 길이)\s*:?\s*(\d+)", cmd_output)
                if match:
                    current_length = int(match.group(2))
                    recommended_length = self.account_config.get('w01_password_policy_min_length', 8)
                    if current_length >= recommended_length:
                        self._record_result(item, "COMPLIANT", f"최소 암호 길이가 {current_length}자로 적절하게 설정되어 있습니다.",
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
                match = re.search(r"(Lockout threshold|잠금 임계값)\s*:?\s*(\d+)", cmd_output)
                if match:
                    current_threshold = int(match.group(2))
                    recommended_threshold = self.account_config.get('w02_account_lockout_threshold', 5)
                    if current_threshold <= recommended_threshold and current_threshold > 0:
                        self._record_result(item, "COMPLIANT", f"계정 잠금 임계값이 {current_threshold}회로 적절하게 설정되어 있습니다.",
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
            match = re.search(r"(Account active|활성 계정)\s*:?\s*(\w+)", cmd_output)
            current_threshold = match.group(2)
            if current_threshold in (r"[Nn]o","아니요"):
                self._record_result(item, "COMPLIANT", "Guest 계정이 비활성화되어 있습니다.",
                                    current_value="비활성화", recommended_value="비활성화")
            elif current_threshold in (r"[Yy]es","예"):
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
                    self._record_result(item, "COMPLIANT", f"Administrator 계정 이름이 '{current_admin_name}'으로 변경되어 있습니다.",
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
            self._record_result(item, "COMPLIANT",
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
            self._record_result(item, "COMPLIANT", "패스워드 복잡성 정책이 '사용'으로 설정되어 있습니다.",
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
            self._record_result(item, "COMPLIANT", f"패스워드 최소 사용 기간이 {policy_value}일로 적절하게 설정되어 있습니다.",
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
            self._record_result(item, "COMPLIANT", f"패스워드 최대 사용 기간이 {policy_value}일로 적절하게 설정되어 있습니다.",
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
            self._record_result(item, "COMPLIANT", f"패스워드 기록 강제 적용이 {policy_value}개로 적절하게 설정되어 있습니다.",
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
            self._record_result(item, "COMPLIANT",
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
            self._record_result(item, "COMPLIANT", "마지막 로그온 시간 기록 정책이 '사용'으로 설정되어 있습니다.",
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
            self._record_result(item, "COMPLIANT", "로컬 계정의 빈 암호 사용 제한 정책이 '사용'으로 설정되어 있습니다.",
                                current_value="사용 (1)", recommended_value="사용 (1)")
        else:
            self._record_result(item, "VULNERABLE", "로컬 계정의 빈 암호 사용 제한 정책이 '사용 안 함'으로 설정되어 있습니다. '사용'으로 변경하십시오.",
                                current_value="사용 안 함 (0)", recommended_value="사용 (1)")