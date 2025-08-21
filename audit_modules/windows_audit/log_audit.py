import logging
import re
from audit_modules.windows_audit.audit_module import AuditModule


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
                self._record_result(item, "COMPLIANT", "주요 감사 정책이 적절하게 설정되어 있습니다.",
                                    current_value="적절", recommended_value="권고 설정 준수")
            else:
                self._record_result(item, "VULNERABLE",
                                    f"일부 감사 정책이 부적절하게 설정되어 있습니다: {'; '.join(vulnerable_policies)}. 권고 설정으로 변경하십시오.",
                                    current_value="부적절", recommended_value="권고 설정 준수")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w32_log_file_size_retention(self, log_type):
        r"""
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
                self._record_result(item, "COMPLIANT",
                                    f"{log_type} 로그 파일 크기 및 보존 기간이 적절하게 설정되어 있습니다.",
                                    current_value=f"크기: {current_max_size_mb:.0f}MB, 보존: {current_retention_days}일",
                                    recommended_value=f"크기: {recommended_max_size_mb}MB 이상, 보존: {recommended_retention_days}일 이상 또는 0")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w35_event_viewer_access_control(self):
        r"""
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