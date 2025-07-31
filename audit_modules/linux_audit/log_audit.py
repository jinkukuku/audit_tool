import logging
from base_audit_module import BaseAuditModule
from platform_utils import PlatformUtils

class LogManagementAudit(BaseAuditModule):
    """
    로그 관리 관련 보안 점검을 수행하는 모듈입니다.
    대상 항목: U-43, U-72
    """
    def __init__(self, config):
        super().__init__(config)
        self.module_name = "로그 관리"
        self.log_config = self.config.get('log_management', {})

    def run_audit(self):
        logging.info(f"{self.module_name} 점검을 시작합니다.")
        self.module_audit_results = [] # 점검 시작 전 결과 목록 초기화

        # U-43. 로그의 정기적 검토 및 보고
        item_u43 = "U-43. 로그의 정기적 검토 및 보고"
        self._log_audit_item(item_u43)
        # 이 항목 또한 자동화된 점검이 어렵고 주로 문서 검토 및 인터뷰를 통해 확인해야 합니다.
        self._add_audit_result(
            item_u43,
            "INFO", # INFO 상태로 변경
            "로그의 정기적 검토 및 보고 절차는 자동화된 점검이 어렵습니다. 관련 정책 문서 및 담당자 인터뷰를 통해 확인이 필요합니다.",
            "수동 점검 필요",
            "로그 검토 및 분석 계획 수립 및 정기적 보고"
        )
        logging.info("  - U-43. 로그의 정기적 검토 및 보고: 수동 점검 필요")

        # U-72. 정책에 따른 시스템 로깅 설정
        item_u72 = "U-72. 정책에 따른 시스템 로깅 설정"
        self._log_audit_item(item_u72)
        rsyslog_conf_path = self.log_config.get('u72_rsyslog_conf_path', "/etc/rsyslog.conf")
        
        is_logging_configured_ok = True
        vulnerable_reasons_u72 = []
        current_rsyslog_status = "N/A"
        current_rsyslog_config = "N/A"

        # rsyslog 서비스 구동 확인
        stdout, stderr, returncode = PlatformUtils.execute_command(['pgrep', 'rsyslogd'])
        is_rsyslog_running = (returncode == 0 and stdout.strip())

        if not is_rsyslog_running:
            is_logging_configured_ok = False
            vulnerable_reasons_u72.append("rsyslog 서비스가 구동 중이지 않습니다. 시스템 로그가 정상적으로 기록되지 않을 수 있습니다.")
            current_rsyslog_status = "rsyslogd 미구동"
        else:
            current_rsyslog_status = "rsyslogd 구동 중"

        # 로깅 설정 파일 확인
        if PlatformUtils.check_file_exists(rsyslog_conf_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', rsyslog_conf_path])
            if returncode == 0:
                current_rsyslog_config = stdout.strip()
                # 예시: *.info;mail.none;authpriv.none;cron.none /var/log/messages 패턴 확인
                # 실제 점검은 조직의 정책에 따라 매우 구체적인 로그 설정 규칙을 확인해야 합니다.
                # 여기서는 기본적인 존재 여부와 특정 키워드 포함 여부로 대체합니다.
                if not ("mail.none" in stdout and "authpriv.none" in stdout and "cron.none" in stdout):
                    is_logging_configured_ok = False
                    vulnerable_reasons_u72.append(f"'{rsyslog_conf_path}' 파일의 로깅 설정이 내부 정책 또는 권고 사항에 부합하지 않을 수 있습니다 (mail.none, authpriv.none, cron.none 키워드 부족).")
            else:
                is_logging_configured_ok = False
                vulnerable_reasons_u72.append(f"'{rsyslog_conf_path}' 파일을 읽을 수 없습니다: {stderr}")
        else:
            is_logging_configured_ok = False
            vulnerable_reasons_u72.append(f"'{rsyslog_conf_path}' 파일이 존재하지 않습니다.")
        
        if is_logging_configured_ok:
            self._add_audit_result(
                item_u72,
                "COMPLIANT",
                "시스템 로깅 설정이 적절하게 구성되어 있습니다.",
                f"rsyslog 상태: {current_rsyslog_status}, 설정: {current_rsyslog_config[:50]}...",
                "rsyslogd 서비스 활성화 및 내부 정책에 따른 로깅 설정"
            )
        else:
            self._add_audit_result(
                item_u72,
                "VULNERABLE",
                "; ".join(vulnerable_reasons_u72),
                f"rsyslog 상태: {current_rsyslog_status}, 설정: {current_rsyslog_config[:50]}...",
                "rsyslogd 서비스 활성화 및 내부 정책에 따른 로깅 설정"
            )

        logging.info(f"{self.module_name} 점검을 완료했습니다.")
        return self.module_audit_results

