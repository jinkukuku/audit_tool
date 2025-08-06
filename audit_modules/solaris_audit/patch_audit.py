import logging
from base_audit_module import BaseAuditModule
from platform_utils import PlatformUtils

class PatchManagementAudit(BaseAuditModule):
    """
    패치 관리 관련 보안 점검을 수행하는 모듈입니다.
    대상 항목: U-42
    """
    def __init__(self, config):
        super().__init__(config)
        self.module_name = "패치 관리"
        self.patch_config = self.config.get('patch_management', {})

    def run_audit(self):
        logging.info(f"{self.module_name} 점검을 시작합니다.")
        self.module_audit_results = [] # 점검 시작 전 결과 목록 초기화

        # U-42. 최신 보안패치 및 벤더 권고사항 적용
        item_u42 = "U-42. 최신 보안패치 및 벤더 권고사항 적용"
        self._log_audit_item(item_u42)
        
        os_release_files = self.patch_config.get('u42_os_release_files', ["/etc/os-release", "/etc/redhat-release", "/etc/lsb-release"])
        os_info = "정보 없음"
        for f in os_release_files:
            if PlatformUtils.check_file_exists(f):
                stdout, _, rc = PlatformUtils.execute_command(['cat', f])
                if rc == 0:
                    os_info = stdout.strip().replace('\n', ', ')
                    break

        # 이 항목은 자동화된 점검이 어렵고 주로 문서 검토 및 인터뷰를 통해 확인해야 합니다.
        # 따라서 INFO 상태로 결과를 기록하여 수동 점검을 유도합니다.
        self._add_audit_result(
            item_u42,
            "INFO", # INFO 상태로 변경
            "최신 보안패치 및 벤더 권고사항 적용 여부는 자동화된 점검이 어렵습니다. 관련 정책 문서 및 시스템 관리자 인터뷰를 통해 확인이 필요합니다.",
            f"현재 OS 정보: {os_info}",
            "패치 적용 정책 수립 및 주기적 적용"
        )
        logging.info("  - U-42. 최신 보안패치 및 벤더 권고사항 적용: 수동 점검 필요")

        logging.info(f"{self.module_name} 점검을 완료했습니다.")
        return self.module_audit_results

