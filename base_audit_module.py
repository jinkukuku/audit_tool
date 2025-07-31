import logging
from abc import ABC, abstractmethod

class BaseAuditModule(ABC):
    """
    모든 보안 점검 모듈을 위한 추상 기본 클래스입니다.
    각 점검 모듈은 이 클래스를 상속받아 run_audit 메서드를 구현해야 합니다.
    """
    def __init__(self, config):
        """
        모듈 초기화.
        Args:
            config (dict): audit_config.json에서 로드된 전체 설정 딕셔너리.
        """
        self.config = config
        self.module_audit_results = [] # 이 모듈에서 발견된 모든 점검 결과 (양호/취약)
        self.module_name = "기본 점검 모듈" # 각 모듈에서 재정의될 이름

    @abstractmethod
    def run_audit(self):
        """
        실제 점검 로직을 실행하고 취약점 목록을 반환하는 추상 메서드.
        하위 클래스에서 반드시 구현해야 합니다.
        Returns:
            list: 발견된 취약점(딕셔너리 형태) 목록.
        """
        pass

    def _add_audit_result(self, item_name, status, reason, current_value="N/A", recommended_value="N/A"):
        """
        점검 결과를 module_audit_results 목록에 추가하고 로깅합니다.
        Args:
            item_name (str): 점검 항목의 이름 (예: "U-01. root 계정 원격 접속 제한").
            status (str): 점검 결과 상태 ("VULNERABLE" 또는 "COMPLIANT").
            reason (str): 점검 결과에 대한 설명.
            current_value (str): 현재 시스템의 설정 또는 값.
            recommended_value (str): 권고되는 설정 또는 값.
        """
        result_entry = {
            'module': self.module_name,
            'item': item_name,
            'status': status,
            'reason': reason,
            'current_value': current_value,
            'recommended_value': recommended_value
        }
        self.module_audit_results.append(result_entry)

        if status == "VULNERABLE":
            logging.warning(f"취약점 발견 - 모듈: {self.module_name}, 항목: {item_name}, 이유: {reason}")
        else:
            logging.info(f"점검 결과 - 모듈: {self.module_name}, 항목: {item_name}, 상태: {status}")

    def _log_audit_item(self, item_name):
        """
        각 점검 항목 시작을 로깅하는 헬퍼 메서드.
        """
        logging.info(f"  - 점검 항목: {item_name}")

