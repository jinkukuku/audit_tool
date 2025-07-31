import datetime
import json
import logging
import os
import sys

# 필요한 모듈 임포트
from platform_utils import PlatformUtils
import audit_modules.linux_audit as lnx
import audit_modules.windows_audit as win

# import (
#     AccountManagementAudit,
#     FileDirectoryAudit,
#     ServiceManagementAudit,
#     PatchManagementAudit,
#     LogManagementAudit
# )

class SecurityAuditEngine:
    RISK_LEVEL_MAPPING = {
        "U-01": "상", "U-02": "상", "U-03": "상", "U-04": "상", "U-05": "상",
        "U-06": "상", "U-07": "상", "U-08": "상", "U-09": "상", "U-10": "상",
        "U-11": "상", "U-12": "상", "U-13": "상", "U-14": "상", "U-15": "상",
        "U-16": "상", "U-17": "상", "U-18": "상", "U-19": "상", "U-20": "상",
        "U-21": "상", "U-22": "상", "U-23": "상", "U-24": "상", "U-25": "상",
        "U-26": "상", "U-27": "상", "U-28": "상", "U-29": "상", "U-30": "상",
        "U-31": "상", "U-32": "상", "U-33": "상", "U-34": "상", "U-35": "상",
        "U-36": "상", "U-37": "상", "U-38": "상", "U-39": "상", "U-40": "상",
        "U-41": "상", "U-42": "상", "U-43": "상",
        "U-44": "중", "U-46": "중", "U-47": "중", "U-48": "중", "U-52": "중",
        "U-56": "중", "U-57": "중", "U-58": "중", "U-60": "중", "U-62": "중",
        "U-64": "중", "U-65": "중", "U-66": "중", "U-67": "중", "U-69": "중",
        "U-70": "중", "U-71": "중",
        "U-45": "하", "U-49": "하", "U-50": "하", "U-51": "하", "U-53": "하",
        "U-54": "하", "U-55": "하", "U-59": "하", "U-61": "하", "U-63": "하",
        "U-68": "하", "U-72": "하"
    }

    # U-XX 항목별 분류 항목 매핑 (PDF 문서 기반)
    CATEGORY_MAPPING = {
        "U-01": "계정 관리", "U-02": "계정 관리", "U-03": "계정 관리", "U-04": "계정 관리",
        "U-44": "계정 관리", "U-45": "계정 관리", "U-46": "계정 관리", "U-47": "계정 관리",
        "U-48": "계정 관리", "U-49": "계정 관리", "U-50": "계정 관리", "U-51": "계정 관리",
        "U-52": "계정 관리", "U-53": "계정 관리", "U-54": "계정 관리",

        "U-05": "파일 및 디렉터리 관리", "U-06": "파일 및 디렉터리 관리", "U-07": "파일 및 디렉터리 관리",
        "U-08": "파일 및 디렉터리 관리", "U-09": "파일 및 디렉터리 관리", "U-10": "파일 및 디렉터리 관리",
        "U-11": "파일 및 디렉터리 관리", "U-12": "파일 및 디렉터리 관리", "U-13": "파일 및 디렉터리 관리",
        "U-14": "파일 및 디렉터리 관리", "U-15": "파일 및 디렉터리 관리", "U-16": "파일 및 디렉터리 관리",
        "U-17": "파일 및 디렉터리 관리", "U-55": "파일 및 디렉터리 관리", "U-56": "파일 및 디렉터리 관리",
        "U-57": "파일 및 디렉터리 관리", "U-58": "파일 및 디렉터리 관리", "U-59": "파일 및 디렉터리 관리",

        "U-18": "서비스 관리", "U-19": "서비스 관리", "U-20": "서비스 관리", "U-21": "서비스 관리",
        "U-22": "서비스 관리", "U-23": "서비스 관리", "U-24": "서비스 관리", "U-25": "서비스 관리",
        "U-26": "서비스 관리", "U-27": "서비스 관리", "U-28": "서비스 관리", "U-29": "서비스 관리",
        "U-30": "서비스 관리", "U-31": "서비스 관리", "U-32": "서비스 관리", "U-33": "서비스 관리",
        "U-34": "서비스 관리", "U-35": "서비스 관리", "U-36": "서비스 관리", "U-37": "서비스 관리",
        "U-38": "서비스 관리", "U-39": "서비스 관리", "U-40": "서비스 관리", "U-41": "서비스 관리",
        "U-60": "서비스 관리", "U-61": "서비스 관리", "U-62": "서비스 관리", "U-63": "서비스 관리",
        "U-64": "서비스 관리", "U-65": "서비스 관리", "U-66": "서비스 관리", "U-67": "서비스 관리",
        "U-68": "서비스 관리", "U-69": "서비스 관리", "U-70": "서비스 관리", "U-71": "서비스 관리",

        "U-42": "패치 관리",

        "U-43": "로그 관리", "U-72": "로그 관리"
    }


    def __init__(self, config_file='audit_config.json'):
        self.config_file = config_file
        self.config = {}
        self.os_type = PlatformUtils.get_os_type()
        self.platform_specific_config = {}
        self.audit_results = [] # 모든 점검 모듈의 결과를 취합할 리스트

        self._setup_logging()
        self.load_configuration()

    def _setup_logging(self):
        """
        로깅 설정을 초기화합니다.
        """
        log_level_str = self.config.get('common_settings', {}).get('log_level', 'CRITICAL').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    def load_configuration(self):
        """
        설정 파일을 로드하고 OS별 설정을 분리합니다.
        """
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            logging.info(f"'{self.config_file}' 설정 파일을 성공적으로 로드했습니다.")

            # OS별 특정 설정 로드
            self.platform_specific_config = self.config.get(self.os_type, {})
            logging.info(f"'{self.os_type}' 플랫폼 전용 설정을 로드했습니다.")

        except FileNotFoundError:
            logging.error(f"오류: 설정 파일 '{self.config_file}'을 찾을 수 없습니다.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            logging.error(f"오류: 설정 파일 '{self.config_file}' 파싱 중 오류 발생: {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"오류: 설정 로드 중 알 수 없는 오류 발생: {e}")
            sys.exit(1)

    def run_audits(self):
        """
        정의된 점검 모듈들을 실행합니다.
        """
        logging.info("보안 점검을 시작합니다.")
        
        audit_modules_to_run = [] # 점검 모듈 인스턴스들을 담을 빈 리스트 생성

        # OS 유형에 따라 실행할 점검 모듈을 동적으로 추가
        # 현재는 Linux만 구현되어 있으므로 Linux 모듈만 추가합니다.
        if self.os_type == "Linux":
            logging.info("Linux 점검 모듈을 로드합니다.")
            audit_modules_to_run.append(lnx.AccountManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(lnx.FileDirectoryAudit(self.platform_specific_config))
            audit_modules_to_run.append(lnx.ServiceManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(lnx.PatchManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(lnx.LogManagementAudit(self.platform_specific_config))
        elif self.os_type == "Windows":
            logging.info("Windows 점검 모듈은 아직 구현되지 않았습니다. (TODO)")
            audit_modules_to_run.append(win.AccountManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.FilePermissionAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.ServiceManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.SecurityManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.LogManagementAudit(self.platform_specific_config))
        else:
            logging.warning(f"알 수 없는 OS 유형 '{self.os_type}'입니다. 실행할 점검 모듈이 없습니다.")
            return

        for audit_module in audit_modules_to_run:
            try:
                logging.info(f"모듈 실행: {audit_module.module_name}")
                module_results = audit_module.run_audit() # 모듈의 run_audit() 메서드 호출
                self.audit_results.extend(module_results) # 결과 취합
            except Exception as e:
                logging.error(f"점검 모듈 '{audit_module.module_name}' 실행 중 오류 발생: {e}")

        logging.info("모든 점검 모듈 실행 완료.")

    def generate_report(self):
        """
        점검 결과를 바탕으로 보고서를 생성합니다.
        """
        logging.info("점검 보고서를 생성합니다.")

        total_audits = len(self.audit_results)
        vulnerable_count = sum(1 for r in self.audit_results if r['status'] == 'VULNERABLE')
        


        report_summary = {
            "총 점검 항목": total_audits,
            "취약 항목": vulnerable_count,
            "양호 항목": total_audits - vulnerable_count
        }

        print("\n--- 점검 요약 ---")
        for key, value in report_summary.items():
            print(f"{key}: {value}")
        print("\n")
        
                # 위험도 및 분류 항목별 취약점 개수 초기화
        risk_levels = ["상", "중", "하", "총계"]
        categories_for_display = [
            "계정 관리",
            "파일 및 디렉터리 관리",
            "서비스 관리",
            "패치 관리",
            "로그 관리",
            "총계"
        ]
        
        # 모든 위험도-분류 항목 조합에 대해 0으로 초기화
        vulnerability_counts = {
            risk: {category: 0 for category in categories_for_display}
            for risk in risk_levels
        }

        # 각 점검 항목의 U-XX 코드를 추출하고 위험도 및 분류에 따라 분류합니다.
        for result in self.audit_results:
            if result['status'] == 'VULNERABLE':
                item_name = result.get('item', '')
                # 'U-XX. 항목 이름' 형식에서 'U-XX' 부분만 추출
                u_code = item_name.split('.')[0].strip()

                risk_level = self.RISK_LEVEL_MAPPING.get(u_code)
                category = self.CATEGORY_MAPPING.get(u_code)

                if risk_level and category and risk_level in risk_levels and category in categories_for_display:
                    vulnerability_counts[risk_level][category] += 1
                # else:
                    # 매핑에 없는 항목은 무시하거나, 필요에 따라 로깅할 수 있습니다.
                    # logging.warning(f"경고: 알 수 없는 U-XX 코드 '{u_code}'에 대한 위험도 또는 분류 정보가 없습니다.")

        # 보고서 헤더 및 데이터 출력 (더 깔끔한 형식으로 변경)
        # 각 분류 항목 헤더의 최대 너비 계산 (최소 10칸 확보)
        # 헤더와 데이터의 최대 길이를 고려하여 너비를 동적으로 조정
        col_widths = {cat: max(len(cat), 10) for cat in categories_for_display}
        
        # '상/중/하' 열의 너비 설정
        risk_label_width = 3 # "상", "중", "하" + 여백

        # 헤더 출력
        header_parts = [" " * risk_label_width] # 첫 번째 빈 칸
        for cat in categories_for_display:
            header_parts.append(f"{cat:^{col_widths[cat]}}") # 중앙 정렬
        print(" | ".join(header_parts))

        # 구분선 출력
        separator_parts = ["-" * risk_label_width]
        for cat in categories_for_display:
            separator_parts.append("-" * (col_widths[cat] + 5))
        print("-+-".join(separator_parts))

        # 데이터 행 출력
        # for risk in risk_levels:
        #     data_parts = [f"{risk:<{risk_label_width}}"] # 좌측 정렬
        #     for category in categories_for_display:
        #         if category != "총계":
        #             count = vulnerability_counts[risk][category]
        #             data_parts.append(f"{str(count):^{col_widths[category]}}") # 중앙 정렬
        #         else
                    
        #     print("  |    ".join(data_parts))

        column_total = {category: 0 for category in categories_for_display}
        entire_total = 0
        for risk in risk_levels:
            data_parts = [f"{risk:<{risk_label_width}}"] # 좌측 정렬
            row_total = 0 # 각 행의 합계를 저장할 변수 초기화
            for category in categories_for_display:
                if risk != "총계" :
                    if category != "총계" :
                        count = vulnerability_counts[risk][category]
                        data_parts.append(f"{str(count):^{col_widths[category]}}") # 중앙 정렬
                        row_total += count # 현재 카테고리의 값을 행의 합계에 더합니다.
                    else:
                        data_parts.append(f"{str(row_total):^{col_widths[category]}}")
                        vulnerability_counts[risk][category] = row_total
                    column_total[category] += vulnerability_counts[risk][category] # 컬럼 합 계산
                else:
                    data_parts.append(f"{str(column_total[category]):^{col_widths[category]}}")
            
            entire_total += row_total
            print("  |    ".join(data_parts))





        # 상세 보고서를 파일로 저장하는 기능은 유지 (로그는 출력되지 않음)
        output_dir = self.config.get('common_settings', {}).get('report_output_dir', './audit_reports')
        os.makedirs(output_dir, exist_ok=True)
        report_file = os.path.join(output_dir, f"security_audit_report_{PlatformUtils.get_os_type()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(self.audit_results, f, indent=4, ensure_ascii=False)
            # logging.info(f"상세 보고서가 '{report_file}'에 저장되었습니다.")
        except Exception as e:
            logging.critical(f"오류: 보고서 저장 중 오류 발생: {e}. 프로그램을 종료합니다.")
            sys.exit(1)


        print(f"\n\n상세 결과 : ./audit_reports/security_audit_report_{PlatformUtils.get_os_type()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")


if __name__ == "__main__":
    # 스크립트가 실행될 때 현재 작업 디렉토리에 audit_modules 폴더가 있는지 확인
    # sys.path에 현재 디렉토리 추가 (IDE나 일부 환경에서 모듈을 찾지 못할 경우 대비)
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    if current_script_dir not in sys.path:
        sys.path.insert(0, current_script_dir)

    # audit_modules 폴더가 존재하는지 확인
    audit_modules_path = os.path.join(current_script_dir, 'audit_modules')
    if not os.path.exists(audit_modules_path) or not os.path.isdir(audit_modules_path):
        logging.error(f"오류: '{audit_modules_path}' 디렉토리를 찾을 수 없습니다. audit_modules 폴더가 main.py와 같은 위치에 있는지 확인해주세요.")
        sys.exit(1)
    
    # audit_modules/__init__.py 파일이 있는지 확인
    if not os.path.exists(os.path.join(audit_modules_path, '__init__.py')):
        logging.error(f"오류: '{audit_modules_path}/__init__.py' 파일이 없습니다. 패키지 구조가 올바른지 확인해주세요.")
        sys.exit(1)

    engine = SecurityAuditEngine()
    engine.run_audits()
    engine.generate_report()