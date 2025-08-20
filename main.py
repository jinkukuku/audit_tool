import datetime
import json
import logging
import os
import sys
import sqlite3
from platform_utils import PlatformUtils

class SecurityAuditEngine:
    def __init__(self, config_file='audit_config.json'):
        self.config_file = config_file
        self.config = {}
        self.os_type = PlatformUtils.get_os_type()
        self.common_os_type = ""
        self.success_paths = []
        self.fail_paths = []
        if self.os_type == "Windows":
            self.common_os_type = "Windows"
        else:
            self.common_os_type = "Linux"
        self.platform_specific_config = {}
        self.audit_results = [] # 모든 점검 모듈의 결과를 취합할 리스트
        self._setup_logging()
        self.load_configuration()

    def _setup_logging(self):
        """
        로깅 설정을 초기화합니다.
        """
        # 설정 파일 로드 전에 로깅 기본 설정
        log_level_str = self.config.get('common_settings', {}).get('log_level', 'ERROR').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logging.basicConfig(filename='./debug.log', level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    def load_configuration(self):
        """
        설정 파일을 로드하고 OS별 설정을 분리합니다.
        """
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            logging.info(f"'{self.config_file}' 설정 파일을 성공적으로 로드했습니다.")
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
        if self.common_os_type == "Linux":
            import audit_modules.linux_audit as lnx
        if self.os_type == "Windows":
            import audit_modules.windows_audit as win

        logging.info("보안 점검을 시작합니다.")
        audit_modules_to_run = []

        if self.common_os_type == "Linux": # Solaris 구현 필요 ★★★★★★★★★★★★★
            if os.geteuid() != 0:
                print("root권한으로 실행해주시길 바랍니다.")
                return False # 실행 중단
            else:
                audit_modules_to_run.append(lnx.GetSystemFile(self.os_type))
                audit_modules_to_run.append(lnx.AccountManagementAudit(self.os_type,self.platform_specific_config))
                audit_modules_to_run.append(lnx.LogManagementAudit(self.platform_specific_config))
                audit_modules_to_run.append(lnx.FileDirectoryAudit(self.platform_specific_config))
                audit_modules_to_run.append(lnx.ServiceManagementAudit(self.platform_specific_config))
        elif self.common_os_type == "Windows":
            logging.info("Windows 점검 모듈을 로드합니다.")
            audit_modules_to_run.append(win.AccountManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.FilePermissionAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.ServiceManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.SecurityManagementAudit(self.platform_specific_config))
            audit_modules_to_run.append(win.LogManagementAudit(self.platform_specific_config))
        else:
            logging.warning(f"알 수 없는 OS 유형 '{self.os_type}'입니다. 실행할 점검 모듈이 없습니다.")
            return False # 실행 중단

        for audit_module in audit_modules_to_run:
            try:
                logging.info(f"모듈 실행: {audit_module.module_name}")
                module_results = audit_module.run_audit()
                self.audit_results.extend(module_results)
                if audit_module.module_name == "시스템 파일 로드":
                    self.success_paths = audit_module.success_path
                    self.fail_paths = audit_module.fail_path
            except Exception as e:
                logging.error(f"점검 모듈 '{audit_module.module_name}' 실행 중 오류 발생: {e}")

        logging.info("모든 점검 모듈 실행 완료.")
        return True # 정상 실행 완료

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
        
        risk_levels = ["상", "중", "하", "총계"]
        categories_for_display = {
            "Linux" : [
                "계정 관리", "파일 및 디렉터리 관리", "서비스 관리",
                "패치 관리","로그 관리", "총계"
            ],
            "Windows" : [
                "계정 관리", "공유 권한 및 사용자 그룹 설정", "서비스 관리", 
                "패치 관리", "로그 관리", "보안 관리", "총계"
            ]
        }
        
        vulnerability_counts = {
            risk: {category: 0 for category in categories_for_display[self.common_os_type]}
            for risk in risk_levels
        }

        for result in self.audit_results:
            if result['status'] == 'VULNERABLE':
                item_name = result.get('item', '')
                u_code = item_name.split('.')[0].strip()
                risk_level = self.config.get(self.common_os_type,{}).get("RISK_LEVEL_MAPPING").get(u_code)
                category = self.config.get(self.common_os_type,{}).get("CATEGORY_MAPPING").get(u_code)
                
                if risk_level and category and risk_level in risk_levels and category in categories_for_display[self.common_os_type]:
                    vulnerability_counts[risk_level][category] += 1
        
        col_widths = {cat: max(len(cat), 10) for cat in categories_for_display[self.common_os_type]}
        risk_label_width = 3
        
        header_parts = [" " * risk_label_width]
        for cat in categories_for_display[self.common_os_type]:
            header_parts.append(f"{cat:^{col_widths[cat]}}")
        print(" | ".join(header_parts))

        separator_parts = ["-" * risk_label_width]
        for cat in categories_for_display[self.common_os_type]:
            separator_parts.append("-" * (col_widths[cat] + 2))
        print("-+-".join(separator_parts))

        column_total = {category: 0 for category in categories_for_display[self.common_os_type]}

        for risk in risk_levels:
            if risk == "총계": continue # 총계는 나중에 계산
            data_parts = [f"{risk:<{risk_label_width}}"]
            row_total = 0
            for category in categories_for_display[self.common_os_type]:
                if category == "총계": continue
                count = vulnerability_counts[risk][category]
                data_parts.append(f"{str(count):^{col_widths[category]}}")
                row_total += count
                column_total[category] += count
            
            vulnerability_counts[risk]["총계"] = row_total
            column_total["총계"] += row_total
            data_parts.append(f"{str(row_total):^{col_widths['총계']}}")
            print(" | ".join(data_parts))
            
        # 총계 행 출력
        total_data_parts = [f"{'총계':<{risk_label_width}}"]
        for category in categories_for_display[self.common_os_type]:
            total_data_parts.append(f"{str(column_total[category]):^{col_widths[category]}}")
        print(" | ".join(total_data_parts))

        output_dir = self.config.get('common_settings', {}).get('report_output_dir', './audit_reports')
        os.makedirs(output_dir, exist_ok=True)
        report_file_name = f"security_audit_report_{PlatformUtils.get_os_type()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_file = os.path.join(output_dir, report_file_name)
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(self.audit_results, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logging.critical(f"오류: 보고서 저장 중 오류 발생: {e}. 프로그램을 종료합니다.")
            sys.exit(1)

        print(f"\n\n상세 결과 : {report_file}")
        self._persist_to_sqlite()

    def _persist_to_sqlite(self, db_path="audit_results.db"):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS run_metadata (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            os_type TEXT,
            total INTEGER,
            vulnerable INTEGER,
            passed INTEGER,
            unknown INTEGER
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            code TEXT,
            item TEXT,
            status TEXT,
            reason TEXT,
            current_value TEXT,
            evidence TEXT,
            category TEXT,
            risk TEXT,
            FOREIGN KEY(run_id) REFERENCES run_metadata(run_id)
        )
        """)

        total = len(self.audit_results)
        vulnerable = sum(1 for r in self.audit_results if r.get("status") == "VULNERABLE")
        passed = sum(1 for r in self.audit_results if r.get("status") == "SAFE")
        unknown = total - vulnerable - passed

        ts = datetime.datetime.utcnow().isoformat() + "Z"
        cur.execute(
            "INSERT INTO run_metadata(timestamp, os_type, total, vulnerable, passed, unknown) VALUES(?,?,?,?,?,?)",
            (ts, self.os_type, total, vulnerable, passed, unknown)
        )
        run_id = cur.lastrowid

        mapping = self.config.get(self.common_os_type, {})
        category_map = mapping.get("CATEGORY_MAPPING", {})
        risk_map = mapping.get("RISK_LEVEL_MAPPING", {})

        for r in self.audit_results:
            item = r.get("item", "")
            code = item.split('.')[0].strip() if (item.startswith("U-") or item.startswith("W-")) else ""
            category = category_map.get(code, "기타")
            risk = risk_map.get(code, "정보")
            cur.execute("""
                INSERT INTO audits(run_id, code, item, status, reason, current_value, evidence, category, risk)
                VALUES(?,?,?,?,?,?,?,?,?)
            """, (
                run_id, code, item, r.get("status", ""), r.get("reason", ""),
                str(r.get("current_value", "")),
                json.dumps(r.get("evidence", ""), ensure_ascii=False) if not isinstance(r.get("evidence", ""), str) else r.get("evidence", ""),
                category, risk
            ))
        conn.commit()
        conn.close()
        logging.info(f"SQLite 저장 완료: {db_path}")

# ==============================================================================
# DB 조회 기능을 위한 새로운 클래스
# ==============================================================================
class DBViewer:
    def __init__(self, db_path="audit_results.db"):
        self.db_path = db_path

    def _connect(self):
        if not os.path.exists(self.db_path):
            print(f"오류: 데이터베이스 파일 '{self.db_path}'을 찾을 수 없습니다. 먼저 점검을 1회 이상 실행하세요.")
            return None
        try:
            conn = sqlite3.connect(self.db_path)
            return conn
        except sqlite3.Error as e:
            print(f"데이터베이스 연결 오류: {e}")
            return None

    def show_all_runs(self):
        """현재까지 한 모든 검사 이력 확인"""
        conn = self._connect()
        if not conn: return
        
        cur = conn.cursor()
        cur.execute("SELECT run_id, timestamp, os_type, total, vulnerable, passed FROM run_metadata ORDER BY run_id DESC")
        rows = cur.fetchall()
        conn.close()

        if not rows:
            print("저장된 검사 이력이 없습니다.")
            return

        print("\n--- 모든 검사 이력 ---")
        print(f"{'ID':>4} | {'실행 시간':<28} | {'OS':<10} | {'총계':>5} | {'취약':>5} | {'양호':>5}")
        print("-" * 75)
        for row in rows:
            run_id, ts, os_type, total, vulnerable, passed = row
            print(f"{run_id:>4} | {ts:<28} | {os_type:<10} | {total:>5} | {vulnerable:>5} | {passed:>5}")

    def show_latest_run_details(self):
        """최근 검사 결과 상세 확인"""
        conn = self._connect()
        if not conn: return

        cur = conn.cursor()
        cur.execute("SELECT run_id FROM run_metadata ORDER BY run_id DESC LIMIT 1")
        latest_run = cur.fetchone()

        if not latest_run:
            print("저장된 검사 이력이 없습니다.")
            conn.close()
            return
        
        latest_run_id = latest_run[0]
        print(f"\n--- 최근 검사 상세 결과 (실행 ID: {latest_run_id}) ---")
        
        cur.execute("SELECT code, status, risk, item, reason FROM audits WHERE run_id = ?", (latest_run_id,))
        rows = cur.fetchall()
        conn.close()

        print(f"{'코드':<8} | {'상태':<12} | {'위험도':<5} | {'항목':<40} | {'사유'}")
        print("-" * 120)
        for row in rows:
            code, status, risk, item, reason = row
            reason_short = (reason[:70] + '...') if len(reason) > 70 else reason
            print(f"{code:<8} | {status:<12} | {risk:<5} | {item:<40} | {reason_short.replace(chr(10), ' ')}")

    def execute_user_query(self):
        """사용자 입력 쿼리 실행"""
        print("\n--- 사용자 직접 쿼리 ---")
        print("주의: 이 기능은 데이터베이스 구조를 아는 사용자를 위한 것입니다.")
        print("실행 가능한 테이블: run_metadata, audits")
        query = input("SQL 쿼리를 입력하세요 (종료: q) > ")

        if query.lower() == 'q':
            return
        
        conn = self._connect()
        if not conn: return

        try:
            cur = conn.cursor()
            cur.execute(query)
            
            # 컬럼 이름 가져오기
            col_names = [description[0] for description in cur.description] if cur.description else []
            
            rows = cur.fetchall()

            if not rows:
                print("쿼리 결과가 없습니다.")
            else:
                print(" | ".join(col_names))
                print("-" * (len(" | ".join(col_names)) + 5))
                for row in rows:
                    print(" | ".join(map(str, row)))
        
        except sqlite3.Error as e:
            print(f"쿼리 실행 오류: {e}")
        finally:
            conn.close()


# ==============================================================================
# 메인 실행 로직
# ==============================================================================
def db_menu():
    viewer = DBViewer()
    while True:
        print("\n--- DB 조회 메뉴 ---")
        print("1. 최근 검사 결과 확인")
        print("2. 현재까지 한 모든 검사 확인")
        print("3. 사용자 입력 (쿼리)")
        print("b. 메인 메뉴로 돌아가기")
        choice = input("선택 > ")

        if choice == '1':
            viewer.show_latest_run_details()
        elif choice == '2':
            viewer.show_all_runs()
        elif choice == '3':
            viewer.execute_user_query()
        elif choice.lower() == 'b':
            break
        else:
            print("잘못된 입력입니다. 다시 선택해주세요.")

def main_menu():
    while True:
        print("\n" + "="*15 + " 메인 메뉴 " + "="*15)
        print("1. 보안 점검 실행")
        print("2. DB 조회")
        print("q. 종료")
        print("="*38)
        choice = input("선택 > ")

        if choice == '1':
            engine = SecurityAuditEngine()
            print(f"\n{engine.os_type} 점검을 시작합니다. 잠시만 기다려주세요.")
            if engine.run_audits():
                engine.generate_report()
                print("\n점검이 성공적으로 완료되었습니다.")
            else:
                print("\n점검이 중단되었습니다. 로그 파일을 확인해주세요.")

        elif choice == '2':
            db_menu()
        elif choice.lower() == 'q':
            print("프로그램을 종료합니다.")
            break
        else:
            print("잘못된 입력입니다. 다시 선택해주세요.")

if __name__ == "__main__":
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    if current_script_dir not in sys.path:
        sys.path.insert(0, current_script_dir)

    audit_modules_path = os.path.join(current_script_dir, 'audit_modules')
    if not os.path.exists(audit_modules_path) or not os.path.isdir(audit_modules_path):
        logging.error(f"오류: '{audit_modules_path}' 디렉토리를 찾을 수 없습니다.")
        sys.exit(1)
    if not os.path.exists(os.path.join(audit_modules_path, '__init__.py')):
        logging.error(f"오류: '{audit_modules_path}/__init__.py' 파일이 없습니다.")
        sys.exit(1)

    main_menu()
    
    # input("Press Enter to exit...") # 메뉴 시스템에서는 불필요