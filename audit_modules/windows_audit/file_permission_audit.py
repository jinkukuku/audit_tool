import logging
import os
import re
from audit_modules.windows_audit.audit_module import AuditModule


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