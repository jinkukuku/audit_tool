import subprocess
import logging
import re
import os
import winreg # Windows 레지스트리 접근을 위한 모듈
import json
from audit_modules.windows_audit.audit_module import AuditModule # JSON 파싱을 위해 추가


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
            self._record_result(item, "COMPLIANT", "불필요하다고 판단되는 서비스가 실행 중이지 않습니다.",
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
            self._record_result(item, "COMPLIANT", "IIS 서비스(World Wide Web Publishing Service)가 중지 및 사용 안 함으로 설정되어 있습니다.",
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
                self._record_result(item, "COMPLIANT",
                                    "IIS 디렉터리 리스팅이 비활성화되어 있습니다.",
                                    current_value="비활성화 (enabled=false)",
                                    recommended_value="비활성화 (enabled=false)")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w12_iis_cgi_execution_restriction(self):
        """
        W-12: IIS CGI 실행 제한
        - 점검기준: CGI 스크립트 디렉터리(C:\\inetpub\\scripts)에 Everyone에 모든 권한, 수정 권한, 쓰기 권한이 부여되지 않은 경우 양호.
                    부여되어 있는 경우 취약.
        - 점검방법: icacls 명령어로 C:\\inetpub\\scripts 디렉터리 권한 확인.
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT",
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
            self._record_result(item, "COMPLIANT", "불필요한 IIS 샘플 디렉터리가 존재하지 않습니다.",
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT", "IIS 웹 홈 디렉터리 내에 바로가기/링크 파일이 존재하지 않습니다.",
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT", "불필요한 IIS 가상 디렉터리(IISAdmin, IISAdminpwd)가 존재하지 않습니다.",
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
                self._record_result(item, "COMPLIANT", "IIS 데이터 파일에 Everyone 권한이 적절하게 제한되어 있습니다.",
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
                self._record_result(item, "COMPLIANT", "미사용 또는 취약한 스크립트 매핑이 존재하지 않습니다.",
                                    current_value="없음",
                                    recommended_value="제거")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w22_iis_exec_command_shell_call(self):
        """
        W-22: IIS Exec 명령어 쉘 호출 진단
        - 점검기준: IIS 5.0 버전에서 해당 레지스트리 값이 0이거나, IIS 6.0 버전 이상인 경우 양호.
                    IIS 5.0 버전에서 해당 레지스트리 값이 1인 경우 취약.
        - 점검방법: 레지스트리 HKLM\\SYSTEM\\CurrentControlSet\\Services\\W3SVC\\Parameters\\SSIEnableCmdDirective 확인.
        """
        item = "W-22. IIS Exec 명령어 쉘 호출 진단"
        try:
            # IIS 버전 확인 (PowerShell)
            iis_version_output = self._execute_powershell(r"(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp).MajorVersion")
            iis_major_version = int(iis_version_output) if iis_version_output else 0

            if iis_major_version >= 6: # IIS 6.0 이상
                self._record_result(item, "COMPLIANT", "IIS 6.0 이상 버전이므로 Exec 명령어 쉘 호출 취약점에 해당하지 않습니다.",
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT", "IIS 서비스가 실행 중이지 않아 WebDAV 취약점에 해당하지 않습니다.")
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
                self._record_result(item, "COMPLIANT", "WebDAV가 레지스트리를 통해 비활성화되어 있습니다.",
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
                    self._record_result(item, "COMPLIANT", "IIS WebDAV가 비활성화되어 있습니다.",
                                        current_value="WebDAV enabled=false",
                                        recommended_value="WebDAV enabled=false")
            else:
                self._record_result(item, "UNKNOWN", "applicationHost.config 파일을 찾을 수 없어 WebDAV 설정을 확인할 수 없습니다.")

        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w24_netbios_binding_service(self):
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
                self._record_result(item, "COMPLIANT",
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
            self._record_result(item, "COMPLIANT", "FTP Publishing Service가 중지 및 사용 안 함으로 설정되어 있습니다.",
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
                self._record_result(item, "COMPLIANT", "FTP 서비스가 실행 중이지 않아 Anonymous FTP 취약점에 해당하지 않습니다.")
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT",
                                    "FTP 접근 제어 설정이 적용되어 있습니다. (특정 IP만 허용 또는 명시적 거부)",
                                    current_value="특정 IP 제한",
                                    recommended_value="특정 IP만 허용")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w29_dns_zone_transfer(self):
        r"""
        W-29: DNS Zone Transfer 설정
        - 점검기준: DNS 서비스를 사용하지 않거나, 영역 전송 허용을 하지 않는 경우, 또는 특정 서버로만 설정이 되어 있는 경우 양호.
                    위 3개 기준 중 하나라도 해당 되지 않는 경우 취약.
        - 점검방법: DNS 관리자 (DNSMGMT.MSC) 또는 레지스트리 HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones\[각 DNS 영역]\SecureSecondaries 확인.
        """
        item = "W-29. DNS Zone Transfer 설정"
        try:
            dns_status, _ = self._get_service_status("DNS") # DNS Server 서비스
            if dns_status != "Running":
                self._record_result(item, "COMPLIANT", "DNS 서비스가 실행 중이지 않아 DNS Zone Transfer 취약점에 해당하지 않습니다.")
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
                self._record_result(item, "COMPLIANT", "모든 DNS Zone의 Zone Transfer 설정이 적절합니다.",
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
        r"""
        W-30: RDS(Remote Data Services) 제거
        - 점검기준: IIS를 사용하지 않거나, Windows 2000 SP4, 2003 SP2 이상 설치, 또는 디폴트 웹 사이트에 MSADC 가상 디렉터리가 존재하지 않는 경우, 또는 해당 레지스트리 값이 존재하지 않는 경우 양호.
        - 점검방법: IIS 서비스 실행 확인 및 레지스트리 HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch 확인.
        """
        item = "W-30. RDS(Remote Data Services) 제거"
        try:
            iis_status, _ = self._get_service_status("W3SVC")
            if iis_status != "Running":
                self._record_result(item, "COMPLIANT", "IIS 서비스가 실행 중이지 않아 RDS 취약점에 해당하지 않습니다.")
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
                self._record_result(item, "COMPLIANT", "RDS(Remote Data Services) 관련 레지스트리 키가 존재하지 않습니다.",
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT", "IIS 웹 서비스 버전 정보가 HTTP 응답 헤더에 노출되어 있지 않습니다.",
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
            self._record_result(item, "COMPLIANT", "SNMP 서비스가 중지 및 사용 안 함으로 설정되어 있습니다.",
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
        r"""
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
                self._record_result(item, "COMPLIANT", "SNMP 서비스 커뮤니티 스트링이 적절하게 설정되어 있습니다.",
                                    current_value="적절",
                                    recommended_value="복잡한 커뮤니티 스트링 사용")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

    def check_w62_snmp_access_control(self):
        r"""
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
                self._record_result(item, "COMPLIANT",
                                    "SNMP Access control이 적절하게 설정되어 있습니다. (127.0.0.1만 허용)",
                                    current_value=f"허용된 IP: {', '.join(allowed_ips)}",
                                    recommended_value="127.0.0.1만 허용")
            elif not allowed_ips: # PermittedManagers 키는 있지만 허용된 IP가 없는 경우
                self._record_result(item, "COMPLIANT",
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
            self._record_result(item, "COMPLIANT", "DNS 서비스가 중지 및 사용 안 함으로 설정되어 있습니다.",
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
            self._record_result(item, "COMPLIANT", "HTTP/FTP/SMTP 서비스 배너 정보가 노출되지 않습니다.",
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
            self._record_result(item, "COMPLIANT", "Telnet 서비스가 중지 및 사용 안 함으로 설정되어 있습니다.",
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
                self._record_result(item, "COMPLIANT", "불필요한 ODBC 데이터 소스(DSN)가 존재하지 않습니다. (OLE-DB 드라이브는 수동 확인 필요)",
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
                self._record_result(item, "COMPLIANT",
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
                self._record_result(item, "COMPLIANT", "예약된 작업이 존재하지 않습니다.",
                                    current_value="예약 작업 없음",
                                    recommended_value="예약 작업 없음")
        except Exception as e:
            self._record_result(item, "ERROR", f"점검 중 오류 발생: {e}")

