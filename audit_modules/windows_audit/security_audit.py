import subprocess
import logging
import re
import os
import winreg # Windows 레지스트리 접근을 위한 모듈
import json
from audit_modules.windows_audit.audit_module import AuditModule # JSON 파싱을 위해 추가


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
                
                # 인스턴스 ID를 가져오는 더 견고한 방법 필요
                # 여기서는 간단하게 Default Instance (MSSQLSERVER) 및 명명된 인스턴스 처리
                
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

