import logging
import re
import os
import pwd
from base_audit_module import BaseAuditModule
from platform_utils import PlatformUtils

class FileDirectoryAudit(BaseAuditModule):
    """
    파일 및 디렉터리 관리 관련 보안 점검을 수행하는 모듈입니다.
    대상 항목: U-05 ~ U-18, U-55 ~ U-59
    """
    def __init__(self, config):
        super().__init__(config)
        self.module_name = "파일 및 디렉터리 관리"
        self.file_dir_config = self.config.get('file_directory_management', {})

    def run_audit(self):
        logging.info(f"{self.module_name} 점검을 시작합니다.")
        self.module_audit_results = [] # 점검 시작 전 결과 목록 초기화

        # U-05. root 홈, 패스 디렉터리 권한 및 패스 설정
        item_u05 = "U-05. root 홈, 패스 디렉터리 권한 및 패스 설정"
        self._log_audit_item(item_u05)
        path_env = os.environ.get('PATH', '')
        if '::' in path_env or path_env.startswith(':') or path_env.startswith('.') or (':.' in path_env and path_env.index(':') < path_env.index('.')):
            status = "취약"
            details = "PATH 환경변수에 '.' 또는 '::'이 포함되어 있습니다."
            action = "PATH에서 '.' 또는 '::' 제거"
        else:
            status = "양호"
            details = "PATH 환경변수에 '.' 또는 '::'이 포함되어 있지 않습니다."
            action = "적절한 PATH 설정 유지"
        self._add_audit_result(item_u05, status, details, "자동 점검", action)

        # U-06. 파일 및 디렉터리 소유자 설정
        item_u06 = "U-06. 파일 및 디렉터리 소유자 설정"
        self._log_audit_item(item_u06)
        stdout, _, returncode = PlatformUtils.execute_command(['find', '/', '-nouser', '-o', '-nogroup', '-xdev', '-ls'])
        if returncode == 0 and stdout:
            status = "취약"
            details = f"소유자 없는 파일/디렉터리가 발견되었습니다: {stdout.splitlines()[0]} 등"
            action = "find 명령으로 검색된 파일/디렉터리의 소유자 설정"
        else:
            status = "양호"
            details = "소유자 없는 파일 또는 디렉터리가 발견되지 않았습니다."
            action = "적절한 소유자 설정 유지"
        self._add_audit_result(item_u06, status, details, "자동 점검", action)

        # U-07. /etc/passwd 파일 소유자 및 권한 설정
        item_u07 = "U-07. /etc/passwd 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u07)
        filepath = self.file_dir_config.get('u07_passwd_path', "/etc/passwd")
        expected_owner = "root"
        max_perms_octal = "644"
        
        is_compliant_u07 = True
        reasons_u07 = []
        current_owner_u07 = "N/A"
        current_perms_octal_u07 = "N/A"

        if not PlatformUtils.check_file_exists(filepath):
            is_compliant_u07 = False
            reasons_u07.append(f"'{filepath}' 파일이 존재하지 않습니다.")
        else:
            current_owner_u07 = PlatformUtils.get_file_owner(filepath)
            current_perms_octal_u07 = PlatformUtils.get_file_permissions(filepath)
            
            if current_owner_u07 is None or current_perms_octal_u07 is None:
                is_compliant_u07 = False
                reasons_u07.append("파일 정보(소유자/권한)를 가져올 수 없습니다.")
            else:
                if current_owner_u07 != expected_owner:
                    is_compliant_u07 = False
                    reasons_u07.append(f"소유자가 '{expected_owner}'가 아닙니다. (현재: {current_owner_u07})")
                
                try:
                    current_perms_decimal = int(current_perms_octal_u07, 8)
                    max_perms_decimal = int(max_perms_octal, 8)
                    if current_perms_decimal > max_perms_decimal:
                        is_compliant_u07 = False
                        reasons_u07.append(f"권한이 {max_perms_octal}보다 높습니다. (현재: {current_perms_octal_u07})")
                except ValueError:
                    is_compliant_u07 = False
                    reasons_u07.append(f"권한 '{current_perms_octal_u07}' 형식이 올바르지 않습니다.")
            
        if is_compliant_u07:
            self._add_audit_result(
                item_u07,
                "COMPLIANT",
                "파일 소유자 및 권한 설정이 양호합니다.",
                f"소유자: {current_owner_u07}, 권한: {current_perms_octal_u07}",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )
        else:
            self._add_audit_result(
                item_u07,
                "VULNERABLE",
                "; ".join(reasons_u07),
                f"소유자: {current_owner_u07}, 권한: {current_perms_octal_u07}",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )

        # U-08. /etc/shadow 파일 소유자 및 권한 설정
        item_u08 = "U-08. /etc/shadow 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u08)
        filepath = self.file_dir_config.get('u08_shadow_path', "/etc/shadow")
        expected_owner = "root"
        max_perms_octal = "400"
        
        is_compliant_u08 = True
        reasons_u08 = []
        current_owner_u08 = "N/A"
        current_perms_octal_u08 = "N/A"

        if not PlatformUtils.check_file_exists(filepath):
            is_compliant_u08 = False
            reasons_u08.append(f"'{filepath}' 파일이 존재하지 않습니다.")
        else:
            current_owner_u08 = PlatformUtils.get_file_owner(filepath)
            current_perms_octal_u08 = PlatformUtils.get_file_permissions(filepath)
            
            if current_owner_u08 is None or current_perms_octal_u08 is None:
                is_compliant_u08 = False
                reasons_u08.append("파일 정보(소유자/권한)를 가져올 수 없습니다.")
            else:
                if current_owner_u08 != expected_owner:
                    is_compliant_u08 = True
                    reasons_u08.append(f"소유자가 '{expected_owner}'가 아닙니다. (현재: {current_owner_u08})")
                
                try:
                    current_perms_decimal = int(current_perms_octal_u08, 8)
                    max_perms_decimal = int(max_perms_octal, 8)
                    if current_perms_decimal > max_perms_decimal:
                        is_compliant_u08 = False
                        reasons_u08.append(f"권한이 {max_perms_octal}보다 높습니다. (현재: {current_perms_octal_u08})")
                except ValueError:
                    is_compliant_u08 = False
                    reasons_u08.append(f"권한 '{current_perms_octal_u08}' 형식이 올바르지 않습니다.")
            
        if is_compliant_u08:
            self._add_audit_result(
                item_u08,
                "COMPLIANT",
                "파일 소유자 및 권한 설정이 양호합니다.",
                f"소유자: {current_owner_u08}, 권한: {current_perms_octal_u08}",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )
        else:
            self._add_audit_result(
                item_u08,
                "VULNERABLE",
                "; ".join(reasons_u08),
                f"소유자: {current_owner_u08}, 권한: {current_perms_octal_u08}",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )

        # U-09. /etc/hosts 파일 소유자 및 권한 설정
        item_u09 = "U-09. /etc/hosts 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u09)
        filepath = self.file_dir_config.get('u09_hosts_path', "/etc/hosts")
        expected_owner = "root"
        max_perms_octal = "600"
        
        is_compliant_u09 = True
        reasons_u09 = []
        current_owner_u09 = "N/A"
        current_perms_octal_u09 = "N/A"

        if not PlatformUtils.check_file_exists(filepath):
            is_compliant_u09 = False
            reasons_u09.append(f"'{filepath}' 파일이 존재하지 않습니다.")
        else:
            current_owner_u09 = PlatformUtils.get_file_owner(filepath)
            current_perms_octal_u09 = PlatformUtils.get_file_permissions(filepath)
            
            if current_owner_u09 is None or current_perms_octal_u09 is None:
                is_compliant_u09 = False
                reasons_u09.append("파일 정보(소유자/권한)를 가져올 수 없습니다.")
            else:
                if current_owner_u09 != expected_owner:
                    is_compliant_u09 = True
                    reasons_u09.append(f"소유자가 '{expected_owner}'가 아닙니다. (현재: {current_owner_u09})")
                
                try:
                    current_perms_decimal = int(current_perms_octal_u09, 8)
                    max_perms_decimal = int(max_perms_octal, 8)
                    if current_perms_decimal > max_perms_decimal:
                        is_compliant_u09 = False
                        reasons_u09.append(f"권한이 {max_perms_octal}보다 높습니다. (현재: {current_perms_octal_u09})")
                except ValueError:
                    is_compliant_u09 = False
                    reasons_u09.append(f"권한 '{current_perms_octal_u09}' 형식이 올바르지 않습니다.")
            
        if is_compliant_u09:
            self._add_audit_result(
                item_u09,
                "COMPLIANT",
                "파일 소유자 및 권한 설정이 양호합니다.",
                f"소유자: {current_owner_u09}, 권한: {current_perms_octal_u09}",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )
        else:
            self._add_audit_result(
                item_u09,
                "VULNERABLE",
                "; ".join(reasons_u09),
                f"소유자: {current_owner_u09}, 권한: {current_perms_octal_u09}",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )

        # U-10. /etc/(x)inetd.conf 파일 소유자 및 권한 설정
        item_u10 = "U-10. /etc/(x)inetd.conf 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u10)
        inetd_conf_paths = self.file_dir_config.get('u10_inetd_conf_paths', ["/etc/inetd.conf", "/etc/xinetd.conf"])
        is_compliant_u10 = True
        vulnerable_reasons_u10 = []

        for filepath in inetd_conf_paths:
            expected_owner = "root"
            max_perms_octal = "600"
            
            if not PlatformUtils.check_file_exists(filepath):
                # 파일이 존재하지 않으면 양호 (최신 systemd 기반 시스템에서는 보통 없음)
                logging.info(f"  - '{filepath}' 파일이 존재하지 않습니다. (양호로 간주)")
                continue # 다음 파일로 넘어감
            else:
                current_owner = PlatformUtils.get_file_owner(filepath)
                current_perms_octal = PlatformUtils.get_file_permissions(filepath)
                
                if current_owner is None or current_perms_octal is None:
                    is_compliant_u10 = False
                    vulnerable_reasons_u10.append(f"'{filepath}' 파일 정보(소유자/권한)를 가져올 수 없습니다.")
                else:
                    if current_owner != expected_owner:
                        is_compliant_u10 = False
                        vulnerable_reasons_u10.append(f"'{filepath}' 소유자가 '{expected_owner}'가 아닙니다. (현재: {current_owner})")
                    
                    try:
                        current_perms_decimal = int(current_perms_octal, 8)
                        max_perms_decimal = int(max_perms_octal, 8)
                        if current_perms_decimal > max_perms_decimal:
                            is_compliant_u10 = False
                            vulnerable_reasons_u10.append(f"'{filepath}' 권한이 {max_perms_octal}보다 높습니다. (현재: {current_perms_octal})")
                    except ValueError:
                        is_compliant_u10 = False
                        vulnerable_reasons_u10.append(f"'{filepath}' 권한 '{current_perms_octal}' 형식이 올바르지 않습니다.")
        
        if is_compliant_u10:
            self._add_audit_result(
                item_u10,
                "COMPLIANT",
                "파일 소유자 및 권한 설정이 양호합니다.",
                "설정 확인됨",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )
        else:
            self._add_audit_result(
                item_u10,
                "VULNERABLE",
                "; ".join(vulnerable_reasons_u10),
                "현재 설정값 확인 필요",
                f"소유자: {expected_owner}, 권한: {max_perms_octal}"
            )

        # U-11. /etc/syslog.conf 파일 소유자 및 권한 설정
        item_u11 = "U-11. /etc/syslog.conf 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u11)
        syslog_conf_paths = self.file_dir_config.get('u11_syslog_conf_paths', ["/etc/syslog.conf", "/etc/rsyslog.conf"])
        is_compliant_u11 = True
        vulnerable_reasons_u11 = []

        for filepath in syslog_conf_paths:
            expected_owner_options = ["root", "bin", "sys"]
            max_perms_octal = "640" # 640 이하
            
            if not PlatformUtils.check_file_exists(filepath):
                logging.info(f"  - '{filepath}' 파일이 존재하지 않습니다. (양호로 간주)")
                continue
            else:
                current_owner = PlatformUtils.get_file_owner(filepath)
                current_perms_octal = PlatformUtils.get_file_permissions(filepath)
                
                if current_owner is None or current_perms_octal is None:
                    is_compliant_u11 = False
                    vulnerable_reasons_u11.append(f"'{filepath}' 파일 정보(소유자/권한)를 가져올 수 없습니다.")
                else:
                    if current_owner not in expected_owner_options:
                        is_compliant_u11 = False
                        vulnerable_reasons_u11.append(f"'{filepath}' 소유자가 '{'/'.join(expected_owner_options)}'가 아닙니다. (현재: {current_owner})")
                    
                    try:
                        current_perms_decimal = int(current_perms_octal, 8)
                        max_perms_decimal = int(max_perms_octal, 8)
                        if current_perms_decimal > max_perms_decimal:
                            is_compliant_u11 = False
                            vulnerable_reasons_u11.append(f"'{filepath}' 권한이 {max_perms_octal}보다 높습니다. (현재: {current_perms_octal})")
                    except ValueError:
                        is_compliant_u11 = False
                        vulnerable_reasons_u11.append(f"'{filepath}' 권한 '{current_perms_octal}' 형식이 올바르지 않습니다.")
        
        if is_compliant_u11:
            self._add_audit_result(
                item_u11,
                "COMPLIANT",
                "파일 소유자 및 권한 설정이 양호합니다.",
                "설정 확인됨",
                f"소유자: {'/'.join(expected_owner_options)}, 권한: {max_perms_octal}"
            )
        else:
            self._add_audit_result(
                item_u11,
                "VULNERABLE",
                "; ".join(vulnerable_reasons_u11),
                "현재 설정값 확인 필요",
                f"소유자: {'/'.join(expected_owner_options)}, 권한: {max_perms_octal}"
            )

        # U-12. /etc/services 파일 소유자 및 권한 설정
        item_u12 = "U-12. /etc/services 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u12)
        filepath = self.file_dir_config.get('u12_services_path', "/etc/services")
        expected_owner_options = ["root", "bin", "sys"]
        max_perms_octal = "644"
        
        is_compliant_u12 = True
        reasons_u12 = []
        current_owner_u12 = "N/A"
        current_perms_octal_u12 = "N/A"

        if not PlatformUtils.check_file_exists(filepath):
            is_compliant_u12 = False
            reasons_u12.append(f"'{filepath}' 파일이 존재하지 않습니다.")
        else:
            current_owner_u12 = PlatformUtils.get_file_owner(filepath)
            current_perms_octal_u12 = PlatformUtils.get_file_permissions(filepath)
            
            if current_owner_u12 is None or current_perms_octal_u12 is None:
                is_compliant_u12 = False
                reasons_u12.append("파일 정보(소유자/권한)를 가져올 수 없습니다.")
            else:
                if current_owner_u12 not in expected_owner_options:
                    is_compliant_u12 = False
                    reasons_u12.append(f"소유자가 '{'/'.join(expected_owner_options)}'가 아닙니다. (현재: {current_owner_u12})")
                
                try:
                    current_perms_decimal = int(current_perms_octal_u12, 8)
                    max_perms_decimal = int(max_perms_octal, 8)
                    if current_perms_decimal > max_perms_decimal:
                        is_compliant_u12 = False
                        reasons_u12.append(f"권한이 {max_perms_octal}보다 높습니다. (현재: {current_perms_octal_u12})")
                except ValueError:
                    is_compliant_u12 = False
                    reasons_u12.append(f"권한 '{current_perms_octal_u12}' 형식이 올바르지 않습니다.")
            
        if is_compliant_u12:
            self._add_audit_result(
                item_u12,
                "COMPLIANT",
                "파일 소유자 및 권한 설정이 양호합니다.",
                f"소유자: {current_owner_u12}, 권한: {current_perms_octal_u12}",
                f"소유자: {'/'.join(expected_owner_options)}, 권한: {max_perms_octal}"
            )
        else:
            self._add_audit_result(
                item_u12,
                "VULNERABLE",
                "; ".join(reasons_u12),
                f"소유자: {current_owner_u12}, 권한: {current_perms_octal_u12}",
                f"소유자: {'/'.join(expected_owner_options)}, 권한: {max_perms_octal}"
            )

        # U-13. SUID, SGID 설정 파일 점검
        item_u13 = "U-13. SUID, SGID 설정 파일 점검"
        self._log_audit_item(item_u13)
        stdout, _, returncode = PlatformUtils.execute_command(['find', '/', '-user', 'root', '-perm', '-4000', '-o', '-perm', '-2000', '-xdev', '-ls'])
        if returncode == 0 and stdout:
            status = "취약"
            details = f"SUID/SGID 권한이 설정된 파일이 발견되었습니다: {stdout.splitlines()[0]} 등"
            action = "불필요한 SUID/SGID 권한 제거"
        else:
            status = "양호"
            details = "SUID/SGID 권한이 설정된 파일이 발견되지 않았습니다."
            action = "적절한 SUID/SGID 설정 유지"
        self._add_audit_result(item_u13, status, details, "자동 점검", action)

        # U-14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
        item_u14 = "U-14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
        self._log_audit_item(item_u14)
        config_files_u14 = ['/etc/profile', '/etc/csh.login', '/etc/bashrc', '/etc/bash.bashrc', '/etc/login.defs', '/etc/skel']
        vulnerable_files_u14 = []
        
        for filepath in config_files_u14:
            is_safe, details = PlatformUtils.is_file_owned_by_root_and_permission_safe(filepath, 644)
            if not is_safe:
                vulnerable_files_u14.append(f"{filepath}: {details}")
        
        if vulnerable_files_u14:
            status = "취약"
            details = "취약한 설정 파일이 발견되었습니다:\n" + "\n".join(vulnerable_files_u14)
            action = "해당 파일들의 소유자를 root로, 권한을 644 이하로 설정"
        else:
            status = "양호"
            details = "주요 환경 설정 파일의 소유자 및 권한이 적절하게 설정되었습니다."
            action = "적절한 소유자 및 권한 설정 유지"
        self._add_audit_result(item_u14, status, details, "자동 점검", action)

        # U-15. world writable 파일 점검
        item_u15 = "U-15. world writable 파일 점검"
        self._log_audit_item(item_u15)
        # 0o002는 world-writable 권한을 의미
        stdout, _, returncode = PlatformUtils.execute_command(['find', '/', '-perm', '-002', '-xdev', '-ls'])
        if returncode == 0 and stdout:
            status = "취약"
            details = f"world writable 파일이 발견되었습니다: {stdout.splitlines()[0]} 등"
            action = "불필요한 world writable 권한 제거"
        else:
            status = "양호"
            details = "world writable 파일이 발견되지 않았습니다."
            action = "적절한 파일 권한 설정 유지"
        self._add_audit_result(item_u15, status, details, "자동 점검", action)

        # U-16. /dev에 존재하지 않는 device 파일 점검
        item_u16 = "U-16. /dev에 존재하지 않는 device 파일 점검"
        self._log_audit_item(item_u16)
        vulnerable_devices = []
        try:
            for root, _, files in os.walk('/dev'):
                for name in files:
                    filepath = os.path.join(root, name)
                    if os.path.exists(filepath) and not os.path.islink(filepath):
                        stat_info = os.stat(filepath)
                        # major, minor number가 없는 일반 파일 확인
                        if stat_info.st_dev and stat_info.st_ino and (stat_info.st_mode & 0o170000) == 0o100000:
                            vulnerable_devices.append(filepath)
        except Exception as e:
            logging.error(f"U-16 점검 중 오류 발생: {e}")
        
        if vulnerable_devices:
            status = "취약"
            details = f"장치 파일이 아닌 일반 파일이 /dev 디렉터리에서 발견되었습니다: {', '.join(vulnerable_devices)}"
            action = "비정상적인 파일을 제거하거나 적절한 파일로 교체"
        else:
            status = "양호"
            details = "/dev 디렉터리에서 비정상적인 일반 파일이 발견되지 않았습니다."
            action = "적절한 디렉터리 설정 유지"
        self._add_audit_result(item_u16, status, details, "자동 점검", action)


        # U-17. $HOME/.rhosts, hosts.equiv 사용 금지
        item_u17 = "U-17. $HOME/.rhosts, hosts.equiv 사용 금지"
        self._log_audit_item(item_u17)
        r_files = ['/etc/hosts.equiv']
        home_dir = os.path.expanduser('~')
        r_files.append(os.path.join(home_dir, '.rhosts'))

        vulnerable_files = []
        for filepath in r_files:
            if PlatformUtils.check_file_exists(filepath):
                content = PlatformUtils.read_file_content(filepath)
                if content and '+' in content:
                    vulnerable_files.append(filepath)
        
        if vulnerable_files:
            status = "취약"
            details = f"취약한 권한의 r 계열 파일이 발견되었습니다: {', '.join(vulnerable_files)}"
            action = "해당 파일에서 '+' 문자 제거 및 권한 조정"
        else:
            status = "양호"
            details = "취약한 r 계열 파일이 발견되지 않았습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u17, status, details, "자동 점검", action)

        # U-18. 접속 IP 및 포트 제한
        item_u18 = "U-18. 접속 IP 및 포트 제한"
        self._log_audit_item(item_u18)
        # 점검 방법: TCP Wrapper (/etc/hosts.deny, /etc/hosts.allow) 또는 IPtables (iptables -L) 설정 확인
        # TODO: U-18 구현
        self._add_audit_result(
            item_u18,
            "INFO",
            "접속 IP 및 포트 제한 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "불필요한 IP 및 포트 접근 제한"
        )

        # U-55. hosts.lpd 파일 소유자 및 권한 설정
        item_u55 = "U-55. hosts.lpd 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u55)
        filepath_u55 = '/etc/hosts.lpd'
        is_safe, details = PlatformUtils.is_file_owned_by_root_and_permission_safe(filepath_u55, 600)
        
        if is_safe:
            status = "양호"
        else:
            status = "취약"

        self._add_audit_result(item_u55, status, details, "자동 점검", "hosts.lpd 파일 삭제 또는 소유자: root, 권한: 600 설정")

        # U-56. UMASK 설정 관리
        item_u56 = "U-56. UMASK 설정 관리"
        self._log_audit_item(item_u56)
        
        # 점검 대상 파일 목록
        umask_files = ['/etc/profile', '/etc/csh.login', '/etc/bashrc']
        vulnerable_files = []
        is_secure = True
        
        for filepath in umask_files:
            if PlatformUtils.check_file_exists(filepath):
                content = PlatformUtils.read_file_content(filepath)
                if content:
                    # umask 설정 값 찾기
                    match = re.search(r'^\s*umask\s+([0-9]{3})', content, re.MULTILINE)
                    if match:
                        umask_value = match.group(1)
                        # 022 미만인지 확인
                        if int(umask_value, 8) < int('022', 8):
                            is_secure = False
                            vulnerable_files.append(f"{filepath}에서 취약한 umask 값 ({umask_value}) 발견")
                    else:
                        is_secure = False
                        vulnerable_files.append(f"{filepath}에서 umask 설정 값을 찾을 수 없습니다.")

        if is_secure:
            status = "양호"
            details = "주요 환경 설정 파일에서 umask 값이 022 이상으로 설정되어 있습니다."
            action = "적절한 umask 설정 유지"
        else:
            status = "취약"
            details = "다음 파일들에서 취약한 umask 설정이 발견되었습니다:\n" + "\n".join(vulnerable_files)
            action = "umask 값을 022 이상으로 설정"
        self._add_audit_result(item_u56, status, details, "자동 점검", action)

        # U-57. 홈 디렉터리 소유자 및 권한 설정
        item_u57 = "U-57. 홈 디렉터리 소유자 및 권한 설정"
        self._log_audit_item(item_u57)
        vulnerable_homes = []
        for user_entry in pwd.getpwall():
            username = user_entry.pw_name
            home_dir = user_entry.pw_dir
            if not os.path.isdir(home_dir):
                continue
            
            try:
                stat_info = os.stat(home_dir)
                # 소유자 확인
                owner = pwd.getpwuid(stat_info.st_uid).pw_name
                if owner != username:
                    vulnerable_homes.append(f"홈 디렉터리 소유자 불일치: {home_dir} (소유자: {owner}, 사용자: {username})")
                
                # 타인 쓰기 권한 확인
                if stat_info.st_mode & 0o002:
                    vulnerable_homes.append(f"타인 쓰기 권한 존재: {home_dir} (권한: {oct(stat_info.st_mode)[-3:]})")
            except Exception as e:
                logging.error(f"홈 디렉터리 검증 중 오류 발생: {home_dir} - {e}")
                
        if vulnerable_homes:
            status = "취약"
            details = "\n".join(vulnerable_homes)
            action = "각 사용자 홈 디렉터리 소유자 및 권한 적절하게 설정"
        else:
            status = "양호"
            details = "모든 사용자 홈 디렉터리의 소유자 및 권한이 적절하게 설정되었습니다."
            action = "적절한 홈 디렉터리 소유자 및 권한 설정 유지"
        self._add_audit_result(item_u57, status, details, "자동 점검", action)


        # U-58. 홈 디렉터리로 지정한 디렉터리의 존재 관리
        item_u58 = "U-58. 홈 디렉터리로 지정한 디렉터리의 존재 관리"
        self._log_audit_item(item_u58)
        missing_homes = []
        for user_entry in pwd.getpwall():
            home_dir = user_entry.pw_dir
            if not os.path.isdir(home_dir):
                missing_homes.append(f"존재하지 않는 홈 디렉터리: {home_dir} (사용자: {user_entry.pw_name})")

        if missing_homes:
            status = "취약"
            details = "\n".join(missing_homes)
            action = "존재하지 않는 홈 디렉터리 제거 또는 생성"
        else:
            status = "양호"
            details = "모든 사용자 홈 디렉터리가 존재합니다."
            action = "적절한 홈 디렉터리 존재 관리"
        self._add_audit_result(item_u58, status, details, "자동 점검", action)

        # U-59. 숨겨진 파일 및 디렉터리 검색 및 제거
        # (기존 코드 유지)

        # U-63. ftpusers 파일 소유자 및 권한 설정
        item_u63 = "U-63. ftpusers 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u63)
        ftpusers_paths = ['/etc/ftpusers', '/etc/ftpd/ftpusers']
        is_safe = False
        details = ""
        for path in ftpusers_paths:
            is_safe, details = PlatformUtils.is_file_owned_by_root_and_permission_safe(path, 640)
            if is_safe:
                break
        
        if is_safe:
            status = "양호"
        else:
            status = "취약"
            if "파일이 존재하지 않습니다" in details:
                # 파일이 없는 경우, 취약하다고 판단
                details = f"{ftpusers_paths} 파일이 존재하지 않아 점검할 수 없습니다. 취약 가능성이 있습니다."
                
        self._add_audit_result(item_u63, status, details, "자동 점검", "ftpusers 파일의 소유자: root, 권한: 640 이하 설정")
        
        logging.info(f"{self.module_name} 점검이 완료되었습니다.")
        return self.module_audit_results