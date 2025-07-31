import logging
import os
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
        # 점검 방법: PATH 환경변수에 "." 또는 "::"이 맨 앞이나 중간에 포함되지 않았는지 확인
        # TODO: U-05 구현
        self._add_audit_result(
            item_u05,
            "INFO",
            "root 홈, 패스 디렉터리 권한 및 패스 설정 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "PATH에 '.' 또는 '::' 제거"
        )

        # U-06. 파일 및 디렉터리 소유자 설정
        item_u06 = "U-06. 파일 및 디렉터리 소유자 설정"
        self._log_audit_item(item_u06)
        # 점검 방법: find / -nouser -o -nogroup -xdev -ls 2>/dev/null 명령으로 소유자 없는 파일/디렉터리 검색
        # TODO: U-06 구현
        self._add_audit_result(
            item_u06,
            "INFO",
            "파일 및 디렉터리 소유자 설정 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "모든 파일/디렉터리에 유효한 소유자/그룹 할당"
        )

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
        # 점검 방법: find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al {} \; 2> /dev/null 명령으로 불필요한 SUID/SGID 파일 검색
        # TODO: U-13 구현
        self._add_audit_result(
            item_u13,
            "INFO",
            "SUID, SGID 설정 파일 점검은 수동 확인이 필요합니다. 불필요한 SUID/SGID 파일 제거.",
            "수동 점검 필요",
            "불필요한 SUID/SGID 파일 제거"
        )

        # U-14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
        item_u14 = "U-14. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
        self._log_audit_item(item_u14)
        # 점검 방법: 각 계정 홈 디렉터리 내 환경변수 파일(.profile, .bashrc 등)의 소유자가 root 또는 해당 계정이고, root와 소유자만 쓰기 권한이 있는지 확인
        # TODO: U-14 구현
        self._add_audit_result(
            item_u14,
            "INFO",
            "사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "환경 파일 소유자 및 권한 적절하게 설정"
        )

        # U-15. world writable 파일 점검
        item_u15 = "U-15. world writable 파일 점검"
        self._log_audit_item(item_u15)
        # 점검 방법: find / -perm -2 -type f -exec ls -alL {} \; 명령으로 world writable 파일 검색
        # TODO: U-15 구현
        self._add_audit_result(
            item_u15,
            "INFO",
            "world writable 파일 점검은 수동 확인이 필요합니다. 불필요한 world writable 파일 제거.",
            "수동 점검 필요",
            "world writable 파일 제거"
        )

        # U-16. /dev에 존재하지 않는 device 파일 점검
        item_u16 = "U-16. /dev에 존재하지 않는 device 파일 점검"
        self._log_audit_item(item_u16)
        # 점검 방법: find /dev -type f -exec ls -l {} \; | grep -v 'major, minor number' 패턴으로 존재하지 않는 device 파일 검색
        # TODO: U-16 구현
        self._add_audit_result(
            item_u16,
            "INFO",
            "/dev에 존재하지 않는 device 파일 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "불필요한 device 파일 제거"
        )

        # U-17. $HOME/.rhosts, hosts.equiv 사용 금지
        item_u17 = "U-17. $HOME/.rhosts, hosts.equiv 사용 금지"
        self._log_audit_item(item_u17)
        # 점검 방법: /etc/hosts.equiv 및 $HOME/.rhosts 파일의 소유자/권한 확인 및 '+' 설정 확인
        # TODO: U-17 구현
        self._add_audit_result(
            item_u17,
            "INFO",
            "$HOME/.rhosts, hosts.equiv 사용 금지 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            ".rhosts, hosts.equiv 파일 제거 또는 비활성화"
        )

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
        # 점검 방법: /etc/hosts.lpd 파일의 소유자가 root이고 권한이 600 이하인지 확인
        # TODO: U-55 구현
        self._add_audit_result(
            item_u55,
            "INFO",
            "hosts.lpd 파일 소유자 및 권한 설정 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "소유자: root, 권한: 600 이하"
        )

        # U-56. UMASK 설정 관리
        item_u56 = "U-56. UMASK 설정 관리"
        self._log_audit_item(item_u56)
        # 점검 방법: /etc/profile 또는 /etc/csh.login 등 환경 파일에서 umask 값 확인 (022 이상)
        # TODO: U-56 구현
        self._add_audit_result(
            item_u56,
            "INFO",
            "UMASK 설정 관리 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "umask 022 이상 설정"
        )

        # U-57. 홈 디렉터리 소유자 및 권한 설정
        item_u57 = "U-57. 홈 디렉터리 소유자 및 권한 설정"
        self._log_audit_item(item_u57)
        # 점검 방법: 각 사용자 홈 디렉터리의 소유자가 해당 계정이고 타 사용자 쓰기 권한이 제거되었는지 확인
        # TODO: U-57 구현
        self._add_audit_result(
            item_u57,
            "INFO",
            "홈 디렉터리 소유자 및 권한 설정 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "홈 디렉터리 소유자 및 권한 적절하게 설정"
        )

        # U-58. 홈 디렉터리로 지정한 디렉터리의 존재 관리
        item_u58 = "U-58. 홈 디렉터리로 지정한 디렉터리의 존재 관리"
        self._log_audit_item(item_u58)
        # 점검 방법: /etc/passwd 파일에서 각 사용자 홈 디렉터리가 실제로 존재하는지 확인
        # TODO: U-58 구현
        self._add_audit_result(
            item_u58,
            "INFO",
            "홈 디렉터리로 지정한 디렉터리의 존재 관리 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "모든 홈 디렉터리 존재 확인"
        )

        # U-59. 숨겨진 파일 및 디렉터리 검색 및 제거
        item_u59 = "U-59. 숨겨진 파일 및 디렉터리 검색 및 제거"
        self._log_audit_item(item_u59)
        # 점검 방법: find / -type f -name ".*" 및 find / -type d -name ".*" 명령으로 숨겨진 파일/디렉터리 검색
        # TODO: U-59 구현
        self._add_audit_result(
            item_u59,
            "INFO",
            "숨겨진 파일 및 디렉터리 검색 및 제거 점검은 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "불필요한 숨겨진 파일/디렉터리 제거"
        )

        logging.info(f"{self.module_name} 점검을 완료했습니다.")
        return self.module_audit_results

