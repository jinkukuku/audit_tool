import logging
import os
from base_audit_module import BaseAuditModule
from platform_utils import PlatformUtils

class AccountManagementAudit(BaseAuditModule):
    """
    계정 관리 관련 보안 점검을 수행하는 모듈입니다.
    대상 항목: U-01 ~ U-04, U-44 ~ U-54
    """
    def __init__(self, config):
        super().__init__(config)
        self.module_name = "계정 관리"
        # 계정 관리 모듈에 필요한 특정 설정들을 config에서 추출할 수 있습니다.
        self.account_config = self.config.get('account_management', {})

    def run_audit(self):
        logging.info(f"{self.module_name} 점검을 시작합니다.")
        self.module_audit_results = [] # 점검 시작 전 결과 목록 초기화

        # U-01. root 계정 원격 접속 제한
        item_u01 = "U-01. root 계정 원격 접속 제한"
        self._log_audit_item(item_u01)
        sshd_config_paths = [
            "/etc/sshd_config",
            "/etc/ssh/sshd_config",
            "/usr/local/etc/sshd_config",
            "/usr/local/sshd/etc/sshd_config",
            "/usr/local/ssh/etc/sshd_config",
            "/etc/opt/ssh/sshd_config"
        ]
        is_root_login_allowed = False
        current_setting = "설정 없음"
        for path in sshd_config_paths:
            if PlatformUtils.check_file_exists(path):
                stdout, stderr, returncode = PlatformUtils.execute_command(['grep', 'PermitRootLogin', path])
                if returncode == 0:
                    current_setting = stdout.strip()
                    if "PermitRootLogin yes" in stdout and "#PermitRootLogin no" not in stdout:
                        is_root_login_allowed = True
                        break
                    elif "PermitRootLogin no" in stdout:
                        is_root_login_allowed = False
                        break
                elif returncode == 1 and not stdout:
                    logging.info(f"  - {path}: PermitRootLogin 설정 없음 (기본값 yes로 간주)")
                    is_root_login_allowed = True
                    current_setting = "설정 없음 (기본값 yes)"
                    break
        
        if is_root_login_allowed:
            self._add_audit_result(
                item_u01,
                "VULNERABLE",
                "SSH PermitRootLogin 설정이 'yes'이거나 설정되지 않아 root 원격 접속이 허용됩니다.",
                current_setting,
                "PermitRootLogin no"
            )
        else:
            self._add_audit_result(
                item_u01,
                "COMPLIANT",
                "root 원격 접속이 제한되어 있습니다.",
                current_setting,
                "PermitRootLogin no"
            )

        # U-02. 패스워드 복잡성 설정
        item_u02 = "U-02. 패스워드 복잡성 설정"
        self._log_audit_item(item_u02)
        pwquality_conf_path = "/etc/security/pwquality.conf"
        
        is_complex_password_set = False
        current_pw_settings = "N/A"

        if PlatformUtils.check_file_exists(pwquality_conf_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', pwquality_conf_path])
            if returncode == 0:
                current_pw_settings = stdout.strip()
                minlen_ok = False
                lcredit_ok = False
                ucredit_ok = False
                dcredit_ok = False
                ocredit_ok = False

                for line in stdout.splitlines():
                    line = line.strip()
                    if line.startswith("minlen") and int(line.split('=')[1].strip()) >= 8:
                        minlen_ok = True
                    if line.startswith("lcredit") and int(line.split('=')[1].strip()) <= -1:
                        lcredit_ok = True
                    if line.startswith("ucredit") and int(line.split('=')[1].strip()) <= -1:
                        ucredit_ok = True
                    if line.startswith("dcredit") and int(line.split('=')[1].strip()) <= -1:
                        dcredit_ok = True
                    if line.startswith("ocredit") and int(line.split('=')[1].strip()) <= -1:
                        ocredit_ok = True
                
                if minlen_ok and lcredit_ok and ucredit_ok and dcredit_ok and ocredit_ok:
                    is_complex_password_set = True
                else:
                    reason_parts = []
                    if not minlen_ok: reason_parts.append("최소 길이 (minlen) 8자리 미만")
                    if not lcredit_ok: reason_parts.append("소문자 요구 (lcredit) 미설정")
                    if not ucredit_ok: reason_parts.append("대문자 요구 (ucredit) 미설정")
                    if not dcredit_ok: reason_parts.append("숫자 요구 (dcredit) 미설정")
                    if not ocredit_ok: reason_parts.append("특수문자 요구 (ocredit) 미설정")
                    self._add_audit_result(
                        item_u02,
                        "VULNERABLE",
                        f"패스워드 복잡성 정책이 미흡합니다: {', '.join(reason_parts)}",
                        current_pw_settings,
                        "minlen=8, lcredit=-1, ucredit=-1, dcredit=-1, ocredit=-1"
                    )
            else:
                self._add_audit_result(
                    item_u02,
                    "VULNERABLE",
                    f"'{pwquality_conf_path}' 파일을 읽을 수 없습니다: {stderr}",
                    "파일 접근 불가",
                    "minlen=8, lcredit=-1, ucredit=-1, dcredit=-1, ocredit=-1"
                )
        else:
            self._add_audit_result(
                item_u02,
                "VULNERABLE",
                f"'{pwquality_conf_path}' 파일이 존재하지 않습니다.",
                "파일 없음",
                "minlen=8, lcredit=-1, ucredit=-1, dcredit=-1, ocredit=-1"
            )
        
        if is_complex_password_set:
            self._add_audit_result(
                item_u02,
                "COMPLIANT",
                "패스워드 복잡성 정책이 적절하게 설정되어 있습니다.",
                current_pw_settings,
                "minlen=8, lcredit=-1, ucredit=-1, dcredit=-1, ocredit=-1"
            )

        # U-03. 계정 잠금 임계값 설정
        item_u03 = "U-03. 계정 잠금 임계값 설정"
        self._log_audit_item(item_u03)
        pam_files = self.account_config.get('u03_pam_files', ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"])
        is_threshold_set = True
        vulnerable_reasons_u03 = []

        for pam_file in pam_files:
            if PlatformUtils.check_file_exists(pam_file):
                stdout, stderr, returncode = PlatformUtils.execute_command(['cat', pam_file])
                if returncode == 0:
                    found_deny_setting = False
                    for line in stdout.splitlines():
                        if ("pam_faillock.so" in line or "pam_tally2.so" in line) and "deny=" in line:
                            try:
                                deny_value_str = line.split("deny=")[1].split(" ")[0].strip()
                                deny_value = int(deny_value_str)
                                if deny_value <= 10:
                                    found_deny_setting = True
                                    break
                                else:
                                    vulnerable_reasons_u03.append(f"'{pam_file}'의 deny 값이 10회를 초과합니다. (현재: {deny_value})")
                                    is_threshold_set = False
                            except ValueError:
                                vulnerable_reasons_u03.append(f"'{pam_file}'에서 deny 값 파싱 오류.")
                                is_threshold_set = False
                    if not found_deny_setting and is_threshold_set: # 아직 취약으로 판단되지 않았을 때만
                        vulnerable_reasons_u03.append(f"'{pam_file}' 파일에 계정 잠금 임계값(deny)이 10회 이하로 설정되어 있지 않습니다.")
                        is_threshold_set = False
                else:
                    vulnerable_reasons_u03.append(f"'{pam_file}' 파일을 읽을 수 없습니다: {stderr}")
                    is_threshold_set = False
            else:
                vulnerable_reasons_u03.append(f"'{pam_file}' 파일이 존재하지 않습니다.")
                is_threshold_set = False
        
        if is_threshold_set:
            self._add_audit_result(
                item_u03,
                "COMPLIANT",
                "계정 잠금 임계값이 적절하게 설정되어 있습니다.",
                "설정 확인됨",
                "deny=10 이하"
            )
        else:
            self._add_audit_result(
                item_u03,
                "VULNERABLE",
                "; ".join(vulnerable_reasons_u03),
                "현재 설정값 확인 필요",
                "deny=10 이하"
            )

        # U-04. 패스워드 파일 보호
        item_u04 = "U-04. 패스워드 파일 보호"
        self._log_audit_item(item_u04)
        passwd_path = self.account_config.get('u04_passwd_file', "/etc/passwd")
        shadow_path = self.account_config.get('u04_shadow_file', "/etc/shadow")
        
        is_passwd_protected = True
        vulnerable_reasons_u04 = []
        current_passwd_info = "N/A"
        current_shadow_info = "N/A"

        if PlatformUtils.check_file_exists(passwd_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', passwd_path])
            if returncode == 0:
                current_passwd_info = stdout.strip()
                for line in stdout.splitlines():
                    parts = line.split(':')
                    if len(parts) > 1 and parts[1] != 'x':
                        is_passwd_protected = False
                        vulnerable_reasons_u04.append(f"'{passwd_path}' 파일에 암호화되지 않은 패스워드가 존재할 수 있습니다 (계정: {parts[0]}, 패스워드 필드: {parts[1]}가 'x'가 아님).")
                        break
            else:
                is_passwd_protected = False
                vulnerable_reasons_u04.append(f"'{passwd_path}' 파일을 읽을 수 없습니다: {stderr}")
        else:
            is_passwd_protected = False
            vulnerable_reasons_u04.append(f"'{passwd_path}' 파일이 존재하지 않습니다.")
        
        if PlatformUtils.check_file_exists(shadow_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', shadow_path])
            if returncode == 0:
                current_shadow_info = stdout.strip()
                if not stdout.strip():
                     is_passwd_protected = False
                     vulnerable_reasons_u04.append(f"'{shadow_path}' 파일이 비어있거나 올바르게 사용되지 않습니다.")
                # TODO: $1 (MD5) 사용 여부 등 더 정밀한 암호화 알고리즘 점검 로직 추가 가능
            else:
                is_passwd_protected = False
                vulnerable_reasons_u04.append(f"'{shadow_path}' 파일을 읽을 수 없습니다: {stderr}")
        else:
            is_passwd_protected = False
            vulnerable_reasons_u04.append(f"'{shadow_path}' 파일이 존재하지 않습니다.")
        
        if is_passwd_protected:
            self._add_audit_result(
                item_u04,
                "COMPLIANT",
                "패스워드 파일이 적절하게 보호되고 있습니다.",
                f"passwd: {current_passwd_info[:50]}..., shadow: {current_shadow_info[:50]}...",
                "shadow 패스워드 사용 및 안전한 알고리즘 적용"
            )
        else:
            self._add_audit_result(
                item_u04,
                "VULNERABLE",
                "; ".join(vulnerable_reasons_u04),
                f"passwd: {current_passwd_info[:50]}..., shadow: {current_shadow_info[:50]}...",
                "shadow 패스워드 사용 및 안전한 알고리즘 적용"
            )

        # U-44. root 이외의 UID가 '0' 금지
        item_u44 = "U-44. root 이외의 UID가 '0' 금지"
        self._log_audit_item(item_u44)
        passwd_path = self.account_config.get('u04_passwd_file', "/etc/passwd") # u04와 동일 경로 사용
        
        is_uid_0_ok = True
        uid_0_accounts = []
        current_passwd_content = "N/A"

        if PlatformUtils.check_file_exists(passwd_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', passwd_path])
            if returncode == 0:
                current_passwd_content = stdout.strip()
                for line in stdout.splitlines():
                    parts = line.split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = parts[2]
                        if uid == '0' and username != 'root':
                            uid_0_accounts.append(username)
                            is_uid_0_ok = False
                
                if not is_uid_0_ok:
                    self._add_audit_result(
                        item_u44,
                        "VULNERABLE",
                        f"root 이외의 UID 0 계정이 존재합니다: {', '.join(uid_0_accounts)}",
                        f"UID 0 계정: {', '.join(uid_0_accounts)}",
                        "root 계정만 UID 0 사용"
                    )
                else:
                    self._add_audit_result(
                        item_u44,
                        "COMPLIANT",
                        "root 계정만 UID 0을 사용하고 있습니다.",
                        "UID 0 계정 없음 (root 제외)",
                        "root 계정만 UID 0 사용"
                    )
            else:
                self._add_audit_result(
                    item_u44,
                    "VULNERABLE",
                    f"'{passwd_path}' 파일을 읽을 수 없습니다: {stderr}",
                    "파일 접근 불가",
                    "root 계정만 UID 0 사용"
                )
        else:
            self._add_audit_result(
                item_u44,
                "VULNERABLE",
                f"'{passwd_path}' 파일이 존재하지 않습니다.",
                "파일 없음",
                "root 계정만 UID 0 사용"
            )

        # U-45. root 계정 su 제한
        item_u45 = "U-45. root 계정 su 제한"
        self._log_audit_item(item_u45)
        su_pam_path = "/etc/pam.d/su"
        group_path = "/etc/group"
        is_su_restricted = False
        current_su_config = "N/A"
        current_group_config = "N/A"
        vulnerable_reasons_u45 = []

        if PlatformUtils.check_file_exists(su_pam_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', su_pam_path])
            if returncode == 0:
                current_su_config = stdout.strip()
                if "pam_wheel.so" in stdout and "group=wheel" in stdout:
                    if PlatformUtils.check_file_exists(group_path):
                        stdout_group, stderr_group, returncode_group = PlatformUtils.execute_command(['cat', group_path])
                        if returncode_group == 0:
                            current_group_config = stdout_group.strip()
                            for line in stdout_group.splitlines():
                                if line.startswith("wheel:"):
                                    parts = line.split(':')
                                    if len(parts) >= 4 and parts[3].strip(): # wheel 그룹에 구성원이 있으면
                                        is_su_restricted = True
                                        break
                            if not is_su_restricted:
                                vulnerable_reasons_u45.append("pam_wheel.so가 설정되었으나 wheel 그룹에 구성원이 없습니다.")
                        else:
                            vulnerable_reasons_u45.append(f"'{group_path}' 파일을 읽을 수 없습니다: {stderr_group}")
                    else:
                        vulnerable_reasons_u45.append(f"'{group_path}' 파일이 존재하지 않습니다.")
                else:
                    vulnerable_reasons_u45.append("pam_wheel.so 또는 group=wheel 설정이 /etc/pam.d/su 파일에 없습니다.")
            else:
                vulnerable_reasons_u45.append(f"'{su_pam_path}' 파일을 읽을 수 없습니다: {stderr}")
        else:
            vulnerable_reasons_u45.append(f"'{su_pam_path}' 파일이 존재하지 않습니다.")
        
        if is_su_restricted:
            self._add_audit_result(
                item_u45,
                "COMPLIANT",
                "su 명령어가 특정 그룹으로 제한되어 있습니다.",
                f"su_pam: {current_su_config[:50]}..., group: {current_group_config[:50]}...",
                "pam_wheel.so 설정 및 wheel 그룹 구성원 제한"
            )
        else:
            self._add_audit_result(
                item_u45,
                "VULNERABLE",
                "; ".join(vulnerable_reasons_u45),
                f"su_pam: {current_su_config[:50]}..., group: {current_group_config[:50]}...",
                "pam_wheel.so 설정 및 wheel 그룹 구성원 제한"
            )

        # U-46. 패스워드 최소 길이 설정
        item_u46 = "U-46. 패스워드 최소 길이 설정"
        self._log_audit_item(item_u46)
        login_defs_path = "/etc/login.defs"
        system_auth_path = "/etc/pam.d/system-auth"
        min_len_ok = False
        current_min_len_info = "N/A"
        vulnerable_reasons_u46 = []

        if PlatformUtils.check_file_exists(login_defs_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['grep', 'PASS_MIN_LEN', login_defs_path])
            if returncode == 0 and "PASS_MIN_LEN" in stdout:
                current_min_len_info += f"login.defs: {stdout.strip()}; "
                try:
                    min_len_val = int(stdout.split("PASS_MIN_LEN")[1].strip().split()[0])
                    if min_len_val >= 8:
                        min_len_ok = True
                except ValueError:
                    vulnerable_reasons_u46.append(f"'{login_defs_path}'에서 PASS_MIN_LEN 값 파싱 오류.")
            else:
                vulnerable_reasons_u46.append(f"'{login_defs_path}'에 PASS_MIN_LEN 설정이 없거나 읽을 수 없습니다.")
        else:
            vulnerable_reasons_u46.append(f"'{login_defs_path}' 파일이 존재하지 않습니다.")
        
        if PlatformUtils.check_file_exists(system_auth_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['grep', 'pam_cracklib.so', system_auth_path])
            if returncode == 0 and "minlen=" in stdout:
                current_min_len_info += f"system-auth: {stdout.strip()}"
                try:
                    min_len_val = int(stdout.split("minlen=")[1].split(" ")[0].strip())
                    if min_len_val >= 8:
                        min_len_ok = True # PAM 설정이 우선하므로 여기서 만족하면 OK
                except ValueError:
                    vulnerable_reasons_u46.append(f"'{system_auth_path}'에서 pam_cracklib.so minlen 값 파싱 오류.")
            else:
                vulnerable_reasons_u46.append(f"'{system_auth_path}'에 pam_cracklib.so minlen 설정이 없거나 읽을 수 없습니다.")
        else:
            vulnerable_reasons_u46.append(f"'{system_auth_path}' 파일이 존재하지 않습니다.")

        if min_len_ok:
            self._add_audit_result(
                item_u46,
                "COMPLIANT",
                "패스워드 최소 길이가 8자리 이상으로 설정되어 있습니다.",
                current_min_len_info,
                "8자리 이상"
            )
        else:
            self._add_audit_result(
                item_u46,
                "VULNERABLE",
                "패스워드 최소 길이가 8자리 미만으로 설정되어 있거나 설정이 미흡합니다: " + "; ".join(vulnerable_reasons_u46),
                current_min_len_info,
                "8자리 이상"
            )
            
        # U-47. 패스워드 최대 사용기간 설정
        item_u47 = "U-47. 패스워드 최대 사용기간 설정"
        self._log_audit_item(item_u47)
        max_days_ok = True
        login_defs_path = "/etc/login.defs"
        current_max_days_info = "N/A"
        vulnerable_reasons_u47 = []

        if PlatformUtils.check_file_exists(login_defs_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['grep', 'PASS_MAX_DAYS', login_defs_path])
            if returncode == 0 and "PASS_MAX_DAYS" in stdout:
                current_max_days_info = stdout.strip()
                try:
                    max_days_val = int(stdout.split("PASS_MAX_DAYS")[1].strip().split()[0])
                    if max_days_val > 90:
                        max_days_ok = False
                        vulnerable_reasons_u47.append(f"PASS_MAX_DAYS가 90일을 초과합니다. (현재: {max_days_val}일)")
                except ValueError:
                    max_days_ok = False
                    vulnerable_reasons_u47.append(f"'{login_defs_path}'에서 PASS_MAX_DAYS 값 파싱 오류.")
            else:
                max_days_ok = False
                vulnerable_reasons_u47.append(f"'{login_defs_path}'에 PASS_MAX_DAYS 설정이 없거나 읽을 수 없습니다.")
        else:
            max_days_ok = False
            vulnerable_reasons_u47.append(f"'{login_defs_path}' 파일이 존재하지 않습니다.")

        if max_days_ok:
            self._add_audit_result(
                item_u47,
                "COMPLIANT",
                "패스워드 최대 사용기간이 90일 이하로 설정되어 있습니다.",
                current_max_days_info,
                "90일 이하"
            )
        else:
            self._add_audit_result(
                item_u47,
                "VULNERABLE",
                "패스워드 최대 사용기간이 90일을 초과하여 설정되어 있거나 설정이 미흡합니다: " + "; ".join(vulnerable_reasons_u47),
                current_max_days_info,
                "90일 이하"
            )

        # U-48. 패스워드 최소 사용기간 설정
        item_u48 = "U-48. 패스워드 최소 사용기간 설정"
        self._log_audit_item(item_u48)
        min_days_ok = True
        login_defs_path = "/etc/login.defs"
        current_min_days_info = "N/A"
        vulnerable_reasons_u48 = []

        if PlatformUtils.check_file_exists(login_defs_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['grep', 'PASS_MIN_DAYS', login_defs_path])
            if returncode == 0 and "PASS_MIN_DAYS" in stdout:
                current_min_days_info = stdout.strip()
                try:
                    min_days_val = int(stdout.split("PASS_MIN_DAYS")[1].strip().split()[0])
                    if min_days_val < 1:
                        min_days_ok = False
                        vulnerable_reasons_u48.append(f"PASS_MIN_DAYS가 1일 미만입니다. (현재: {min_days_val}일)")
                except ValueError:
                    min_days_ok = False
                    vulnerable_reasons_u48.append(f"'{login_defs_path}'에서 PASS_MIN_DAYS 값 파싱 오류.")
            else:
                min_days_ok = False
                vulnerable_reasons_u48.append(f"'{login_defs_path}'에 PASS_MIN_DAYS 설정이 없거나 읽을 수 없습니다.")
        else:
            min_days_ok = False
            vulnerable_reasons_u48.append(f"'{login_defs_path}' 파일이 존재하지 않습니다.")

        if min_days_ok:
            self._add_audit_result(
                item_u48,
                "COMPLIANT",
                "패스워드 최소 사용기간이 1일 이상으로 설정되어 있습니다.",
                current_min_days_info,
                "1일 이상"
            )
        else:
            self._add_audit_result(
                item_u48,
                "VULNERABLE",
                "패스워드 최소 사용기간이 1일 미만으로 설정되어 있거나 설정이 미흡합니다: " + "; ".join(vulnerable_reasons_u48),
                current_min_days_info,
                "1일 이상"
            )

        # U-49. 불필요한 계정 제거
        item_u49 = "U-49. 불필요한 계정 제거"
        self._log_audit_item(item_u49)
        unnecessary_accounts = self.account_config.get('u49_unnecessary_accounts', ["lp", "uucp", "operator", "games", "gopher", "nscd", "nobody"])
        passwd_path = self.account_config.get('u04_passwd_file', "/etc/passwd")
        found_unnecessary = []
        current_passwd_content = "N/A"

        if PlatformUtils.check_file_exists(passwd_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', passwd_path])
            if returncode == 0:
                current_passwd_content = stdout.strip()
                for line in stdout.splitlines():
                    username = line.split(':')[0]
                    if username in unnecessary_accounts:
                        found_unnecessary.append(username)
            else:
                self._add_audit_result(
                    item_u49,
                    "VULNERABLE",
                    f"'{passwd_path}' 파일을 읽을 수 없습니다: {stderr}",
                    "파일 접근 불가",
                    "불필요한 계정 제거 또는 쉘 제한"
                )
        else:
            self._add_audit_result(
                item_u49,
                "VULNERABLE",
                f"'{passwd_path}' 파일이 존재하지 않습니다.",
                "파일 없음",
                "불필요한 계정 제거 또는 쉘 제한"
            )

        if found_unnecessary:
            self._add_audit_result(
                item_u49,
                "VULNERABLE",
                f"불필요하거나 기본적으로 생성되는 계정이 존재합니다: {', '.join(found_unnecessary)}",
                f"발견된 계정: {', '.join(found_unnecessary)}",
                "불필요한 계정 제거 또는 쉘 제한"
            )
        elif PlatformUtils.check_file_exists(passwd_path) and returncode == 0: # 파일 읽기 성공 시에만 양호
            self._add_audit_result(
                item_u49,
                "COMPLIANT",
                "불필요한 계정이 존재하지 않습니다.",
                "불필요한 계정 없음",
                "불필요한 계정 제거 또는 쉘 제한"
            )

        # U-50. 관리자 그룹에 최소한의 계정 포함
        item_u50 = "U-50. 관리자 그룹에 최소한의 계정 포함"
        self._log_audit_item(item_u50)
        group_path = "/etc/group"
        is_admin_group_ok = True
        current_group_content = "N/A"
        vulnerable_reasons_u50 = []

        if PlatformUtils.check_file_exists(group_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', group_path])
            if returncode == 0:
                current_group_content = stdout.strip()
                for line in stdout.splitlines():
                    if line.startswith("root:"):
                        parts = line.split(':')
                        if len(parts) == 4:
                            members = [m.strip() for m in parts[3].split(',') if m.strip()]
                            if 'root' not in members or len(members) > 1:
                                is_admin_group_ok = False
                                vulnerable_reasons_u50.append(f"root 그룹에 root 외의 계정이 포함되어 있거나 root 계정이 없습니다: {parts[3]}")
                                break
                        break # root 그룹 라인만 확인
                if not is_admin_group_ok:
                    self._add_audit_result(
                        item_u50,
                        "VULNERABLE",
                        "; ".join(vulnerable_reasons_u50),
                        current_group_content,
                        "root 그룹에 root 계정만 포함"
                    )
                else:
                    self._add_audit_result(
                        item_u50,
                        "COMPLIANT",
                        "관리자 그룹에 최소한의 계정만 포함되어 있습니다.",
                        current_group_content,
                        "root 그룹에 root 계정만 포함"
                    )
            else:
                self._add_audit_result(
                    item_u50,
                    "VULNERABLE",
                    f"'{group_path}' 파일을 읽을 수 없습니다: {stderr}",
                    "파일 접근 불가",
                    "root 그룹에 root 계정만 포함"
                )
        else:
            self._add_audit_result(
                item_u50,
                "VULNERABLE",
                f"'{group_path}' 파일이 존재하지 않습니다.",
                "파일 없음",
                "root 그룹에 root 계정만 포함"
            )

        # U-51. 계정이 존재하지 않는 GID 금지
        item_u51 = "U-51. 계정이 존재하지 않는 GID 금지"
        self._log_audit_item(item_u51)
        # 이 점검은 GID와 UID 매핑을 모두 확인해야 하므로 복잡합니다.
        self._add_audit_result(
            item_u51,
            "INFO", # INFO 상태로 변경하여 수동 점검 필요 알림
            "계정이 존재하지 않는 GID 금지 점검은 복잡하여 수동 확인이 필요합니다.",
            "수동 점검 필요",
            "모든 GID에 유효한 계정 매핑"
        )


        # U-52. 동일한 UID 금지
        item_u52 = "U-52. 동일한 UID 금지"
        self._log_audit_item(item_u52)
        passwd_path = self.account_config.get('u04_passwd_file', "/etc/passwd")
        is_duplicate_uid = False
        uid_map = {} # {uid: [username1, username2]}
        current_passwd_content = "N/A"
        vulnerable_uids = []

        if PlatformUtils.check_file_exists(passwd_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', passwd_path])
            if returncode == 0:
                current_passwd_content = stdout.strip()
                for line in stdout.splitlines():
                    parts = line.split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        uid = parts[2]
                        if uid == '0' and username == 'root':
                            continue
                        
                        if uid in uid_map:
                            uid_map[uid].append(username)
                            is_duplicate_uid = True
                        else:
                            uid_map[uid] = [username]
                
                if is_duplicate_uid:
                    for uid, users in uid_map.items():
                        if len(users) > 1:
                            vulnerable_uids.append(f"UID {uid}: {', '.join(users)}")
                    self._add_audit_result(
                        item_u52,
                        "VULNERABLE",
                        f"동일한 UID를 사용하는 계정이 존재합니다: {'; '.join(vulnerable_uids)}",
                        current_passwd_content,
                        "각 계정별 고유 UID 할당"
                    )
                else:
                    self._add_audit_result(
                        item_u52,
                        "COMPLIANT",
                        "동일한 UID를 사용하는 계정이 존재하지 않습니다.",
                        current_passwd_content,
                        "각 계정별 고유 UID 할당"
                    )
            else:
                self._add_audit_result(
                    item_u52,
                    "VULNERABLE",
                    f"'{passwd_path}' 파일을 읽을 수 없습니다: {stderr}",
                    "파일 접근 불가",
                    "각 계정별 고유 UID 할당"
                )
        else:
            self._add_audit_result(
                item_u52,
                "VULNERABLE",
                f"'{passwd_path}' 파일이 존재하지 않습니다.",
                "파일 없음",
                "각 계정별 고유 UID 할당"
            )

        # U-53. 사용자 shell 점검
        item_u53 = "U-53. 사용자 shell 점검"
        self._log_audit_item(item_u53)
        passwd_path = self.account_config.get('u04_passwd_file', "/etc/passwd")
        unnecessary_shells = ["/bin/false", "/sbin/nologin"]
        system_accounts_to_check = self.account_config.get('u53_system_accounts_to_check_shell', ["daemon", "bin", "sys", "adm", "lp", "uucp", "operator", "games", "gopher", "nscd", "nobody"])

        is_shell_ok = True
        vulnerable_shells = []
        current_passwd_content = "N/A"

        if PlatformUtils.check_file_exists(passwd_path):
            stdout, stderr, returncode = PlatformUtils.execute_command(['cat', passwd_path])
            if returncode == 0:
                current_passwd_content = stdout.strip()
                for line in stdout.splitlines():
                    parts = line.split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        shell = parts[6]
                        if username in system_accounts_to_check and shell not in unnecessary_shells:
                            vulnerable_shells.append(f"{username}:{shell}")
                            is_shell_ok = False
                
                if not is_shell_ok:
                    self._add_audit_result(
                        item_u53,
                        "VULNERABLE",
                        f"로그인이 불필요한 계정에 제한된 쉘이 부여되지 않았습니다: {', '.join(vulnerable_shells)}",
                        current_passwd_content,
                        "/bin/false 또는 /sbin/nologin 쉘 부여"
                    )
                else:
                    self._add_audit_result(
                        item_u53,
                        "COMPLIANT",
                        "로그인이 불필요한 계정에 제한된 쉘이 부여되어 있습니다.",
                        current_passwd_content,
                        "/bin/false 또는 /sbin/nologin 쉘 부여"
                    )
            else:
                self._add_audit_result(
                    item_u53,
                    "VULNERABLE",
                    f"'{passwd_path}' 파일을 읽을 수 없습니다: {stderr}",
                    "파일 접근 불가",
                    "/bin/false 또는 /sbin/nologin 쉘 부여"
                )
        else:
            self._add_audit_result(
                item_u53,
                "VULNERABLE",
                f"'{passwd_path}' 파일이 존재하지 않습니다.",
                "파일 없음",
                "/bin/false 또는 /sbin/nologin 쉘 부여"
            )

        # U-54. Session Timeout 설정
        item_u54 = "U-54. Session Timeout 설정"
        self._log_audit_item(item_u54)
        env_files = ["/etc/profile", "/etc/csh.login", "/etc/csh.cshrc"] # TODO: config에서 가져오도록 변경
        session_timeout_ok = False
        current_timeout_info = "N/A"
        vulnerable_reasons_u54 = []
        
        for env_file in env_files:
            if PlatformUtils.check_file_exists(env_file):
                stdout, stderr, returncode = PlatformUtils.execute_command(['cat', env_file])
                if returncode == 0:
                    current_timeout_info += f"{env_file}: {stdout.strip()[:50]}...; "
                    for line in stdout.splitlines():
                        line = line.strip()
                        if line.startswith("TMOUT=") and "export TMOUT" in stdout:
                            try:
                                timeout_val = int(line.split('=')[1].strip())
                                if timeout_val <= 600 and timeout_val > 0:
                                    session_timeout_ok = True
                                    break
                            except ValueError:
                                vulnerable_reasons_u54.append(f"'{env_file}'에서 TMOUT 값 파싱 오류.")
                        elif line.startswith("set autologout="):
                            try:
                                timeout_val = int(line.split('=')[1].strip())
                                if timeout_val <= 10 and timeout_val > 0:
                                    session_timeout_ok = True
                                    break
                            except ValueError:
                                vulnerable_reasons_u54.append(f"'{env_file}'에서 autologout 값 파싱 오류.")
                    if session_timeout_ok:
                        break
                else:
                    vulnerable_reasons_u54.append(f"'{env_file}' 파일을 읽을 수 없습니다: {stderr}")
            else:
                vulnerable_reasons_u54.append(f"'{env_file}' 파일이 존재하지 않습니다.")

        if session_timeout_ok:
            self._add_audit_result(
                item_u54,
                "COMPLIANT",
                "Session Timeout이 600초(10분) 이하로 적절하게 설정되어 있습니다.",
                current_timeout_info,
                "TMOUT=600 또는 set autologout=10"
            )
        else:
            self._add_audit_result(
                item_u54,
                "VULNERABLE",
                "Session Timeout이 600초(10분) 이하로 설정되어 있지 않거나 설정이 미흡합니다: " + "; ".join(vulnerable_reasons_u54),
                current_timeout_info,
                "TMOUT=600 또는 set autologout=10"
            )

        logging.info(f"{self.module_name} 점검을 완료했습니다.")
        return self.module_audit_results

