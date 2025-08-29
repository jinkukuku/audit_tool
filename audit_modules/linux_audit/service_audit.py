import logging
import os
import pwd
import re
from base_audit_module import BaseAuditModule
from platform_utils import PlatformUtils

class ServiceManagementAudit(BaseAuditModule):
    """
    서비스 관리 관련 보안 점검을 수행하는 모듈입니다.
    대상 항목: U-19 ~ U-41, U-60 ~ U-71
    """
    def __init__(self, config):
        super().__init__(config)
        self.module_name = "서비스 관리"
        self.service_config = self.config.get('service_management', {})

    def run_audit(self):
        logging.info(f"{self.module_name} 점검을 시작합니다.")
        self.module_audit_results = [] # 점검 시작 전 결과 목록 초기화

        # U-19. Finger 서비스 비활성화
        item_u19 = "U-19. Finger 서비스 비활성화"
        self._log_audit_item(item_u19)
        is_finger_active = False
        finger_files = ['/etc/inetd.conf', '/etc/xinetd.d/finger']
        for filepath in finger_files:
            if PlatformUtils.check_file_exists(filepath):
                content = PlatformUtils.read_file_content(filepath)
                if content and 'finger' in content and 'disable = yes' not in content:
                    is_finger_active = True
                    break

        if is_finger_active:
            status = "취약"
            details = "Finger 서비스가 활성화되어 있을 수 있습니다."
            action = "Finger 서비스 비활성화"
        else:
            status = "양호"
            details = "Finger 서비스가 비활성화되어 있거나 관련 파일이 존재하지 않습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u19, status, details, "자동 점검", action)

        # U-20. Anonymous FTP 비활성화
        item_u20 = "U-20. Anonymous FTP 비활성화"
        self._log_audit_item(item_u20)
        is_anonymous_ftp_active = False
        
        # 1. ftp 계정 확인
        try:
            pwd.getpwnam('ftp')
            is_anonymous_ftp_active = True
            details = "ftp 계정이 존재합니다."
        except KeyError:
            pass

        # 2. vsftpd.conf 파일 확인
        vsftpd_conf_path = '/etc/vsftpd.conf'
        if not is_anonymous_ftp_active and PlatformUtils.check_file_exists(vsftpd_conf_path):
            content = PlatformUtils.read_file_content(vsftpd_conf_path)
            if content and 'anonymous_enable=YES' in content:
                is_anonymous_ftp_active = True
                details = "vsftpd.conf 파일에서 익명 FTP가 활성화되어 있습니다."
        
        if is_anonymous_ftp_active:
            status = "취약"
            action = "ftp 계정 제거 및 Anonymous FTP 비활성화"
        else:
            status = "양호"
            details = "Anonymous FTP가 비활성화되어 있습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u20, status, details, "자동 점검", action)

        # U-21. r 계열 서비스 비활성화 (rsh, rlogin, rexec, talk, ntalk)
        item_u21 = "U-21. r 계열 서비스 비활성화"
        self._log_audit_item(item_u21)
        vulnerable_services = []
        services_to_check = ['rsh', 'rlogin', 'rexec', 'talk', 'ntalk']
        for service in services_to_check:
            is_secure, _ = self._check_xinetd_service(service)
            if not is_secure:
                vulnerable_services.append(service)
        
        if vulnerable_services:
            status = "취약"
            details = f"다음 r계열 서비스가 활성화되어 있을 수 있습니다: {', '.join(vulnerable_services)}"
            action = "r계열 서비스 비활성화"
        else:
            status = "양호"
            details = "r계열 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u21, status, details, "자동 점검", action)

        # U-22. cron 파일 소유자 및 권한 설정
        item_u22 = "U-22. cron 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u22)
        cron_files = ['/etc/crontab']
        for root, _, files in os.walk('/etc/cron.d'):
            for name in files:
                cron_files.append(os.path.join(root, name))
        
        vulnerable_files = []
        for filepath in cron_files:
            is_safe, details = PlatformUtils.is_file_owned_by_root_and_permission_safe(filepath, 640)
            if not is_safe:
                vulnerable_files.append(f"{filepath}: {details}")

        if vulnerable_files:
            status = "취약"
            details = "다음 파일의 소유자 또는 권한 설정이 취약합니다:\n" + "\n".join(vulnerable_files)
            action = "cron 관련 파일 소유자를 root로, 권한을 640 이하로 설정"
        else:
            status = "양호"
            details = "cron 관련 파일의 소유자 및 권한이 적절하게 설정되었습니다."
            action = "적절한 소유자 및 권한 설정 유지"
        self._add_audit_result(item_u22, status, details, "자동 점검", action)

        # U-23. DoS 공격에 취약한 서비스 비활성화
        item_u23 = "U-23. DoS 공격에 취약한 서비스 비활성화"
        self._log_audit_item(item_u23)
        vulnerable_services = []
        services_to_check = ['echo', 'discard', 'daytime', 'chargen']
        for service in services_to_check:
            is_secure, _ = self._check_xinetd_service(service)
            if not is_secure:
                vulnerable_services.append(service)

        if vulnerable_services:
            status = "취약"
            details = f"다음 DoS 공격에 취약한 서비스가 활성화되어 있을 수 있습니다: {', '.join(vulnerable_services)}"
            action = "취약한 서비스 비활성화"
        else:
            status = "양호"
            details = "DoS 공격에 취약한 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u23, status, details, "자동 점검", action)

        # U-24. NFS 서비스 비활성화
        item_u24 = "U-24. NFS 서비스 비활성화"
        self._log_audit_item(item_u24)
        nfs_services = ['nfs', 'nfs-server', 'nfsd', 'nfsserver', 'rpcbind']
        is_nfs_running = False
        for service in nfs_services:
            if PlatformUtils.is_service_active(service):
                is_nfs_running = True
                break

        if is_nfs_running:
            status = "취약"
            details = "NFS 서비스가 활성화되어 있습니다."
            action = "NFS 서비스 비활성화"
        else:
            status = "양호"
            details = "NFS 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u24, status, details, "자동 점검", action)

        # U-25. NFS 접근통제
        item_u25 = "U-25. NFS 접근통제"
        self._log_audit_item(item_u25)
        exports_path = '/etc/exports'
        is_secure = True
        details = ""
        if PlatformUtils.check_file_exists(exports_path):
            content = PlatformUtils.read_file_content(exports_path)
            if content and re.search(r'^\s*[\w\/]+\s*(\*|[\d\.]+)\(.*\)', content, re.MULTILINE):
                is_secure = False
                details = f"{exports_path} 파일에 '*'(와일드카드) 접근 허용 설정이 발견되었습니다."
        else:
            details = f"{exports_path} 파일이 존재하지 않아 점검할 수 없습니다. NFS가 비활성화된 경우 양호합니다."

        status = "양호" if is_secure else "취약"
        action = "NFS 접근 제어를 강화" if not is_secure else "적절한 접근 제어 유지"
        self._add_audit_result(item_u25, status, details, "자동 점검", action)

        # U-26. automountd 제거
        item_u26 = "U-26. automountd 제거"
        self._log_audit_item(item_u26)
        is_autofs_running = PlatformUtils.is_service_active('autofs')
        if is_autofs_running:
            status = "취약"
            details = "automountd(autofs) 서비스가 활성화되어 있습니다."
            action = "automountd(autofs) 서비스 비활성화"
        else:
            status = "양호"
            details = "automountd(autofs) 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u26, status, details, "자동 점검", action)

        # U-27. RPC 서비스 확인
        item_u27 = "U-27. RPC 서비스 확인"
        self._log_audit_item(item_u27)
        stdout, _, returncode = PlatformUtils.execute_command(['rpcinfo', '-p'])
        if returncode == 0 and "rpcbind" in stdout.lower() and len(stdout.splitlines()) > 1:
            status = "취약"
            details = "RPC 서비스가 활성화되어 있습니다."
            action = "불필요한 RPC 서비스 비활성화"
        else:
            status = "양호"
            details = "불필요한 RPC 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u27, status, details, "자동 점검", action)

        # U-28. NIS, NIS+ 점검
        item_u28 = "U-28. NIS, NIS+ 점검"
        self._log_audit_item(item_u28)
        if PlatformUtils.is_service_active('ypserv') or PlatformUtils.is_service_active('ypbind'):
            status = "취약"
            details = "NIS/NIS+ 서비스(ypserv 또는 ypbind)가 활성화되어 있습니다."
            action = "NIS/NIS+ 서비스 비활성화"
        else:
            status = "양호"
            details = "NIS/NIS+ 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u28, status, details, "자동 점검", action)

        # U-29. tftp, talk 서비스 비활성화
        item_u29 = "U-29. tftp, talk 서비스 비활성화"
        self._log_audit_item(item_u29)
        vulnerable_services = []
        services_to_check = ['tftp', 'talk']
        for service in services_to_check:
            is_secure, _ = self._check_xinetd_service(service)
            if not is_secure:
                vulnerable_services.append(service)

        if vulnerable_services:
            status = "취약"
            details = f"다음 서비스가 활성화되어 있을 수 있습니다: {', '.join(vulnerable_services)}"
            action = "불필요한 서비스 비활성화"
        else:
            status = "양호"
            details = "tftp, talk 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u29, status, details, "자동 점검", action)

        # U-30. Sendmail 버전 점검
        item_u30 = "U-30. Sendmail 버전 점검"
        self._log_audit_item(item_u30)
        stdout, _, _ = PlatformUtils.execute_command(['/usr/sbin/sendmail', '-d0.1', '-bt', '<', '/dev/null'])
        if stdout and "version" in stdout.lower():
            status = "취약"
            details = f"Sendmail 버전이 노출됩니다. 버전 정보: {stdout.strip()}"
            action = "최신 버전으로 패치 또는 서비스 정보 숨김"
        else:
            status = "양호"
            details = "Sendmail 버전 정보 노출 취약점이 발견되지 않았습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u30, status, details, "자동 점검", action)

        # U-31. 스팸 메일 릴레이 제한
        item_u31 = "U-31. 스팸 메일 릴레이 제한"
        self._log_audit_item(item_u31)
        sendmail_conf = '/etc/mail/sendmail.cf'
        if PlatformUtils.check_file_exists(sendmail_conf):
            content = PlatformUtils.read_file_content(sendmail_conf)
            if content and re.search(r'O\s*DaemonPortOptions=.*Family=inet.*Name=MTA_RELAY.*', content) and not re.search(r'O\s*DaemonPortOptions=.*Name=MTA_RELAY.*MTA_RELAY\s*Auth\s*', content):
                status = "취약"
                details = f"{sendmail_conf} 파일에서 스팸 메일 릴레이 제한 설정이 미흡합니다."
                action = "sendmail.cf 파일에서 릴레이 제한 설정"
            else:
                status = "양호"
                details = f"{sendmail_conf} 파일에서 스팸 메일 릴레이 제한 설정이 적절합니다."
                action = "적절한 설정 유지"
        else:
            status = "정보 없음"
            details = f"{sendmail_conf} 파일이 존재하지 않아 점검할 수 없습니다."
            action = "수동 점검 필요"
        self._add_audit_result(item_u31, status, details, "자동 점검", action)

        # U-32. 일반 사용자의 Sendmail 실행 방지
        item_u32 = "U-32. 일반 사용자의 Sendmail 실행 방지"
        self._log_audit_item(item_u32)
        sendmail_bin = '/usr/sbin/sendmail'
        is_safe, details = PlatformUtils.is_file_owned_by_root_and_permission_safe(sendmail_bin, 655)
        status = "양호" if is_safe else "취약"
        action = "Sendmail 실행 파일 권한 강화" if not is_safe else "적절한 권한 유지"
        self._add_audit_result(item_u32, status, details, "자동 점검", action)

        # U-33. DNS 보안 버전 패치
        item_u33 = "U-33. DNS 보안 버전 패치"
        self._log_audit_item(item_u33)
        stdout, _, _ = PlatformUtils.execute_command(['named', '-v'])
        if stdout and "version" in stdout.lower():
            status = "취약"
            details = f"DNS 버전이 노출됩니다. 버전 정보: {stdout.strip()}"
            action = "DNS 서버 최신 버전으로 패치"
        else:
            status = "양호"
            details = "DNS 버전 정보 노출 취약점이 발견되지 않았습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u33, status, details, "자동 점검", action)
        
        # U-34. DNS Zone Transfer 설정
        item_u34 = "U-34. DNS Zone Transfer 설정"
        self._log_audit_item(item_u34)
        named_conf = '/etc/named.conf'
        is_secure = True
        details = ""
        if PlatformUtils.check_file_exists(named_conf):
            content = PlatformUtils.read_file_content(named_conf)
            if content and re.search(r'allow-transfer\s*\{\s*any;\s*\};', content, re.IGNORECASE):
                is_secure = False
                details = f"{named_conf} 파일에 'allow-transfer {{any;}};' 설정이 발견되었습니다."
        else:
            is_secure = False
            details = f"{named_conf} 파일이 존재하지 않거나 Zone Transfer 설정 점검이 불가능합니다."

        status = "양호" if is_secure else "취약"
        action = "Zone Transfer 허용 범위를 제한" if not is_secure else "적절한 Zone Transfer 설정 유지"
        self._add_audit_result(item_u34, status, details, "자동 점검", action)

        # U-35. 웹서비스 디렉터리 리스팅 제거
        item_u35 = "U-35. 웹서비스 디렉터리 리스팅 제거"
        self._log_audit_item(item_u35)
        is_vulnerable = False
        details_list = []
        for conf_file in self.apache_conf_files:
            content = PlatformUtils.read_file_content(conf_file)
            if content and re.search(r'Options\s*([-+])?Indexes', content):
                is_vulnerable = True
                details_list.append(f"{conf_file} 파일에 'Options Indexes' 설정이 발견되었습니다.")
        
        if is_vulnerable:
            status = "취약"
            details = "\n".join(details_list)
            action = "Apache 설정 파일에서 'Options Indexes' 제거"
        else:
            status = "양호"
            details = "Apache 설정 파일에서 디렉터리 리스팅이 활성화되지 않았습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u35, status, details, "자동 점검", action)

        # U-36. 웹서비스 웹 프로세스 권한 제한
        item_u36 = "U-36. 웹서비스 웹 프로세스 권한 제한"
        self._log_audit_item(item_u36)
        is_secure = True
        details_list = []
        for conf_file in self.apache_conf_files:
            content = PlatformUtils.read_file_content(conf_file)
            if content and (re.search(r'^\s*User\s+root', content, re.MULTILINE) or re.search(r'^\s*Group\s+root', content, re.MULTILINE)):
                is_secure = False
                details_list.append(f"{conf_file} 파일에 'User' 또는 'Group'이 root로 설정되었습니다.")
        
        if not is_secure:
            status = "취약"
            details = "\n".join(details_list)
            action = "Apache 프로세스를 일반 사용자 계정으로 실행하도록 설정"
        else:
            status = "양호"
            details = "Apache 웹 프로세스가 root가 아닌 일반 사용자 계정으로 실행됩니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u36, status, details, "자동 점검", action)

        # U-37. 웹서비스 상위 디렉터리 접근 금지
        item_u37 = "U-37. 웹서비스 상위 디렉터리 접근 금지"
        self._log_audit_item(item_u37)
        is_vulnerable = False
        details_list = []
        for conf_file in self.apache_conf_files:
            content = PlatformUtils.read_file_content(conf_file)
            if content and re.search(r'Options\s*FollowSymLinks', content):
                is_vulnerable = True
                details_list.append(f"{conf_file} 파일에 'Options FollowSymLinks' 설정이 발견되었습니다.")
        
        if is_vulnerable:
            status = "취약"
            details = "\n".join(details_list)
            action = "Apache 설정 파일에서 'FollowSymLinks'를 'SymLinksIfOwnerMatch'로 변경"
        else:
            status = "양호"
            details = "Apache 설정 파일에 상위 디렉터리 접근 허용 설정이 없습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u37, status, details, "자동 점검", action)

        # U-38. 웹서비스 불필요한 파일 제거
        item_u38 = "U-38. 웹서비스 불필요한 파일 제거"
        self._log_audit_item(item_u38)
        # 이 항목은 자동화하기 어렵습니다.
        self._add_audit_result(item_u38, "INFO", "웹서비스 불필요한 파일 제거 점검은 수동 확인이 필요합니다.", "수동 점검 필요", "불필요한 파일 (예: 테스트용 페이지, 백업 파일) 제거")

        # U-39. 웹서비스 링크 사용 금지
        item_u39 = "U-39. 웹서비스 링크 사용 금지"
        self._log_audit_item(item_u39)
        # U-37과 유사한 점검이므로 동일하게 처리
        is_vulnerable = False
        details_list = []
        for conf_file in self.apache_conf_files:
            content = PlatformUtils.read_file_content(conf_file)
            if content and re.search(r'Options\s*FollowSymLinks', content):
                is_vulnerable = True
                details_list.append(f"{conf_file} 파일에 'Options FollowSymLinks' 설정이 발견되었습니다.")
        
        if is_vulnerable:
            status = "취약"
            details = "\n".join(details_list)
            action = "Apache 설정 파일에서 'FollowSymLinks'를 'SymLinksIfOwnerMatch'로 변경"
        else:
            status = "양호"
            details = "Apache 설정 파일에 링크 사용 허용 설정이 없습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u39, status, details, "자동 점검", action)

        # U-40. 웹서비스 파일 업로드 및 다운로드 제한
        item_u40 = "U-40. 웹서비스 파일 업로드 및 다운로드 제한"
        self._log_audit_item(item_u40)
        # 이 항목은 자동화하기 어렵습니다.
        self._add_audit_result(item_u40, "INFO", "웹서비스 파일 업로드 및 다운로드 제한 점검은 수동 확인이 필요합니다.", "수동 점검 필요", "파일 업로드/다운로드 경로에 대한 실행 권한 제한")

        # U-41. 웹 서비스 영역의 분리
        item_u41 = "U-41. 웹 서비스 영역의 분리"
        self._log_audit_item(item_u41)
        is_vulnerable = False
        details_list = []
        for conf_file in self.apache_conf_files:
            content = PlatformUtils.read_file_content(conf_file)
            if content and re.search(r'DocumentRoot\s+\/\s*$', content, re.MULTILINE):
                is_vulnerable = True
                details_list.append(f"{conf_file} 파일의 DocumentRoot가 '/'로 설정되었습니다.")
        
        if is_vulnerable:
            status = "취약"
            details = "\n".join(details_list)
            action = "DocumentRoot를 OS의 루트 디렉터리가 아닌 별도의 디렉터리로 설정"
        else:
            status = "양호"
            details = "웹 서비스 영역이 OS 영역과 분리되었습니다."
            action = "적절한 설정 유지"
        self._add_audit_result(item_u41, status, details, "자동 점검", action)

        # U-60. ssh 원격접속 허용
        item_u60 = "U-60. ssh 원격접속 허용"
        self._log_audit_item(item_u60)
        sshd_conf = '/etc/ssh/sshd_config'
        is_vulnerable = False
        details = ""
        if PlatformUtils.check_file_exists(sshd_conf):
            content = PlatformUtils.read_file_content(sshd_conf)
            if content and re.search(r'^\s*PermitRootLogin\s+yes', content, re.IGNORECASE):
                is_vulnerable = True
                details = f"{sshd_conf} 파일에 'PermitRootLogin yes' 설정이 발견되었습니다."
        else:
            details = f"{sshd_conf} 파일이 존재하지 않아 점검할 수 없습니다."
        
        status = "양호" if not is_vulnerable else "취약"
        action = "sshd_config에서 'PermitRootLogin no'로 설정" if is_vulnerable else "적절한 설정 유지"
        self._add_audit_result(item_u60, status, details, "자동 점검", action)

        # U-61. FTP 서비스 확인
        item_u61 = "U-61. FTP 서비스 확인"
        self._log_audit_item(item_u61)
        ftp_services = ['vsftpd', 'proftpd', 'pure-ftpd']
        is_ftp_running = False
        for service in ftp_services:
            if PlatformUtils.is_service_active(service):
                is_ftp_running = True
                break
        
        if is_ftp_running:
            status = "취약"
            details = "FTP 서비스가 활성화되어 있습니다."
            action = "불필요한 FTP 서비스 비활성화"
        else:
            status = "양호"
            details = "FTP 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u61, status, details, "자동 점검", action)

        # U-62. ftp 계정 shell 제한
        item_u62 = "U-62. ftp 계정 shell 제한"
        self._log_audit_item(item_u62)
        vsftpd_conf = '/etc/vsftpd.conf'
        is_vulnerable = False
        details = ""
        if PlatformUtils.check_file_exists(vsftpd_conf):
            content = PlatformUtils.read_file_content(vsftpd_conf)
            if content and re.search(r'chroot_local_user\s*=\s*NO', content):
                is_vulnerable = True
                details = f"{vsftpd_conf} 파일에 'chroot_local_user=NO' 설정이 발견되었습니다."
        else:
            details = "vsftpd.conf 파일이 존재하지 않아 점검할 수 없습니다."
        
        status = "양호" if not is_vulnerable else "취약"
        action = "vsftpd.conf에서 'chroot_local_user=YES'로 설정" if is_vulnerable else "적절한 설정 유지"
        self._add_audit_result(item_u62, status, details, "자동 점검", action)

        # U-64. ftpusers 파일 설정
        item_u64 = "U-64. ftpusers 파일 설정"
        self._log_audit_item(item_u64)
        ftpusers_path = '/etc/ftpusers'
        is_secure = True
        details = ""
        if PlatformUtils.check_file_exists(ftpusers_path):
            content = PlatformUtils.read_file_content(ftpusers_path)
            if content and 'root' not in content:
                is_secure = False
                details = f"'{ftpusers_path}' 파일에 'root' 계정이 포함되어 있지 않습니다."
        else:
            is_secure = False
            details = f"'{ftpusers_path}' 파일이 존재하지 않아 점검할 수 없습니다."
        
        status = "양호" if is_secure else "취약"
        action = "ftpusers 파일에 root 계정 추가" if not is_secure else "적절한 설정 유지"
        self._add_audit_result(item_u64, status, details, "자동 점검", action)

        # U-65. at 파일 소유자 및 권한 설정
        item_u65 = "U-65. at 파일 소유자 및 권한 설정"
        self._log_audit_item(item_u65)
        at_files = ['/etc/at.allow', '/etc/at.deny']
        vulnerable_files = []
        for filepath in at_files:
            is_safe, details_info = PlatformUtils.is_file_owned_by_root_and_permission_safe(filepath, 640)
            if not is_safe:
                vulnerable_files.append(f"{filepath}: {details_info}")
        
        if vulnerable_files:
            status = "취약"
            details = "다음 파일의 소유자 또는 권한 설정이 취약합니다:\n" + "\n".join(vulnerable_files)
            action = "at 관련 파일 소유자를 root로, 권한을 640 이하로 설정"
        else:
            status = "양호"
            details = "at 관련 파일의 소유자 및 권한이 적절하게 설정되었습니다."
            action = "적절한 소유자 및 권한 설정 유지"
        self._add_audit_result(item_u65, status, details, "자동 점검", action)

        # U-66. SNMP 서비스 구동 점검
        item_u66 = "U-66. SNMP 서비스 구동 점검"
        self._log_audit_item(item_u66)
        is_snmp_running = PlatformUtils.is_service_active('snmpd')
        if is_snmp_running:
            status = "취약"
            details = "SNMP 서비스가 활성화되어 있습니다."
            action = "불필요한 SNMP 서비스 비활성화"
        else:
            status = "양호"
            details = "SNMP 서비스가 비활성화되어 있습니다."
            action = "적절한 서비스 설정 유지"
        self._add_audit_result(item_u66, status, details, "자동 점검", action)

        # U-67. SNMP 서비스 Community String의 복잡성 설정
        item_u67 = "U-67. SNMP 서비스 Community String의 복잡성 설정"
        self._log_audit_item(item_u67)
        snmp_conf = '/etc/snmp/snmpd.conf'
        is_vulnerable = False
        details = ""
        if PlatformUtils.check_file_exists(snmp_conf):
            content = PlatformUtils.read_file_content(snmp_conf)
            if content and (re.search(r'public', content) or re.search(r'private', content)):
                is_vulnerable = True
                details = f"'{snmp_conf}' 파일에 'public' 또는 'private' 커뮤니티 문자열이 발견되었습니다."
        else:
            details = f"'{snmp_conf}' 파일이 존재하지 않아 점검할 수 없습니다."
        
        status = "양호" if not is_vulnerable else "취약"
        action = "커뮤니티 문자열을 복잡한 문자열로 변경" if is_vulnerable else "적절한 설정 유지"
        self._add_audit_result(item_u67, status, details, "자동 점검", action)

        # U-68. 로그온 시 경고 메시지 제공
        item_u68 = "U-68. 로그온 시 경고 메시지 제공"
        self._log_audit_item(item_u68)
        
        motd_content = PlatformUtils.read_file_content('/etc/motd')
        issue_content = PlatformUtils.read_file_content('/etc/issue')

        if motd_content or issue_content:
            status = "양호"
            details = "로그온 경고 메시지가 설정되어 있습니다."
            action = "적절한 설정 유지"
        else:
            status = "취약"
            details = "로그온 경고 메시지 파일이 비어있습니다."
            action = "로그온 경고 메시지 설정"
        self._add_audit_result(item_u68, status, details, "자동 점검", action)

        # U-69. NFS 설정파일 접근 제한
        item_u69 = "U-69. NFS 설정파일 접근 제한"
        self._log_audit_item(item_u69)
        filepath_u69 = '/etc/exports'
        is_safe, details = PlatformUtils.is_file_owned_by_root_and_permission_safe(filepath_u69, 644)
        
        if is_safe:
            status = "양호"
        else:
            status = "취약"
        self._add_audit_result(item_u69, status, details, "자동 점검", "소유자: root, 권한: 644 이하로 설정")

        # U-70. expn, vrfy 명령어 제한
        item_u70 = "U-70. expn, vrfy 명령어 제한"
        self._log_audit_item(item_u70)
        
        is_expn_vrfy_restricted = False
        sendmail_conf_path = '/etc/mail/sendmail.cf'
        if PlatformUtils.check_file_exists(sendmail_conf_path):
            content = PlatformUtils.read_file_content(sendmail_conf_path)
            if content and ('noexpn' in content or 'novrfy' in content):
                is_expn_vrfy_restricted = True

        if is_expn_vrfy_restricted:
            status = "양호"
            details = "Sendmail 설정 파일에서 expn, vrfy 명령어 사용이 제한되었습니다."
            action = "적절한 설정 유지"
        else:
            status = "취약"
            details = "Sendmail 설정 파일에서 expn, vrfy 명령어에 대한 제한 설정이 없습니다."
            action = "sendmail.cf에 noexpn, novrfy 옵션 추가"
        self._add_audit_result(item_u70, status, details, "자동 점검", action)

        # U-71. Apache 웹서비스 정보 숨김
        item_u71 = "U-71. Apache 웹서비스 정보 숨김"
        self._log_audit_item(item_u71)
        
        is_apache_info_hidden = False
        apache_conf_paths = ['/etc/httpd/conf/httpd.conf', '/etc/apache2/apache2.conf', '/etc/apache2/conf.d']
        
        for path in apache_conf_paths:
            if os.path.isfile(path):
                content = PlatformUtils.read_file_content(path)
                if content and ('ServerTokens Prod' in content or 'ServerSignature Off' in content):
                    is_apache_info_hidden = True
                    break
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        content = PlatformUtils.read_file_content(filepath)
                        if content and ('ServerTokens Prod' in content or 'ServerSignature Off' in content):
                            is_apache_info_hidden = True
                            break
                    if is_apache_info_hidden:
                        break
            if is_apache_info_hidden:
                break

        if is_apache_info_hidden:
            status = "양호"
            details = "Apache 설정 파일에서 서버 정보가 숨겨져 있습니다."
            action = "적절한 설정 유지"
        else:
            status = "취약"
            details = "Apache 설정 파일에 ServerTokens Prod 또는 ServerSignature Off 설정이 없습니다."
            action = "ServerTokens Prod 또는 ServerSignature Off 설정"
        self._add_audit_result(item_u71, status, details, "자동 점검", action)

        # U-72. 정책에 따른 시스템 로깅 설정
        item_u72 = "U-72. 정책에 따른 시스템 로깅 설정"
        self._log_audit_item(item_u72)
        syslog_conf = '/etc/rsyslog.conf'
        is_secure = True
        details = ""
        if PlatformUtils.check_file_exists(syslog_conf):
            content = PlatformUtils.read_file_content(syslog_conf)
            if content and not re.search(r'^\s*\*\.info;mail\.none;authpriv\.none;cron\.none\s+\/var\/log\/messages', content, re.MULTILINE):
                is_secure = False
                details = f"'{syslog_conf}' 파일에 'authpriv.none' 설정이 없거나 'info' 설정이 미흡합니다."
        else:
            is_secure = False
            details = f"'{syslog_conf}' 파일이 존재하지 않아 점검할 수 없습니다."
        
        status = "양호" if is_secure else "취약"
        action = "rsyslog.conf 파일 수정" if not is_secure else "적절한 로깅 설정 유지"
        self._add_audit_result(item_u72, status, details, "자동 점검", action)

        logging.info(f"{self.module_name} 점검이 완료되었습니다.")
        return self.module_audit_results