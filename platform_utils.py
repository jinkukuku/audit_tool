import platform
import subprocess
import logging
import os

class PlatformUtils:
    """
    운영체제별 유틸리티 기능을 제공하는 클래스입니다.
    파일 소유자/권한 확인, 명령어 실행 등을 OS에 독립적으로 처리합니다.
    """

    @staticmethod
    def get_os_type():
        """
        현재 운영체제 유형을 반환합니다.
        Returns:
            str: "Linux", "Windows", "Darwin" (macOS) 등.
        """
        os_name = platform.system()
        if os_name == "Linux":
            return "Linux"
        elif os_name == "Windows":
            return "Windows"
        elif os_name == "AIX":
            return "AIX"
        elif os_name == "HP-UX":
            return "HP-UX"
        elif os_name == "SunOS": # Solaris의 platform.system() 값
            return "Solaris"
        else:
            return os_name # 기타 OS는 그대로 반환

    @staticmethod
    def execute_command(command, shell=False):
        """
        쉘 명령어를 실행하고 결과를 반환합니다.
        Args:
            command (list or str): 실행할 명령어 (list 형태 권장, shell=True일 경우 str).
            shell (bool): 쉘을 통해 명령어를 실행할지 여부. (보안상 False 권장)
        Returns:
            tuple: (stdout, stderr, returncode)
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False, # 오류 발생 시에도 예외를 발생시키지 않음
                shell=shell
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except FileNotFoundError:
            logging.error(f"명령어를 찾을 수 없습니다: {command[0] if isinstance(command, list) else command}")
            return "", "Command not found", 127
        except Exception as e:
            logging.error(f"명령어 실행 중 오류 발생: {command} - {e}")
            return "", str(e), 1

    @staticmethod
    def get_file_owner(filepath):
        """
        파일의 소유자 이름을 가져옵니다. (Linux 기준)
        Args:
            filepath (str): 파일 경로.
        Returns:
            str: 소유자 이름 또는 None (오류 시).
        """
        if PlatformUtils.get_os_type() == "Linux":
            try:
                # `stat -c %U <filepath>` 명령어를 사용하여 소유자 이름 가져오기
                stdout, stderr, returncode = PlatformUtils.execute_command(['stat', '-c', '%U', filepath])
                if returncode == 0:
                    return stdout
                else:
                    logging.error(f"파일 소유자를 가져오는 데 실패했습니다 '{filepath}': {stderr}")
                    return None
            except Exception as e:
                logging.error(f"파일 소유자 확인 중 오류 발생: {filepath} - {e}")
                return None
        # TODO: Windows, macOS 등 다른 OS에 대한 구현 추가
        logging.warning(f"get_file_owner: '{PlatformUtils.get_os_type()}' OS는 아직 지원되지 않습니다.")
        return None

    @staticmethod
    def get_file_permissions(filepath):
        """
        파일의 8진수 권한을 가져옵니다. (Linux 기준)
        Args:
            filepath (str): 파일 경로.
        Returns:
            str: 8진수 권한 문자열 (예: "644") 또는 None (오류 시).
        """
        if PlatformUtils.get_os_type() == "Linux":
            try:
                # `stat -c %a <filepath>` 명령어를 사용하여 8진수 권한 가져오기
                stdout, stderr, returncode = PlatformUtils.execute_command(['stat', '-c', '%a', filepath])
                if returncode == 0:
                    return stdout
                else:
                    logging.error(f"파일 권한을 가져오는 데 실패했습니다 '{filepath}': {stderr}")
                    return None
            except Exception as e:
                logging.error(f"파일 권한 확인 중 오류 발생: {filepath} - {e}")
                return None
        # TODO: Windows, macOS 등 다른 OS에 대한 구현 추가
        logging.warning(f"get_file_permissions: '{PlatformUtils.get_os_type()}' OS는 아직 지원되지 않습니다.")
        return None

    @staticmethod
    def is_file_owned_by_root_and_permission_safe(filepath, max_permission):
        """
        파일의 소유자가 root이고, 지정된 최대 권한보다 낮거나 같은지 확인합니다.
        Args:
            filepath (str): 파일 경로.
            max_permission (int): 허용되는 최대 8진수 권한 (예: 644).
        Returns:
            bool: 양호(True) 또는 취약(False).
        """
        try:
            if not os.path.exists(filepath):
                return False, f"파일이 존재하지 않습니다: {filepath}"
            
            stat_info = os.stat(filepath)
            
            # 소유자 확인
            file_owner = pwd.getpwuid(stat_info.st_uid).pw_name
            if file_owner != 'root':
                return False, f"소유자가 root가 아닙니다. 현재 소유자: {file_owner}"

            # 권한 확인
            # os.stat().st_mode 값은 권한 외의 정보도 포함하므로 순수 권한만 추출
            permissions = oct(stat_info.st_mode)[-3:]
            
            if int(permissions) > max_permission:
                return False, f"권한이 {max_permission}보다 높습니다. 현재 권한: {permissions}"

            return True, "양호"
        except FileNotFoundError:
            return True, "파일이 존재하지 않으므로 양호합니다." # 파일이 없으면 양호로 간주
        except Exception as e:
            logging.error(f"파일 검증 중 오류 발생: {filepath} - {e}")
            return False, f"파일 검증 중 오류 발생: {e}"


    @staticmethod
    def check_file_exists(filepath):
        """
        파일이 존재하는지 확인합니다.
        Args:
            filepath (str): 파일 경로.
        Returns:
            bool: 파일이 존재하면 True, 아니면 False.
        """
        return os.path.exists(filepath)

    @staticmethod
    def read_file_content(filepath):
        """
        파일의 내용을 읽어 반환합니다.
        Args:
            filepath (str): 파일 경로.
        Returns:
            str: 파일 내용 또는 None (오류 시).
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except FileNotFoundError:
            logging.error(f"파일을 찾을 수 없습니다: {filepath}")
            return None
        except Exception as e:
            logging.error(f"파일 내용 읽기 중 오류 발생: {e}")
            return None