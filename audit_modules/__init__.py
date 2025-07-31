# audit_modules/__init__.py

# 하위 OS별 패키지들을 임포트하여 외부에서 접근할 수 있도록 합니다.
# 이렇게 하면 'import audit_modules.linux_audit' 등으로 접근 가능합니다.
from . import linux_audit
from . import windows_audit
from . import aix_audit
from . import hpux_audit
from . import solaris_audit

# 'from audit_modules import *' 사용 시 임포트될 서브 패키지들을 정의합니다.
# 일반적으로 와일드카드 임포트는 권장되지 않지만, 패키지 구조를 명확히 하기 위해 포함합니다.
__all__ = [
    "linux_audit",
    "windows_audit",
    "aix_audit",
    "hpux_audit",
    "solaris_audit"
]
