import subprocess
from utils.logger import log


def run(cmd):
    """
    문자열 명령어를 안전하게 실행.
    shell=True는 유지하되, IP 등 외부 입력값은
    반드시 호출 전에 검증(validate_ip 등)할 것.
    """
    try:
        result = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT
        ).decode()
        return result
    except subprocess.CalledProcessError as e:
        log(f"[shell] 명령 실패: {cmd} → {e.output.decode().strip()}")
        return e.output.decode()


def run_safe(args: list):
    """
    리스트 형태로 명령어를 받아 shell=False로 실행.
    IP를 직접 iptables에 넘길 때 이 함수를 사용.
    예: run_safe(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    """
    try:
        result = subprocess.check_output(
            args, shell=False, stderr=subprocess.STDOUT
        ).decode()
        return result
    except subprocess.CalledProcessError as e:
        log(f"[shell] 명령 실패: {args} → {e.output.decode().strip()}")
        return e.output.decode()
