from utils.shell import run
from utils.logger import log
from config import RTSP_PORT, ALLOWED_NET


class ExposureController:
    def check(self):
        rules = run("iptables -L INPUT -n")

        # ACCEPT + DROP 규칙이 모두 존재하는지 확인 (단순 포트 포함 여부만 보면 오탐 가능)
        port_str = f"dpt:{RTSP_PORT}"
        has_accept = port_str in rules and "ACCEPT" in rules
        has_drop = port_str in rules and "DROP" in rules

        if has_accept and has_drop:
            return

        log("RTSP 포트 보호 규칙 적용")

        # 기존에 일부만 적용된 경우 중복 방지를 위해 기존 규칙 제거 후 재적용
        run(f"iptables -D INPUT -p tcp --dport {RTSP_PORT} -s {ALLOWED_NET} -j ACCEPT 2>/dev/null")
        run(f"iptables -D INPUT -p tcp --dport {RTSP_PORT} -j DROP 2>/dev/null")

        run(f"iptables -A INPUT -p tcp --dport {RTSP_PORT} -s {ALLOWED_NET} -j ACCEPT")
        run(f"iptables -A INPUT -p tcp --dport {RTSP_PORT} -j DROP")

        log("RTSP 포트 보호 규칙 적용 완료")
