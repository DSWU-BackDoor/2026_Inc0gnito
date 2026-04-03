import time
import subprocess
import select
from utils.shell import run
from utils.logger import log
from config import MEDIAMTX_LOG, BAN_THRESHOLD, BAN_TIME

class IntrusionMonitor:
    def __init__(self):
        self.failed = {}
        self.banned = {}
        self._proc = None
        self._start_tail()

    def _start_tail(self):
        try:
            self._proc = subprocess.Popen(
                ["tail", "-F", MEDIAMTX_LOG],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
        except Exception as e:
            log(f"tail 실행 실패: {e}")

    def monitor(self):
        if not self._proc:
            self._start_tail()
            return

        # 논블로킹: 읽을 데이터 있을 때만 처리
        while True:
            ready = select.select([self._proc.stdout], [], [], 0)
            if not ready[0]:
                break  # 읽을 데이터 없으면 바로 리턴

            line = self._proc.stdout.readline()
            if not line:
                break

            if "closed" not in line.lower():
                continue

            try:
                ip = None
                for part in line.split():
                    if part.count(".") == 3:
                        ip = part.split(":")[0]
                        break
                if not ip:
                    continue
                if ip in self.banned or ip == "127.0.0.1":
                    continue

                self.failed[ip] = self.failed.get(ip, 0) + 1
                count = self.failed[ip]
                print(f"[IoT-Sentry] 인증 실패 감지 - IP: {ip} ({count}회)")
                log(f"인증 실패 {ip} ({count}회)")

                if count >= BAN_THRESHOLD:
                    self.ban(ip)

            except Exception as e:
                log(f"IntrusionMonitor 파싱 오류: {e}")

    def ban(self, ip):
        if ip in self.banned:
            return
        print(f"[IoT-Sentry] IP 자동 차단: {ip}")
        log(f"IP 차단: {ip}")
        run(f"iptables -I INPUT -s {ip} -j DROP")
        self.banned[ip] = time.time()

    def unban_expired(self):
        now = time.time()
        for ip, t in list(self.banned.items()):
            if now - t > BAN_TIME:
                print(f"[IoT-Sentry] IP 차단 해제: {ip}")
                log(f"IP 차단 해제: {ip}")
                run(f"iptables -D INPUT -s {ip} -j DROP")
                del self.banned[ip]
                del self.failed[ip]