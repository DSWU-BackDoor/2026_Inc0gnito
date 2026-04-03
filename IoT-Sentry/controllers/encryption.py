import os
import yaml
from utils.shell import run
from utils.logger import log
from config import MEDIAMTX_CONF

CERT = "/home/pi/server.crt"
KEY = "/home/pi/server.key"

class EncryptionController:
    def check(self):
        try:
            with open(MEDIAMTX_CONF) as f:
                data = yaml.safe_load(f) or {}

            if data.get("encryption") == "yes":
                return

            log("RTSP 암호화 미적용 감지")

            # 인증서 없으면 생성
            if not os.path.exists(CERT):
                log("TLS 인증서 생성")
                result = run(
                    f'openssl req -x509 -newkey rsa:2048 -keyout {KEY} -out {CERT} '
                    f'-days 365 -nodes -subj "/CN=raspberrypi"'
                )
                if not os.path.exists(CERT):
                    log(f"인증서 생성 실패: {result}")
                    return

            # 미지원 필드 제거
            for field in ["rtspEncryption", "rtspServerCert", "rtspServerKey", "rtspCert", "rtspKey"]:
                data.pop(field, None)

            # 암호화 설정 적용
            data["encryption"] = "yes"
            data["serverCert"] = CERT
            data["serverKey"] = KEY

            # protocols에서 udp, multicast 제거
            protocols = data.get("protocols", ["udp", "multicast", "tcp"])
            data["protocols"] = [p for p in protocols if p not in ("udp", "multicast")]

            with open(MEDIAMTX_CONF, "w") as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

            log("TLS 암호화 설정 완료 → mediamtx 재시작")
            run("pkill mediamtx; sleep 1; /home/pi/mediamtx /home/pi/mediamtx.yml &")

        except Exception as e:
            log(f"EncryptionController 오류: {e}")