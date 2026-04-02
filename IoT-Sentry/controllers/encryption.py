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

            # v1.3.0 미지원 필드 제거
            changed = False
            for field in ["rtspEncryption", "rtspServerCert", "rtspServerKey", "rtspsAddress"]:
                if field in data:
                    del data[field]
                    changed = True

            if changed:
                with open(MEDIAMTX_CONF, "w") as f:
                    yaml.dump(data, f)
                log("EncryptionController: 미지원 TLS 필드 제거 (v1.3.0 호환)")
                run("systemctl restart mediamtx")

        except Exception as e:
            log(f"EncryptionController 오류: {e}")
