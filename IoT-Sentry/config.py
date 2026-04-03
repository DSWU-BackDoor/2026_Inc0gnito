RTSP_PORT = 8554
ALLOWED_NET = "172.20.10.0/28"

MEDIAMTX_CONF = "/home/pi/mediamtx.yml"
MEDIAMTX_LOG = "/home/pi/mediamtx.log"

# 모듈별 실행 주기 (초)
INTRUSION_INTERVAL = 5      # 침입 탐지 (빠르게)
EXPOSURE_INTERVAL = 30      # 포트 감시
ENCRYPTION_INTERVAL = 60    # TLS 검사
AUTH_INTERVAL = 3600        # 비번 만료 (1시간)

BAN_THRESHOLD = 5
BAN_TIME = 600