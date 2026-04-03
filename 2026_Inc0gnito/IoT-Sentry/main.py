import time
import psutil
from controllers.exposure import ExposureController
from controllers.auth import AuthController, load_meta
from controllers.encryption import EncryptionController
from controllers.intrusion import IntrusionMonitor
from config import (
    INTRUSION_INTERVAL,
    EXPOSURE_INTERVAL,
    ENCRYPTION_INTERVAL,
    AUTH_INTERVAL
)

exposure   = ExposureController()
auth       = AuthController()
encryption = EncryptionController()
intrusion  = IntrusionMonitor()

print("=" * 40)
print("  [IoT-Sentry] 보안 모듈 시작")
print("=" * 40)

meta = load_meta()
if not meta.get("is_initialized"):
    auth.setup()

print("\n[IoT-Sentry] 보안 감시 시작\n")

last_exposure   = 0
last_encryption = 0
last_auth       = 0
last_status     = 0

while True:
    now = time.time()

    intrusion.monitor()
    intrusion.unban_expired()

    if now - last_exposure >= EXPOSURE_INTERVAL:
        exposure.check()
        last_exposure = now

    if now - last_encryption >= ENCRYPTION_INTERVAL:
        encryption.check()
        last_encryption = now

    if now - last_auth >= AUTH_INTERVAL:
        auth.check()
        last_auth = now

    if now - last_status >= 30:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        print(f"[IoT-Sentry] CPU: {cpu}% | 메모리: {mem.percent}% ({mem.used // 1024 // 1024}MB / {mem.total // 1024 // 1024}MB)")
        last_status = now

    time.sleep(INTRUSION_INTERVAL)
