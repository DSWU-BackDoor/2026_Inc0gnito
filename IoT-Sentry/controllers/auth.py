import yaml
import secrets
import re
import json
import getpass
from datetime import datetime
from utils.shell import run
from utils.logger import log
from config import MEDIAMTX_CONF

AUTH_META = "/home/pi/iot-sentry/auth_meta.json"

WEAK_PASSWORDS = [
    "1234", "12345", "123456", "password", "admin", "admin123",
    "root", "test", "guest", "raspberry", "pi", "0000", "111111"
]

# mediamtx v1.3.0 허용 문자만 사용
ALLOWED_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$*+.;<=>[]^_-@#&"

def is_strong_password(pw: str):
    if len(pw) < 8:
        return False, "8자 미만"
    if not re.search(r"[A-Z]", pw):
        return False, "대문자 없음"
    if not re.search(r"[a-z]", pw):
        return False, "소문자 없음"
    if not re.search(r"[0-9]", pw):
        return False, "숫자 없음"
    if pw.lower() in WEAK_PASSWORDS:
        return False, "기본 비번 사용 감지"
    # 허용 문자 검사
    for c in pw:
        if c not in ALLOWED_CHARS:
            return False, f"허용되지 않는 문자 포함: {c}"
    return True, "OK"

def load_meta():
    try:
        with open(AUTH_META) as f:
            return json.load(f)
    except:
        return {}

def save_meta(data):
    with open(AUTH_META, "w") as f:
        json.dump(data, f)
    run(f"chmod 600 {AUTH_META}")

def apply_password(password):
    with open(MEDIAMTX_CONF) as f:
        data = yaml.safe_load(f) or {}

    data["paths"] = {
        "stream": {
            "publishUser": "admin",
            "publishPass": password,
            "readUser": "admin",
            "readPass": password
        }
    }

    with open(MEDIAMTX_CONF, "w") as f:
        yaml.dump(data, f)

    run(f"chmod 600 {MEDIAMTX_CONF}")
    save_meta({
        "is_initialized": True,
        "last_changed": datetime.now().strftime("%Y-%m-%d")
    })
    log(f"비번 설정 완료 - 앞4자리: {password[:4]}****")
    run("systemctl restart mediamtx")

def prompt_password():
    print("\n[IoT-Sentry]  RTSP 스트림 비밀번호를 설정하세요")
    print("  조건: 8자 이상, 대소문자 + 숫자 포함\n")
    while True:
        pw = getpass.getpass("  비밀번호 입력: ")
        ok, reason = is_strong_password(pw)
        if not ok:
            print(f"  거부: {reason} → 다시 입력하세요\n")
            continue
        pw2 = getpass.getpass("  비밀번호 확인: ")
        if pw != pw2:
            print("  비밀번호가 일치하지 않습니다\n")
            continue
        return pw

class AuthController:
    def setup(self):
        print("\n[IoT-Sentry]  최초 실행 감지 → 비밀번호 설정 필요")
        password = prompt_password()
        apply_password(password)
        print(f"\n[IoT-Sentry] 비밀번호 설정 완료")
        print(f"  ID: admin")
        print(f"  만료: 90일 후 자동 알림\n")

    def check(self):
        meta = load_meta()
        last = meta.get("last_changed")
        if last:
            last_date = datetime.strptime(last, "%Y-%m-%d")
            days_left = 90 - (datetime.now() - last_date).days
            if days_left <= 0:
                print(f"\n[IoT-Sentry] 비밀번호 만료 → 변경 필요")
                log("비번 만료 감지 → 변경 요청")
                password = prompt_password()
                apply_password(password)
                print(f"[IoT-Sentry] 비밀번호 변경 완료\n")
            elif days_left <= 7:
                print(f"[IoT-Sentry] 비밀번호 만료 {days_left}일 전 경고!")
                log(f"비번 만료 {days_left}일 전 경고")
