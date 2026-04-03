import logging
import os

os.makedirs("/home/pi/IoT-sentry/logs", exist_ok=True)

logging.basicConfig(
    filename="/home/pi/IoT-sentry/logs/sentry.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def log(msg):
    logging.info(msg)