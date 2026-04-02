import logging
import os

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/sentry.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def log(msg):
    logging.info(msg)
