"""
Structured logging — one logger, one format, everywhere.
"""
import logging
import sys
from config import Config


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(Config.LOG_FORMAT))
        logger.addHandler(handler)
    logger.setLevel(Config.LOG_LEVEL)
    return logger
