import logging
import os
from logging.handlers import RotatingFileHandler

# Configure logger
logger = logging.getLogger('CybersecurityDashboard')
logger.setLevel(logging.DEBUG)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Create file handler with rotation
os.makedirs('logs', exist_ok=True)
file_handler = RotatingFileHandler(
    'logs/cybersecurity_dashboard.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def log_exception(exc_type, exc_value, exc_traceback):
    """Log uncaught exceptions"""
    logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))