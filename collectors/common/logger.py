"""
JFS SIEM - Centralized Logging System
FIXED: Added Logger class alias
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

class Logger:
    """Centralized logging for JFS SIEM - Simple wrapper"""
    
    def __init__(self, name):
        """Initialize logger with given name"""
        self.logger = self._get_logger(name)
        self.name = name
    
    def _get_logger(self, name):
        """Get or create a logger"""
        logger = logging.getLogger(f'jfs_siem.{name}')
        logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers
        if logger.handlers:
            return logger
        
        # Get log directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(os.path.dirname(script_dir))
        log_dir = os.path.join(base_dir, 'logs')
        
        # Create logs directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Console handler (INFO and above)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler (DEBUG and above) with rotation
        log_file = os.path.join(log_dir, f'{name}.log')
        try:
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10 MB
                backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            # If file logging fails, just use console
            logger.warning(f"Could not create log file: {e}")
        
        return logger
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)

# Backward compatibility
SIEMLogger = Logger

def get_logger(name):
    """Get a logger instance"""
    return Logger(name)
