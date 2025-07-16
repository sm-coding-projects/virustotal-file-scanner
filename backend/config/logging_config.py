"""
Logging configuration for the VirusTotal File Scanner application.
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask

def configure_logging(app: Flask) -> None:
    """
    Configure logging for the application.
    
    Args:
        app: Flask application instance
    """
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
    log_file = app.config.get('LOG_FILE', '/app/logs/app.log')
    
    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure file handler
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10485760,  # 10 MB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    file_handler.setLevel(log_level)
    
    # Add handlers to app logger
    app.logger.addHandler(file_handler)
    app.logger.setLevel(log_level)
    
    # Log application startup
    app.logger.info(f"Application starting in {app.config.get('ENV', 'development')} mode")