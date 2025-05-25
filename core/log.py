import logging
import sys
import json
from datetime import datetime
from .colors import *

__all__ = ["setup_logger", "console_log_level", "file_log_level", "log_file"]

console_log_level = "INFO"
file_log_level = None
log_file = "xsstrike.log"

"""
Default Logging Levels
CRITICAL = 50
ERROR = 40
WARNING = 30
INFO = 20
DEBUG = 10
"""

VULN_LEVEL_NUM = 60
RUN_LEVEL_NUM = 22
GOOD_LEVEL_NUM = 25

logging.addLevelName(VULN_LEVEL_NUM, "VULN")
logging.addLevelName(RUN_LEVEL_NUM, "RUN")
logging.addLevelName(GOOD_LEVEL_NUM, "GOOD")


def _vuln(self, msg, *args, **kwargs):
    if self.isEnabledFor(VULN_LEVEL_NUM):
        self._log(VULN_LEVEL_NUM, msg, args, **kwargs)


def _run(self, msg, *args, **kwargs):
    if self.isEnabledFor(RUN_LEVEL_NUM):
        self._log(RUN_LEVEL_NUM, msg, args, **kwargs)


def _good(self, msg, *args, **kwargs):
    if self.isEnabledFor(GOOD_LEVEL_NUM):
        self._log(GOOD_LEVEL_NUM, msg, args, **kwargs)


logging.Logger.vuln = _vuln
logging.Logger.run = _run
logging.Logger.good = _good


log_config = {
    "DEBUG": {
        "value": logging.DEBUG,
        "prefix": f"{yellow}[*]{end}",
    },
    "INFO": {
        "value": logging.INFO,
        "prefix": info,
    },
    "RUN": {
        "value": RUN_LEVEL_NUM,
        "prefix": run,
    },
    "GOOD": {
        "value": GOOD_LEVEL_NUM,
        "prefix": good,
    },
    "WARNING": {
        "value": logging.WARNING,
        "prefix": f"{yellow}[!!]{end}",
    },
    "ERROR": {
        "value": logging.ERROR,
        "prefix": bad,
    },
    "CRITICAL": {
        "value": logging.CRITICAL,
        "prefix": f"{red}[--]{end}",
    },
    "VULN": {
        "value": VULN_LEVEL_NUM,
        "prefix": f"{green}[++]{red}",
    },
}


class CustomFormatter(logging.Formatter):
    """Custom formatter with color support and configurable formats."""

    def __init__(self, fmt=None, datefmt=None, style='%', use_colors=True):
        super().__init__(fmt, datefmt, style)
        self.use_colors = use_colors

    def format(self, record):
        msg = super().format(record)
        if self.use_colors and record.levelname in log_config:
            msg = f"{log_config[record.levelname]['prefix']} {msg} {end}"
        return msg


class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for machine-readable logs."""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if hasattr(record, 'extra_data'):
            log_entry["extra"] = record.extra_data

        return json.dumps(log_entry, ensure_ascii=False)


class CustomStreamHandler(logging.StreamHandler):
    """Custom stream handler with support for carriage return handling."""
    default_terminator = "\n"

    def emit(self, record):
        """
        Overrides emit method to temporarily update terminator character 
        in case last log record character is '\r'
        """
        if record.msg.endswith("\r"):
            self.terminator = "\r"
            super().emit(record)
            self.terminator = self.default_terminator
        else:
            super().emit(record)


class LoggerConfigMixin:
    """Mixin class providing additional logging functionality."""

    def log_with_extra(self, level, msg, extra_data=None):
        """Log a message with additional structured data."""
        if extra_data:
            # Create a new record with extra data
            record = self.makeRecord(
                self.name, level, "", 0, msg, (), None,
                extra={"extra_data": extra_data}
            )
            self.handle(record)
        else:
            self.log(level, msg)

    def log_vulnerability(self, url, parameter, payload, confidence=None):
        """Log a vulnerability finding with structured data."""
        extra_data = {
            "type": "vulnerability",
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.log_with_extra(VULN_LEVEL_NUM, f"XSS vulnerability found: {url}", extra_data)

    def log_scan_progress(self, current, total, target=None):
        """Log scan progress with structured data."""
        extra_data = {
            "type": "progress",
            "current": current,
            "total": total,
            "percentage": (current / total * 100) if total > 0 else 0,
            "target": target
        }
        self.log_with_extra(RUN_LEVEL_NUM, f"Progress: {current}/{total}", extra_data)


def _switch_to_no_format_loggers(self):
    """Switch to no-format loggers temporarily."""
    self.removeHandler(self.console_handler)
    self.addHandler(self.no_format_console_handler)
    if hasattr(self, "file_handler") and hasattr(self, "no_format_file_handler"):
        self.removeHandler(self.file_handler)
        self.addHandler(self.no_format_file_handler)


def _switch_to_default_loggers(self):
    """Switch back to default formatted loggers."""
    self.removeHandler(self.no_format_console_handler)
    self.addHandler(self.console_handler)
    if hasattr(self, "file_handler") and hasattr(self, "no_format_file_handler"):
        self.removeHandler(self.no_format_file_handler)
        self.addHandler(self.file_handler)


def _get_level_and_log(self, msg, level):
    """Get appropriate log level and log message."""
    if level.upper() in log_config:
        log_method = getattr(self, level.lower())
        log_method(msg)
    else:
        self.info(msg)


def log_red_line(self, amount=60, level="INFO"):
    """Log a red line separator."""
    _switch_to_no_format_loggers(self)
    _get_level_and_log(self, red + ("-" * amount) + end, level)
    _switch_to_default_loggers(self)


def log_no_format(self, msg="", level="INFO"):
    """Log a message without formatting."""
    _switch_to_no_format_loggers(self)
    _get_level_and_log(self, msg, level)
    _switch_to_default_loggers(self)


def log_debug_json(self, msg="", data=None):
    """Log data as JSON for debugging."""
    if self.isEnabledFor(logging.DEBUG):
        if data is None:
            data = {}
        if isinstance(data, dict):
            try:
                self.debug(f"{msg} {json.dumps(data, indent=2)}")
            except TypeError:
                self.debug(f"{msg} {data}")
        else:
            self.debug(f"{msg} {data}")


def setup_logger(name="xsstrike", structured=False, log_to_file=None, console_colors=True):
    """
    Set up a logger with enhanced configuration options.
    
    Args:
        name: Logger name
        structured: Whether to use structured JSON logging for files
        log_to_file: Optional file path to log to (overrides global setting)
        console_colors: Whether to use colors in console output
    
    Returns:
        Configured logger instance
    """
    from types import MethodType

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()

    # Console handler
    console_handler = CustomStreamHandler(sys.stdout)
    console_handler.setLevel(log_config[console_log_level]["value"])
    console_formatter = CustomFormatter("%(message)s", use_colors=console_colors)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Setup blank handler for no-format logging
    no_format_console_handler = CustomStreamHandler(sys.stdout)
    no_format_console_handler.setLevel(log_config[console_log_level]["value"])
    no_format_console_handler.setFormatter(logging.Formatter(fmt=""))

    # Store handlers
    logger.console_handler = console_handler
    logger.no_format_console_handler = no_format_console_handler

    # File logging setup
    target_file = log_to_file or (log_file if file_log_level else None)
    if file_log_level and target_file:
        # Choose formatter based on structured logging preference
        if structured:
            file_formatter = StructuredFormatter()
        else:
            file_formatter = CustomFormatter(
                "%(asctime)s %(name)s - %(levelname)s - %(message)s",
                use_colors=False
            )

        file_handler = logging.FileHandler(target_file)
        file_handler.setLevel(log_config[file_log_level]["value"])
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Setup no-format file handler
        no_format_file_handler = logging.FileHandler(target_file)
        no_format_file_handler.setLevel(log_config[file_log_level]["value"])
        no_format_file_handler.setFormatter(logging.Formatter(fmt=""))

        # Store file handlers
        logger.file_handler = file_handler
        logger.no_format_file_handler = no_format_file_handler

    # Add mixin methods
    for attr_name in dir(LoggerConfigMixin):
        if not attr_name.startswith('_'):
            method = getattr(LoggerConfigMixin, attr_name)
            if callable(method):
                setattr(logger, attr_name, MethodType(method, logger))

    # Add custom methods
    logger.red_line = MethodType(log_red_line, logger)
    logger.no_format = MethodType(log_no_format, logger)
    logger.debug_json = MethodType(log_debug_json, logger)

    return logger


def configure_logging_from_config(config_manager):
    """
    Configure logging system from configuration manager.
    
    Args:
        config_manager: Configuration manager instance
    """
    global console_log_level, file_log_level, log_file

    console_log_level = config_manager.get("logging.console_log_level", "INFO")
    file_log_level = config_manager.get("logging.file_log_level", None)
    log_file = config_manager.get("logging.log_file", "xsstrike.log")

    # Additional logging configuration
    structured_logging = config_manager.get("logging.structured", False)
    console_colors = config_manager.get("logging.console_colors", True)

    return {
        "structured": structured_logging,
        "console_colors": console_colors
    }
