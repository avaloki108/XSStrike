"""
Configuration Manager Module

This module handles loading, validation, and management of XSStrike configuration files.
It supports both JSON configuration files and environment variable overrides.
"""

import json
import os
import sys
from typing import Dict, Any, Optional
from core.log import setup_logger

logger = setup_logger(__name__)


class ConfigurationManager:
    """Manages XSStrike configuration from files and environment variables."""

    def __init__(self):
        self.config = {}
        self.config_file_path = None
        self.default_config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config',
            'default.json'
        )

    def load_default_config(self) -> Dict[str, Any]:
        """
        Load the default configuration file.
        
        Returns:
            Dictionary containing the default configuration
            
        Raises:
            FileNotFoundError: If default config file doesn't exist
            json.JSONDecodeError: If config file is invalid JSON
        """
        try:
            with open(self.default_config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            logger.debug(f"Loaded default configuration from {self.default_config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Default configuration file not found: {self.default_config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in default config file: {e}")
            raise

    def load_user_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load a user-specified configuration file.
        
        Args:
            config_path: Path to the user configuration file
            
        Returns:
            Dictionary containing the user configuration
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If config file is invalid JSON
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            logger.info(f"Loaded user configuration from {config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"User configuration file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in user config file: {e}")
            raise

    def merge_configs(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge user configuration with default configuration.
        User values override default values.
        
        Args:
            default: Default configuration dictionary
            user: User configuration dictionary
            
        Returns:
            Merged configuration dictionary
        """
        merged = default.copy()

        def deep_update(base_dict: Dict[str, Any], update_dict: Dict[str, Any]):
            for key, value in update_dict.items():
                if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                    deep_update(base_dict[key], value)
                else:
                    base_dict[key] = value

        deep_update(merged, user)
        return merged

    def apply_env_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply environment variable overrides to configuration.
        Environment variables should be prefixed with 'XSSTRIKE_'
        
        Args:
            config: Configuration dictionary to update
            
        Returns:
            Updated configuration dictionary
        """
        env_mapping = {
            'XSSTRIKE_XSS_CHECKER': ('xss_checker', str),
            'XSSTRIKE_BLIND_PAYLOAD': ('blind_payload', str),
            'XSSTRIKE_DELAY': ('network.delay', int),
            'XSSTRIKE_TIMEOUT': ('network.timeout', int),
            'XSSTRIKE_THREAD_COUNT': ('network.thread_count', int),
            'XSSTRIKE_VERIFY_SSL': ('network.verify_ssl', bool),
            'XSSTRIKE_SSL_CERT_PATH': ('network.ssl_cert_path', str),
            'XSSTRIKE_MIN_EFFICIENCY': ('scanning.min_efficiency', int),
            'XSSTRIKE_LOG_LEVEL': ('logging.console_log_level', str),
            'XSSTRIKE_LOG_FILE': ('logging.log_file', str),
        }

        updated_config = config.copy()

        for env_var, (config_path, value_type) in env_mapping.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                try:
                    # Convert value to appropriate type
                    if value_type == bool:
                        parsed_value = env_value.lower() in ('true', '1', 'yes', 'on')
                    elif value_type == int:
                        parsed_value = int(env_value)
                    else:
                        parsed_value = env_value

                    # Set nested configuration value
                    keys = config_path.split('.')
                    current = updated_config
                    for key in keys[:-1]:
                        if key not in current:
                            current[key] = {}
                        current = current[key]
                    current[keys[-1]] = parsed_value

                    logger.debug(f"Applied environment override: {env_var} = {parsed_value}")
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid environment variable value {env_var}={env_value}: {e}")

        return updated_config

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration values.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        validation_rules = [
            ('xss_checker', str, lambda x: len(x) > 0),
            ('network.delay', int, lambda x: x >= 0),
            ('network.timeout', int, lambda x: x > 0),
            ('network.thread_count', int, lambda x: 0 < x <= 100),
            ('scanning.min_efficiency', int, lambda x: 0 <= x <= 100),
        ]

        is_valid = True

        for config_path, expected_type, validator in validation_rules:
            try:
                keys = config_path.split('.')
                current = config
                for key in keys:
                    current = current[key]

                if not isinstance(current, expected_type):
                    logger.error(f"Configuration {config_path} must be of type {expected_type.__name__}")
                    is_valid = False
                elif not validator(current):
                    logger.error(f"Configuration {config_path} has invalid value: {current}")
                    is_valid = False
            except KeyError:
                logger.error(f"Required configuration {config_path} is missing")
                is_valid = False

        return is_valid

    def load_config(self, user_config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load and merge configuration from default and user files, with environment overrides.
        
        Args:
            user_config_path: Optional path to user configuration file
            
        Returns:
            Final merged and validated configuration
            
        Raises:
            SystemExit: If configuration loading or validation fails
        """
        try:
            # Load default configuration
            config = self.load_default_config()

            # Load and merge user configuration if provided
            if user_config_path:
                user_config = self.load_user_config(user_config_path)
                config = self.merge_configs(config, user_config)
                self.config_file_path = user_config_path

            # Apply environment variable overrides
            config = self.apply_env_overrides(config)

            # Validate configuration
            if not self.validate_config(config):
                logger.error("Configuration validation failed")
                sys.exit(1)

            self.config = config
            logger.info("Configuration loaded successfully")
            return config

        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation (e.g., 'network.timeout')
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        current = self.config

        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.
        
        Args:
            key: Configuration key in dot notation
            value: Value to set
        """
        keys = key.split('.')
        current = self.config

        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value

    def save_config(self, output_path: str) -> None:
        """
        Save current configuration to a file.
        
        Args:
            output_path: Path where to save the configuration file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            logger.info(f"Configuration saved to {output_path}")
        except (IOError, OSError) as e:
            logger.error(f"Failed to save configuration: {e}")
            raise


# Global configuration manager instance
config_manager = ConfigurationManager()
