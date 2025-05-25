"""
Plugin management system for XSStrike.

This module provides a comprehensive plugin system that allows for extensible
functionality through a well-defined plugin interface.
"""

import os
import importlib
import inspect
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Type
from enum import Enum

from core.log import setup_logger

logger = setup_logger(__name__)


class PluginType(Enum):
    """Enum defining different types of plugins."""
    SCANNER = "scanner"  # Plugins that scan for vulnerabilities
    ANALYZER = "analyzer"  # Plugins that analyze responses
    REPORTER = "reporter"  # Plugins that generate reports
    FILTER = "filter"  # Plugins that filter requests/responses
    MODIFIER = "modifier"  # Plugins that modify requests/responses


class PluginHook(Enum):
    """Enum defining plugin execution hooks."""
    PRE_SCAN = "pre_scan"  # Before scanning starts
    POST_SCAN = "post_scan"  # After scanning completes
    PRE_REQUEST = "pre_request"  # Before each request
    POST_REQUEST = "post_request"  # After each request
    PRE_CRAWL = "pre_crawl"  # Before crawling starts
    POST_CRAWL = "post_crawl"  # After crawling completes
    VULNERABILITY_FOUND = "vulnerability_found"  # When vulnerability is found


class PluginResult:
    """Container for plugin execution results."""

    def __init__(self, success: bool = True, data: Any = None,
                 message: str = "", metadata: Dict[str, Any] = None):
        self.success = success
        self.data = data
        self.message = message
        self.metadata = metadata or {}

    def __bool__(self) -> bool:
        return self.success


class BasePlugin(ABC):
    """
    Abstract base class for all XSStrike plugins.
    
    All plugins must inherit from this class and implement the required methods.
    """

    def __init__(self, name: str, version: str = "1.0.0",
                 description: str = "", author: str = ""):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.enabled = True
        self.config = {}
        self.logger = setup_logger(f"plugin.{name}")

    @property
    @abstractmethod
    def plugin_type(self) -> PluginType:
        """Return the type of this plugin."""
        pass

    @property
    @abstractmethod
    def supported_hooks(self) -> List[PluginHook]:
        """Return list of hooks this plugin supports."""
        pass

    def configure(self, config: Dict[str, Any]) -> None:
        """Configure the plugin with settings."""
        self.config.update(config)
        self.logger.debug(f"Plugin {self.name} configured with: {config}")

    def enable(self) -> None:
        """Enable the plugin."""
        self.enabled = True
        self.logger.info(f"Plugin {self.name} enabled")

    def disable(self) -> None:
        """Disable the plugin."""
        self.enabled = False
        self.logger.info(f"Plugin {self.name} disabled")

    def is_enabled(self) -> bool:
        """Check if plugin is enabled."""
        return self.enabled

    @abstractmethod
    def execute(self, hook: PluginHook, context: Dict[str, Any]) -> PluginResult:
        """
        Execute the plugin for a specific hook.
        
        Args:
            hook: The hook being executed
            context: Context data for the execution
            
        Returns:
            PluginResult: Result of the plugin execution
        """
        pass

    def validate_context(self, hook: PluginHook, context: Dict[str, Any]) -> bool:
        """
        Validate that the context contains required data for the hook.
        
        Args:
            hook: The hook being executed
            context: Context data to validate
            
        Returns:
            bool: True if context is valid
        """
        return True

    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "type": self.plugin_type.value,
            "enabled": self.enabled,
            "supported_hooks": [hook.value for hook in self.supported_hooks]
        }


class PluginManager:
    """
    Manages plugin discovery, loading, and execution.
    """

    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, BasePlugin] = {}
        self.hooks: Dict[PluginHook, List[BasePlugin]] = {
            hook: [] for hook in PluginHook
        }
        self.logger = setup_logger(__name__)

    def discover_plugins(self) -> List[str]:
        """
        Discover available plugin files.
        
        Returns:
            List[str]: List of plugin module names
        """
        plugin_files = []
        if not os.path.exists(self.plugin_dir):
            self.logger.warning(f"Plugin directory {self.plugin_dir} does not exist")
            return plugin_files

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                plugin_files.append(module_name)

        self.logger.info(f"Discovered {len(plugin_files)} plugin files: {plugin_files}")
        return plugin_files

    def load_plugin(self, module_name: str) -> Optional[BasePlugin]:
        """
        Load a single plugin from module.
        
        Args:
            module_name: Name of the module to load
            
        Returns:
            Optional[BasePlugin]: Loaded plugin instance or None
        """
        try:
            # Import the module
            module_path = f"{self.plugin_dir}.{module_name}"
            module = importlib.import_module(module_path)

            # Find plugin classes in the module
            plugin_classes = []
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and
                        issubclass(obj, BasePlugin) and
                        obj is not BasePlugin):
                    plugin_classes.append(obj)

            if not plugin_classes:
                self.logger.warning(f"No plugin classes found in {module_name}")
                return None

            if len(plugin_classes) > 1:
                self.logger.warning(f"Multiple plugin classes found in {module_name}, using first one")

            # Instantiate the plugin
            plugin_class = plugin_classes[0]
            plugin_instance = plugin_class()

            self.logger.info(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
            return plugin_instance

        except Exception as e:
            self.logger.error(f"Failed to load plugin {module_name}: {str(e)}")
            return None

    def load_all_plugins(self) -> None:
        """Load all discovered plugins."""
        plugin_files = self.discover_plugins()

        for module_name in plugin_files:
            plugin = self.load_plugin(module_name)
            if plugin:
                self.register_plugin(plugin)

    def register_plugin(self, plugin: BasePlugin) -> None:
        """
        Register a plugin with the manager.
        
        Args:
            plugin: Plugin instance to register
        """
        if plugin.name in self.plugins:
            self.logger.warning(f"Plugin {plugin.name} already registered, replacing")

        self.plugins[plugin.name] = plugin

        # Register plugin for its supported hooks
        for hook in plugin.supported_hooks:
            if plugin not in self.hooks[hook]:
                self.hooks[hook].append(plugin)

        self.logger.info(f"Registered plugin: {plugin.name}")

    def unregister_plugin(self, plugin_name: str) -> bool:
        """
        Unregister a plugin.
        
        Args:
            plugin_name: Name of plugin to unregister
            
        Returns:
            bool: True if plugin was unregistered
        """
        if plugin_name not in self.plugins:
            self.logger.warning(f"Plugin {plugin_name} not found")
            return False

        plugin = self.plugins[plugin_name]

        # Remove from hooks
        for hook in PluginHook:
            if plugin in self.hooks[hook]:
                self.hooks[hook].remove(plugin)

        # Remove from plugins dict
        del self.plugins[plugin_name]

        self.logger.info(f"Unregistered plugin: {plugin_name}")
        return True

    def execute_hook(self, hook: PluginHook, context: Dict[str, Any]) -> Dict[str, PluginResult]:
        """
        Execute all plugins registered for a specific hook.
        
        Args:
            hook: Hook to execute
            context: Context data for execution
            
        Returns:
            Dict[str, PluginResult]: Results from each plugin
        """
        results = {}
        plugins = self.hooks.get(hook, [])

        if not plugins:
            self.logger.debug(f"No plugins registered for hook: {hook.value}")
            return results

        self.logger.debug(f"Executing {len(plugins)} plugins for hook: {hook.value}")

        for plugin in plugins:
            if not plugin.is_enabled():
                self.logger.debug(f"Skipping disabled plugin: {plugin.name}")
                continue

            try:
                # Validate context
                if not plugin.validate_context(hook, context):
                    self.logger.warning(f"Plugin {plugin.name} context validation failed for hook {hook.value}")
                    results[plugin.name] = PluginResult(False, message="Context validation failed")
                    continue

                # Execute plugin
                result = plugin.execute(hook, context)
                results[plugin.name] = result

                if result.success:
                    self.logger.debug(f"Plugin {plugin.name} executed successfully for hook {hook.value}")
                else:
                    self.logger.warning(f"Plugin {plugin.name} execution failed: {result.message}")

            except Exception as e:
                self.logger.error(f"Plugin {plugin.name} execution error: {str(e)}")
                results[plugin.name] = PluginResult(False, message=str(e))

        return results

    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Get a plugin by name."""
        return self.plugins.get(plugin_name)

    def get_plugins(self, plugin_type: Optional[PluginType] = None,
                    enabled_only: bool = False) -> List[BasePlugin]:
        """
        Get plugins by type and/or enabled status.
        
        Args:
            plugin_type: Filter by plugin type
            enabled_only: Only return enabled plugins
            
        Returns:
            List[BasePlugin]: Filtered list of plugins
        """
        plugins = list(self.plugins.values())

        if plugin_type:
            plugins = [p for p in plugins if p.plugin_type == plugin_type]

        if enabled_only:
            plugins = [p for p in plugins if p.is_enabled()]

        return plugins

    def configure_plugin(self, plugin_name: str, config: Dict[str, Any]) -> bool:
        """
        Configure a specific plugin.
        
        Args:
            plugin_name: Name of plugin to configure
            config: Configuration dictionary
            
        Returns:
            bool: True if plugin was configured successfully
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            self.logger.error(f"Plugin {plugin_name} not found")
            return False

        try:
            plugin.configure(config)
            return True
        except Exception as e:
            self.logger.error(f"Failed to configure plugin {plugin_name}: {str(e)}")
            return False

    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin."""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.enable()
            return True
        return False

    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.disable()
            return True
        return False

    def get_plugin_info(self) -> List[Dict[str, Any]]:
        """Get information about all registered plugins."""
        return [plugin.get_info() for plugin in self.plugins.values()]


# Global plugin manager instance
plugin_manager = PluginManager()
