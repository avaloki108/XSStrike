"""
Unit tests for the plugin management system.
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch
from typing import Dict, List, Any

# Add the parent directory to the path so we can import the core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.plugin_manager import (
    BasePlugin, PluginManager, PluginType, PluginHook, PluginResult,
    plugin_manager
)


class TestPlugin(BasePlugin):
    """Test plugin for unit tests."""

    def __init__(self, name="TestPlugin"):
        super().__init__(
            name=name,
            version="1.0.0",
            description="Test plugin for unit tests",
            author="Test Author"
        )
        self.execute_called = False
        self.execute_results = {}

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.SCANNER

    @property
    def supported_hooks(self) -> List[PluginHook]:
        return [PluginHook.PRE_SCAN, PluginHook.POST_SCAN]

    def execute(self, hook: PluginHook, context: Dict[str, Any]) -> PluginResult:
        self.execute_called = True
        self.execute_results[hook] = context
        return PluginResult(True, data={"test": "success"}, message="Test execution")


class TestPluginResult(unittest.TestCase):
    """Test PluginResult class."""

    def test_plugin_result_success(self):
        """Test successful plugin result."""
        result = PluginResult(True, data={"key": "value"}, message="Success")

        self.assertTrue(result.success)
        self.assertTrue(bool(result))
        self.assertEqual(result.data, {"key": "value"})
        self.assertEqual(result.message, "Success")
        self.assertEqual(result.metadata, {})

    def test_plugin_result_failure(self):
        """Test failed plugin result."""
        result = PluginResult(False, message="Error occurred")

        self.assertFalse(result.success)
        self.assertFalse(bool(result))
        self.assertIsNone(result.data)
        self.assertEqual(result.message, "Error occurred")

    def test_plugin_result_with_metadata(self):
        """Test plugin result with metadata."""
        metadata = {"timestamp": "2023-01-01", "source": "test"}
        result = PluginResult(True, metadata=metadata)

        self.assertEqual(result.metadata, metadata)


class TestBasePlugin(unittest.TestCase):
    """Test BasePlugin class."""

    def setUp(self):
        """Set up test plugin."""
        self.plugin = TestPlugin()

    def test_plugin_initialization(self):
        """Test plugin initialization."""
        self.assertEqual(self.plugin.name, "TestPlugin")
        self.assertEqual(self.plugin.version, "1.0.0")
        self.assertEqual(self.plugin.description, "Test plugin for unit tests")
        self.assertEqual(self.plugin.author, "Test Author")
        self.assertTrue(self.plugin.enabled)
        self.assertEqual(self.plugin.config, {})

    def test_plugin_enable_disable(self):
        """Test plugin enable/disable functionality."""
        self.assertTrue(self.plugin.is_enabled())

        self.plugin.disable()
        self.assertFalse(self.plugin.is_enabled())

        self.plugin.enable()
        self.assertTrue(self.plugin.is_enabled())

    def test_plugin_configuration(self):
        """Test plugin configuration."""
        config = {"setting1": "value1", "setting2": "value2"}
        self.plugin.configure(config)

        self.assertEqual(self.plugin.config, config)

    def test_plugin_info(self):
        """Test plugin info retrieval."""
        info = self.plugin.get_info()

        expected_info = {
            "name": "TestPlugin",
            "version": "1.0.0",
            "description": "Test plugin for unit tests",
            "author": "Test Author",
            "type": "scanner",
            "enabled": True,
            "supported_hooks": ["pre_scan", "post_scan"]
        }

        self.assertEqual(info, expected_info)

    def test_plugin_execution(self):
        """Test plugin execution."""
        context = {"test": "data"}
        result = self.plugin.execute(PluginHook.PRE_SCAN, context)

        self.assertTrue(self.plugin.execute_called)
        self.assertIn(PluginHook.PRE_SCAN, self.plugin.execute_results)
        self.assertEqual(self.plugin.execute_results[PluginHook.PRE_SCAN], context)
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"test": "success"})


class TestPluginManager(unittest.TestCase):
    """Test PluginManager class."""

    def setUp(self):
        """Set up test plugin manager."""
        self.manager = PluginManager("test_plugins")

    def test_plugin_manager_initialization(self):
        """Test plugin manager initialization."""
        self.assertEqual(self.manager.plugin_dir, "test_plugins")
        self.assertEqual(self.manager.plugins, {})
        self.assertEqual(len(self.manager.hooks), len(PluginHook))

    def test_register_plugin(self):
        """Test plugin registration."""
        plugin = TestPlugin()
        self.manager.register_plugin(plugin)

        self.assertIn("TestPlugin", self.manager.plugins)
        self.assertEqual(self.manager.plugins["TestPlugin"], plugin)

        # Check hooks registration
        self.assertIn(plugin, self.manager.hooks[PluginHook.PRE_SCAN])
        self.assertIn(plugin, self.manager.hooks[PluginHook.POST_SCAN])

    def test_unregister_plugin(self):
        """Test plugin unregistration."""
        plugin = TestPlugin()
        self.manager.register_plugin(plugin)

        result = self.manager.unregister_plugin("TestPlugin")

        self.assertTrue(result)
        self.assertNotIn("TestPlugin", self.manager.plugins)
        self.assertNotIn(plugin, self.manager.hooks[PluginHook.PRE_SCAN])
        self.assertNotIn(plugin, self.manager.hooks[PluginHook.POST_SCAN])

    def test_unregister_nonexistent_plugin(self):
        """Test unregistering non-existent plugin."""
        result = self.manager.unregister_plugin("NonExistent")
        self.assertFalse(result)

    def test_get_plugin(self):
        """Test getting plugin by name."""
        plugin = TestPlugin()
        self.manager.register_plugin(plugin)

        retrieved_plugin = self.manager.get_plugin("TestPlugin")
        self.assertEqual(retrieved_plugin, plugin)

        non_existent = self.manager.get_plugin("NonExistent")
        self.assertIsNone(non_existent)

    def test_get_plugins_by_type(self):
        """Test getting plugins by type."""
        plugin1 = TestPlugin("Plugin1")
        plugin2 = TestPlugin("Plugin2")

        self.manager.register_plugin(plugin1)
        self.manager.register_plugin(plugin2)

        scanner_plugins = self.manager.get_plugins(PluginType.SCANNER)
        self.assertEqual(len(scanner_plugins), 2)
        self.assertIn(plugin1, scanner_plugins)
        self.assertIn(plugin2, scanner_plugins)

        analyzer_plugins = self.manager.get_plugins(PluginType.ANALYZER)
        self.assertEqual(len(analyzer_plugins), 0)

    def test_get_enabled_plugins_only(self):
        """Test getting only enabled plugins."""
        plugin1 = TestPlugin("Plugin1")
        plugin2 = TestPlugin("Plugin2")
        plugin2.disable()

        self.manager.register_plugin(plugin1)
        self.manager.register_plugin(plugin2)

        enabled_plugins = self.manager.get_plugins(enabled_only=True)
        self.assertEqual(len(enabled_plugins), 1)
        self.assertIn(plugin1, enabled_plugins)
        self.assertNotIn(plugin2, enabled_plugins)

    def test_execute_hook(self):
        """Test hook execution."""
        plugin1 = TestPlugin("Plugin1")
        plugin2 = TestPlugin("Plugin2")

        self.manager.register_plugin(plugin1)
        self.manager.register_plugin(plugin2)

        context = {"test": "data"}
        results = self.manager.execute_hook(PluginHook.PRE_SCAN, context)

        self.assertEqual(len(results), 2)
        self.assertIn("Plugin1", results)
        self.assertIn("Plugin2", results)

        self.assertTrue(results["Plugin1"].success)
        self.assertTrue(results["Plugin2"].success)

        self.assertTrue(plugin1.execute_called)
        self.assertTrue(plugin2.execute_called)

    def test_execute_hook_disabled_plugin(self):
        """Test hook execution with disabled plugin."""
        plugin1 = TestPlugin("Plugin1")
        plugin2 = TestPlugin("Plugin2")
        plugin2.disable()

        self.manager.register_plugin(plugin1)
        self.manager.register_plugin(plugin2)

        context = {"test": "data"}
        results = self.manager.execute_hook(PluginHook.PRE_SCAN, context)

        self.assertEqual(len(results), 1)
        self.assertIn("Plugin1", results)
        self.assertNotIn("Plugin2", results)

        self.assertTrue(plugin1.execute_called)
        self.assertFalse(plugin2.execute_called)

    def test_execute_hook_no_plugins(self):
        """Test hook execution with no registered plugins."""
        context = {"test": "data"}
        results = self.manager.execute_hook(PluginHook.PRE_SCAN, context)

        self.assertEqual(len(results), 0)

    def test_configure_plugin(self):
        """Test plugin configuration through manager."""
        plugin = TestPlugin()
        self.manager.register_plugin(plugin)

        config = {"setting": "value"}
        success = self.manager.configure_plugin("TestPlugin", config)

        self.assertTrue(success)
        self.assertEqual(plugin.config, config)

    def test_configure_nonexistent_plugin(self):
        """Test configuring non-existent plugin."""
        config = {"setting": "value"}
        success = self.manager.configure_plugin("NonExistent", config)

        self.assertFalse(success)

    def test_enable_disable_plugin(self):
        """Test enabling/disabling plugin through manager."""
        plugin = TestPlugin()
        self.manager.register_plugin(plugin)

        # Disable plugin
        success = self.manager.disable_plugin("TestPlugin")
        self.assertTrue(success)
        self.assertFalse(plugin.is_enabled())

        # Enable plugin
        success = self.manager.enable_plugin("TestPlugin")
        self.assertTrue(success)
        self.assertTrue(plugin.is_enabled())

    def test_enable_disable_nonexistent_plugin(self):
        """Test enabling/disabling non-existent plugin."""
        success = self.manager.enable_plugin("NonExistent")
        self.assertFalse(success)

        success = self.manager.disable_plugin("NonExistent")
        self.assertFalse(success)

    def test_get_plugin_info(self):
        """Test getting plugin information."""
        plugin1 = TestPlugin("Plugin1")
        plugin2 = TestPlugin("Plugin2")

        self.manager.register_plugin(plugin1)
        self.manager.register_plugin(plugin2)

        info_list = self.manager.get_plugin_info()

        self.assertEqual(len(info_list), 2)
        names = [info["name"] for info in info_list]
        self.assertIn("Plugin1", names)
        self.assertIn("Plugin2", names)

    @patch('os.path.exists')
    @patch('os.listdir')
    def test_discover_plugins(self, mock_listdir, mock_exists):
        """Test plugin discovery."""
        mock_exists.return_value = True
        mock_listdir.return_value = [
            'plugin1.py',
            'plugin2.py',
            '__init__.py',
            'not_plugin.txt',
            '__pycache__'
        ]

        plugins = self.manager.discover_plugins()

        expected_plugins = ['plugin1', 'plugin2']
        self.assertEqual(sorted(plugins), sorted(expected_plugins))

    @patch('os.path.exists')
    def test_discover_plugins_no_directory(self, mock_exists):
        """Test plugin discovery when directory doesn't exist."""
        mock_exists.return_value = False

        plugins = self.manager.discover_plugins()

        self.assertEqual(plugins, [])


if __name__ == "__main__":
    unittest.main()
