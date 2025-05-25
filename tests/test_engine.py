"""
Unit tests for the XSStrike scanning engine.
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any

# Add the parent directory to the path so we can import the core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import XSSEngine, ScanOptions, ScanResult, ScanMode, ScanStatus


class TestScanOptions(unittest.TestCase):
    """Test ScanOptions dataclass."""

    def test_scan_options_default_values(self):
        """Test scan options with default values."""
        options = ScanOptions(target="http://example.com")

        self.assertEqual(options.target, "http://example.com")
        self.assertEqual(options.timeout, 10)
        self.assertEqual(options.thread_count, 10)
        self.assertEqual(options.delay, 0)
        self.assertEqual(options.level, 2)
        self.assertFalse(options.proxy)
        self.assertFalse(options.json_data)
        self.assertFalse(options.path)

    def test_scan_options_custom_values(self):
        """Test scan options with custom values."""
        options = ScanOptions(
            target="http://example.com",
            timeout=30,
            thread_count=5,
            delay=1,
            proxy=True,
            json_data=True
        )

        self.assertEqual(options.target, "http://example.com")
        self.assertEqual(options.timeout, 30)
        self.assertEqual(options.thread_count, 5)
        self.assertEqual(options.delay, 1)
        self.assertTrue(options.proxy)
        self.assertTrue(options.json_data)


class TestScanResult(unittest.TestCase):
    """Test ScanResult dataclass."""

    def test_scan_result_initialization(self):
        """Test scan result initialization."""
        result = ScanResult(
            scan_id="scan_001",
            status=ScanStatus.COMPLETED,
            mode=ScanMode.SINGLE_SCAN,
            target="http://example.com"
        )

        self.assertEqual(result.scan_id, "scan_001")
        self.assertEqual(result.status, ScanStatus.COMPLETED)
        self.assertEqual(result.mode, ScanMode.SINGLE_SCAN)
        self.assertEqual(result.target, "http://example.com")
        self.assertEqual(result.vulnerabilities, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])
        self.assertEqual(result.metadata, {})

    def test_scan_result_properties(self):
        """Test scan result properties."""
        result = ScanResult(
            scan_id="scan_001",
            status=ScanStatus.COMPLETED,
            mode=ScanMode.SINGLE_SCAN,
            vulnerabilities=[{"type": "xss", "severity": "high"}],
            start_time=1000.0,
            end_time=1010.0
        )

        self.assertEqual(result.vulnerability_count, 1)
        self.assertEqual(result.duration, 10.0)
        self.assertTrue(result.success)

    def test_scan_result_failed_status(self):
        """Test scan result with failed status."""
        result = ScanResult(
            scan_id="scan_001",
            status=ScanStatus.FAILED,
            mode=ScanMode.SINGLE_SCAN
        )

        self.assertFalse(result.success)


class TestXSSEngine(unittest.TestCase):
    """Test XSSEngine class."""

    def setUp(self):
        """Set up test engine."""
        with patch('core.engine.plugin_manager'), \
                patch('core.engine.reader') as mock_reader, \
                patch('core.config'):
            mock_reader.return_value = ['{"test": "data"}']
            self.engine = XSSEngine()

    def test_engine_initialization(self):
        """Test engine initialization."""
        self.assertIsNotNone(self.engine)
        self.assertEqual(self.engine._scan_counter, 0)
        self.assertEqual(self.engine._active_scans, {})

    def test_generate_scan_id(self):
        """Test scan ID generation."""
        scan_id1 = self.engine._generate_scan_id()
        scan_id2 = self.engine._generate_scan_id()

        self.assertEqual(scan_id1, "scan_000001")
        self.assertEqual(scan_id2, "scan_000002")
        self.assertNotEqual(scan_id1, scan_id2)

    def test_create_scan(self):
        """Test scan creation."""
        options = ScanOptions(target="http://example.com")
        scan_id = self.engine.create_scan(options)

        self.assertIn(scan_id, self.engine._active_scans)
        result = self.engine._active_scans[scan_id]
        self.assertEqual(result.target, "http://example.com")
        self.assertEqual(result.status, ScanStatus.NOT_STARTED)

    def test_determine_scan_mode_single(self):
        """Test scan mode determination for single scan."""
        options = ScanOptions(target="http://example.com")
        mode = self.engine._determine_scan_mode(options)
        self.assertEqual(mode, ScanMode.SINGLE_SCAN)

    def test_determine_scan_mode_path(self):
        """Test scan mode determination for path injection."""
        options = ScanOptions(target="http://example.com", path=True)
        mode = self.engine._determine_scan_mode(options)
        self.assertEqual(mode, ScanMode.SINGLE_SCAN)

    def test_determine_scan_mode_json(self):
        """Test scan mode determination for JSON injection."""
        options = ScanOptions(target="http://example.com", json_data=True)
        mode = self.engine._determine_scan_mode(options)
        self.assertEqual(mode, ScanMode.SINGLE_SCAN)

    def test_determine_scan_mode_bruteforce(self):
        """Test scan mode determination for bruteforce."""
        options = ScanOptions(target="http://example.com", payloads_file="payloads.txt")
        mode = self.engine._determine_scan_mode(options)
        self.assertEqual(mode, ScanMode.BRUTEFORCE)

    def test_determine_scan_mode_crawler(self):
        """Test scan mode determination for crawler."""
        options = ScanOptions(target="http://example.com", level=3)
        mode = self.engine._determine_scan_mode(options)
        self.assertEqual(mode, ScanMode.CRAWLER)

    def test_get_scan_result(self):
        """Test getting scan result."""
        options = ScanOptions(target="http://example.com")
        scan_id = self.engine.create_scan(options)

        result = self.engine.get_scan_result(scan_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.scan_id, scan_id)

        # Test non-existent scan
        result = self.engine.get_scan_result("non_existent")
        self.assertIsNone(result)

    def test_list_scans(self):
        """Test listing scans."""
        options1 = ScanOptions(target="http://example1.com")
        options2 = ScanOptions(target="http://example2.com")

        scan_id1 = self.engine.create_scan(options1)
        scan_id2 = self.engine.create_scan(options2)

        scans = self.engine.list_scans()
        self.assertEqual(len(scans), 2)

        scan_ids = [scan.scan_id for scan in scans]
        self.assertIn(scan_id1, scan_ids)
        self.assertIn(scan_id2, scan_ids)

    def test_cancel_scan(self):
        """Test scan cancellation."""
        options = ScanOptions(target="http://example.com")
        scan_id = self.engine.create_scan(options)

        # Set scan to running status
        self.engine._active_scans[scan_id].status = ScanStatus.RUNNING

        success = self.engine.cancel_scan(scan_id)
        self.assertTrue(success)
        self.assertEqual(self.engine._active_scans[scan_id].status, ScanStatus.INTERRUPTED)

        # Test cancelling non-existent scan
        success = self.engine.cancel_scan("non_existent")
        self.assertFalse(success)

        # Test cancelling completed scan
        self.engine._active_scans[scan_id].status = ScanStatus.COMPLETED
        success = self.engine.cancel_scan(scan_id)
        self.assertFalse(success)

    def test_cleanup_scan(self):
        """Test scan cleanup."""
        options = ScanOptions(target="http://example.com")
        scan_id = self.engine.create_scan(options)

        self.assertIn(scan_id, self.engine._active_scans)

        success = self.engine.cleanup_scan(scan_id)
        self.assertTrue(success)
        self.assertNotIn(scan_id, self.engine._active_scans)

        # Test cleaning up non-existent scan
        success = self.engine.cleanup_scan("non_existent")
        self.assertFalse(success)

    @patch('core.engine.scan')
    def test_execute_single_scan(self, mock_scan):
        """Test single scan execution."""
        options = ScanOptions(target="http://example.com", param_data="test=value")
        scan_id = self.engine.create_scan(options)

        result = self.engine.execute_scan(scan_id, options)

        self.assertEqual(result.status, ScanStatus.COMPLETED)
        mock_scan.assert_called_once()

    @patch('core.engine.singleFuzz')
    def test_execute_fuzzer_scan(self, mock_fuzz):
        """Test fuzzer scan execution."""
        options = ScanOptions(target="http://example.com")
        setattr(options, 'fuzz', True)
        scan_id = self.engine.create_scan(options)

        # Manually set mode to fuzzer for this test
        self.engine._active_scans[scan_id].mode = ScanMode.FUZZER

        result = self.engine.execute_scan(scan_id, options)

        self.assertEqual(result.status, ScanStatus.COMPLETED)
        mock_fuzz.assert_called_once()

    @patch('core.engine.reader')
    @patch('core.engine.bruteforcer')
    def test_execute_bruteforce_scan(self, mock_bruteforcer, mock_reader):
        """Test bruteforce scan execution."""
        mock_reader.return_value = ['payload1', 'payload2', 'payload3']

        options = ScanOptions(target="http://example.com", payloads_file="payloads.txt")
        scan_id = self.engine.create_scan(options)

        result = self.engine.execute_scan(scan_id, options)

        self.assertEqual(result.status, ScanStatus.COMPLETED)
        mock_bruteforcer.assert_called_once()
        mock_reader.assert_called_with("payloads.txt")

    def test_execute_scan_with_exception(self):
        """Test scan execution with exception."""
        options = ScanOptions(target="http://example.com")
        scan_id = self.engine.create_scan(options)

        with patch('core.engine.scan', side_effect=Exception("Test error")):
            result = self.engine.execute_scan(scan_id, options)

        self.assertEqual(result.status, ScanStatus.FAILED)
        self.assertIn("Test error", result.errors)

    def test_execute_scan_with_keyboard_interrupt(self):
        """Test scan execution with keyboard interrupt."""
        options = ScanOptions(target="http://example.com")
        scan_id = self.engine.create_scan(options)

        with patch('core.engine.scan', side_effect=KeyboardInterrupt()):
            result = self.engine.execute_scan(scan_id, options)

        self.assertEqual(result.status, ScanStatus.INTERRUPTED)

    def test_execute_scan_invalid_id(self):
        """Test executing scan with invalid ID."""
        options = ScanOptions(target="http://example.com")

        with self.assertRaises(ValueError):
            self.engine.execute_scan("invalid_id", options)


if __name__ == "__main__":
    unittest.main()
