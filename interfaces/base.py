"""
Base Interface for XSStrike.

This module provides the base interface class that all UI implementations
should inherit from, ensuring consistent behavior across different interfaces.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from core.engine import XSSEngine, ScanOptions, ScanResult


class BaseInterface(ABC):
    """
    Abstract base class for XSStrike interfaces.
    
    This class defines the common interface that all UI implementations
    (CLI, API, GUI) should implement.
    """

    def __init__(self, engine: Optional[XSSEngine] = None):
        """
        Initialize the interface.
        
        Args:
            engine: XSS scanning engine instance
        """
        self.engine = engine or XSSEngine()

    @abstractmethod
    def initialize(self) -> None:
        """Initialize the interface (setup, configuration, etc.)."""
        pass

    @abstractmethod
    def run(self) -> None:
        """Start the interface main loop."""
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Cleanup and shutdown the interface."""
        pass

    @abstractmethod
    def handle_scan_request(self, options: ScanOptions) -> str:
        """
        Handle a scan request.
        
        Args:
            options: Scan configuration options
            
        Returns:
            str: Scan ID
        """
        pass

    @abstractmethod
    def handle_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """
        Handle scan status request.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            Optional[ScanResult]: Scan result or None if not found
        """
        pass

    @abstractmethod
    def handle_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Handle scan results request.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            Optional[Dict[str, Any]]: Formatted scan results
        """
        pass

    @abstractmethod
    def handle_list_scans(self) -> List[Dict[str, Any]]:
        """
        Handle list scans request.
        
        Returns:
            List[Dict[str, Any]]: List of scan summaries
        """
        pass

    @abstractmethod
    def handle_cancel_scan(self, scan_id: str) -> bool:
        """
        Handle scan cancellation request.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            bool: True if scan was cancelled successfully
        """
        pass

    @abstractmethod
    def display_error(self, message: str, error: Optional[Exception] = None) -> None:
        """
        Display an error message.
        
        Args:
            message: Error message
            error: Optional exception object
        """
        pass

    @abstractmethod
    def display_info(self, message: str) -> None:
        """
        Display an informational message.
        
        Args:
            message: Information message
        """
        pass

    @abstractmethod
    def display_warning(self, message: str) -> None:
        """
        Display a warning message.
        
        Args:
            message: Warning message
        """
        pass

    def format_scan_summary(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Format scan result into summary dictionary.
        
        Args:
            scan_result: Scan result object
            
        Returns:
            Dict[str, Any]: Formatted scan summary
        """
        return {
            "scan_id": scan_result.scan_id,
            "status": scan_result.status.value,
            "mode": scan_result.mode.value,
            "target": scan_result.target,
            "vulnerability_count": scan_result.vulnerability_count,
            "forms_found": scan_result.forms_found,
            "urls_processed": scan_result.urls_processed,
            "requests_made": scan_result.requests_made,
            "duration": scan_result.duration,
            "errors": len(scan_result.errors),
            "warnings": len(scan_result.warnings)
        }

    def format_detailed_results(self, scan_result: ScanResult) -> Dict[str, Any]:
        """
        Format scan result into detailed dictionary.
        
        Args:
            scan_result: Scan result object
            
        Returns:
            Dict[str, Any]: Formatted detailed results
        """
        summary = self.format_scan_summary(scan_result)
        summary.update({
            "vulnerabilities": scan_result.vulnerabilities,
            "error_messages": scan_result.errors,
            "warning_messages": scan_result.warnings,
            "start_time": scan_result.start_time,
            "end_time": scan_result.end_time,
            "metadata": scan_result.metadata
        })
        return summary
