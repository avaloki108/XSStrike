"""
XSStrike Core Scanning Engine.

This module provides the core scanning functionality separated from UI logic,
enabling different interfaces (CLI, API, GUI) to use the same scanning engine.
"""

import json
import sys
import concurrent.futures
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from core.config import blindPayload
from core.encoders import base64
from core.photon import photon
from core.utils import extractHeaders, reader, converter
from core.plugin_manager import plugin_manager
from core.log import setup_logger
# from core.ai_integration import intelligent_orchestrator  # AI INTEGRATION - MOVED TO AVOID CIRCULAR IMPORT

from modes.bruteforcer import bruteforcer
from modes.crawl import crawl
from modes.scan import scan
from modes.singleFuzz import singleFuzz

logger = setup_logger(__name__)


class ScanMode(Enum):
    """Enumeration of available scanning modes."""
    SINGLE_SCAN = "single_scan"
    FUZZER = "fuzzer"
    BRUTEFORCE = "bruteforce"
    CRAWLER = "crawler"


class ScanStatus(Enum):
    """Enumeration of scan status values."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass
class ScanOptions:
    """Configuration options for a scan."""
    target: Optional[str] = None
    param_data: Optional[str] = None
    encode: Optional[str] = None
    timeout: int = 10
    proxy: bool = False
    json_data: bool = False
    path: bool = False
    seeds_file: Optional[str] = None
    payloads_file: Optional[str] = None
    level: int = 2
    headers: Optional[Dict[str, str]] = None
    thread_count: int = 10
    delay: int = 0
    skip: bool = False
    skip_dom: bool = False
    blind_xss: bool = False
    blind_payload: Optional[str] = None
    verify_ssl: bool = False
    ssl_cert_path: Optional[str] = None
    ai_enabled: bool = False  # AI INTEGRATION
    ai_learning_mode: bool = True  # AI INTEGRATION
    ai_confidence_threshold: float = 0.5  # AI INTEGRATION


@dataclass
class ScanResult:
    """Container for scan results."""
    scan_id: str
    status: ScanStatus
    mode: ScanMode
    target: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = None
    forms_found: int = 0
    urls_processed: int = 0
    requests_made: int = 0
    errors: List[str] = None
    warnings: List[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.metadata is None:
            self.metadata = {}

    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None

    @property
    def vulnerability_count(self) -> int:
        """Get total number of vulnerabilities found."""
        return len(self.vulnerabilities)

    @property
    def success(self) -> bool:
        """Check if scan completed successfully."""
        return self.status == ScanStatus.COMPLETED


class XSSEngine:
    """
    Core XSS scanning engine without UI dependencies.
    
    This class provides the main scanning functionality that can be used
    by different interfaces (CLI, API, GUI) without coupling to any specific UI.
    """

    def __init__(self):
        self.logger = setup_logger(__name__)
        self._scan_counter = 0
        self._active_scans: Dict[str, ScanResult] = {}
        self._initialize_engine()

    def _initialize_engine(self) -> None:
        """Initialize the scanning engine."""
        try:
            # Initialize plugin system
            plugin_manager.load_all_plugins()
            plugin_info = plugin_manager.get_plugin_info()

            if plugin_info:
                self.logger.info(f"Loaded {len(plugin_info)} plugins")
                for plugin in plugin_info:
                    status = "enabled" if plugin["enabled"] else "disabled"
                    self.logger.debug(f"  - {plugin['name']} v{plugin['version']} ({status})")

            # Load definitions
            definitions_path = "db/definitions.json"
            definitions_data = "\n".join(reader(definitions_path))

            # Store in core config for backward compatibility
            import core.config
            core.config.globalVariables = core.config.globalVariables or {}
            core.config.globalVariables["definitions"] = json.loads(definitions_data)
            core.config.globalVariables["checkedScripts"] = set()
            core.config.globalVariables["checkedForms"] = {}

            self.logger.info("XSS Engine initialized successfully")

        except Exception as e:
            self.logger.error(f"Engine initialization failed: {str(e)}")
            raise

    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        self._scan_counter += 1
        return f"scan_{self._scan_counter:06d}"

    def _prepare_scan_options(self, options: ScanOptions) -> ScanOptions:
        """Prepare and validate scan options."""
        # Set default headers if not provided
        if options.headers is None:
            from core.config import headers as default_headers
            options.headers = default_headers.copy()

        # Handle encoding
        if options.encode == "base64":
            options.encode = base64
        else:
            options.encode = False

        # Set default blind payload if not provided
        if options.blind_xss and not options.blind_payload:
            options.blind_payload = blindPayload

        return options

    def _determine_scan_mode(self, options: ScanOptions) -> ScanMode:
        """Determine the appropriate scan mode based on options."""
        if options.path or options.json_data:
            # Path or JSON injection
            return ScanMode.SINGLE_SCAN
        elif hasattr(options, 'fuzz') and getattr(options, 'fuzz', False):
            # Fuzzer mode (would need to be added to ScanOptions)
            return ScanMode.FUZZER
        elif options.payloads_file:
            return ScanMode.BRUTEFORCE
        elif options.seeds_file or options.level > 2:
            return ScanMode.CRAWLER
        else:
            return ScanMode.SINGLE_SCAN

    def create_scan(self, options: ScanOptions) -> str:
        """
        Create a new scan with the given options.
        
        Args:
            options: Scan configuration options
            
        Returns:
            str: Unique scan ID
        """
        scan_id = self._generate_scan_id()
        mode = self._determine_scan_mode(options)

        scan_result = ScanResult(
            scan_id=scan_id,
            status=ScanStatus.NOT_STARTED,
            mode=mode,
            target=options.target
        )

        self._active_scans[scan_id] = scan_result
        self.logger.info(f"Created scan {scan_id} for target: {options.target}")

        return scan_id

    def execute_scan(self, scan_id: str, options: ScanOptions) -> ScanResult:
        """
        Execute a scan synchronously.
        
        Args:
            scan_id: Unique scan identifier
            options: Scan configuration options
            
        Returns:
            ScanResult: Scan results
        """
        if scan_id not in self._active_scans:
            raise ValueError(f"Scan ID {scan_id} not found")

        scan_result = self._active_scans[scan_id]

        try:
            import time
            scan_result.start_time = time.time()
            scan_result.status = ScanStatus.RUNNING

            # Prepare options
            options = self._prepare_scan_options(options)

            # Update core config for backward compatibility
            import core.config
            core.config.globalVariables.update({
                "headers": options.headers,
                "delay": options.delay,
                "timeout": options.timeout,
                "threadCount": options.thread_count,
                "ai_enabled": options.ai_enabled if hasattr(options, 'ai_enabled') else False  # AI INTEGRATION
            })

            # AI-driven scan if enabled
            if core.config.globalVariables.get("ai_enabled"):
                self.logger.info("Executing AI-enhanced scan")
                from core.ai_integration import \
                    intelligent_orchestrator  # AI INTEGRATION - MOVED TO AVOID CIRCULAR IMPORT
                intelligent_config = intelligent_orchestrator.prepare_intelligent_scan(options)
                ai_results = intelligent_orchestrator.execute_intelligent_scan(intelligent_config)

                # Populate scan_result from ai_results (simplified for now)
                scan_result.vulnerabilities = ai_results.get('vulnerabilities', [])
                scan_result.forms_found = ai_results.get('target', {}).get('forms_found', 0)
                scan_result.urls_processed = ai_results.get('target', {}).get('urls_processed', 0)
                scan_result.requests_made = ai_results.get('scan_statistics', {}).get('total_payloads_tested', 0)
                scan_result.metadata['ai_analysis'] = ai_results.get('rag_analysis', {}).get('intelligence_summary', {})
                scan_result.metadata['ai_strategy'] = ai_results.get('scan_strategy', {})

            # Execute based on scan mode (standard scan if AI disabled or for specific modes not fully AI-driven yet)
            elif scan_result.mode == ScanMode.FUZZER:
                self._execute_fuzzer_scan(scan_result, options)
            elif scan_result.mode == ScanMode.BRUTEFORCE:
                self._execute_bruteforce_scan(scan_result, options)
            elif scan_result.mode == ScanMode.CRAWLER:
                self._execute_crawler_scan(scan_result, options)
            else:  # SINGLE_SCAN or if AI is off
                self._execute_single_scan(scan_result, options)

            scan_result.end_time = time.time()
            scan_result.status = ScanStatus.COMPLETED
            self.logger.info(f"Scan {scan_id} completed successfully")

        except KeyboardInterrupt:
            scan_result.status = ScanStatus.INTERRUPTED
            self.logger.warning(f"Scan {scan_id} was interrupted")
        except Exception as e:
            scan_result.status = ScanStatus.FAILED
            scan_result.errors.append(str(e))
            self.logger.error(f"Scan {scan_id} failed: {str(e)}")

        return scan_result

    def _execute_single_scan(self, scan_result: ScanResult, options: ScanOptions) -> None:
        """Execute a single target scan."""
        target = options.target
        param_data = options.param_data

        # Handle path and JSON data
        if options.path:
            param_data = converter(target, target)
        elif options.json_data:
            options.headers["Content-type"] = "application/json"
            param_data = converter(param_data)

        # Execute scan
        scan(
            target, param_data, options.encode, options.headers,
            options.delay, options.timeout, options.skip_dom, options.skip
        )

        scan_result.requests_made = 1  # Basic counting

    def _execute_fuzzer_scan(self, scan_result: ScanResult, options: ScanOptions) -> None:
        """Execute fuzzer scan."""
        singleFuzz(
            options.target, options.param_data, options.encode,
            options.headers, options.delay, options.timeout
        )

        scan_result.requests_made = 1  # Basic counting

    def _execute_bruteforce_scan(self, scan_result: ScanResult, options: ScanOptions) -> None:
        """Execute bruteforce scan."""
        # Load payloads
        if options.payloads_file == "default":
            from core.config import payloads as payload_list
        else:
            payload_list = list(filter(None, reader(options.payloads_file)))

        bruteforcer(
            options.target, options.param_data, payload_list,
            options.encode, options.headers, options.delay, options.timeout
        )

        scan_result.requests_made = len(payload_list)

    def _execute_crawler_scan(self, scan_result: ScanResult, options: ScanOptions) -> None:
        """Execute crawler scan."""
        # Prepare seed list
        seed_list = []
        if options.target:
            seed_list.append(options.target)
        if options.seeds_file:
            seed_list.extend(list(filter(None, reader(options.seeds_file))))

        total_forms = 0
        total_urls = 0

        for target in seed_list:
            self.logger.info(f"Crawling target: {target}")

            scheme = urlparse(target).scheme
            host = urlparse(target).netloc
            main_url = scheme + "://" + host

            # Execute crawling
            crawling_result = photon(
                target, options.headers, options.level,
                options.thread_count, options.delay, options.timeout, options.skip_dom
            )

            forms = crawling_result[0]
            dom_urls = list(crawling_result[1])

            total_forms += len(forms)
            total_urls += len(dom_urls)

            # Balance forms and URLs
            difference = abs(len(dom_urls) - len(forms))
            if len(dom_urls) > len(forms):
                for i in range(difference):
                    forms.append(0)
            elif len(forms) > len(dom_urls):
                for i in range(difference):
                    dom_urls.append(0)

            # Execute crawl scanning
            threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=options.thread_count)
            futures = (
                threadpool.submit(
                    crawl,
                    scheme, host, main_url, form,
                    options.blind_xss, options.blind_payload,
                    options.headers, options.delay, options.timeout, options.encode
                )
                for form, dom_url in zip(forms, dom_urls)
            )

            completed = 0
            for _ in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % options.thread_count == 0 or completed == len(forms):
                    self.logger.debug(f"Progress: {completed}/{len(forms)}")

        scan_result.forms_found = total_forms
        scan_result.urls_processed = total_urls
        scan_result.requests_made = total_forms

    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """
        Get scan result by ID.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            Optional[ScanResult]: Scan result or None if not found
        """
        return self._active_scans.get(scan_id)

    def list_scans(self) -> List[ScanResult]:
        """
        List all scans.
        
        Returns:
            List[ScanResult]: List of all scan results
        """
        return list(self._active_scans.values())

    def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            bool: True if scan was cancelled successfully
        """
        if scan_id not in self._active_scans:
            return False

        scan_result = self._active_scans[scan_id]
        if scan_result.status == ScanStatus.RUNNING:
            scan_result.status = ScanStatus.INTERRUPTED
            self.logger.info(f"Scan {scan_id} cancelled")
            return True

        return False

    def cleanup_scan(self, scan_id: str) -> bool:
        """
        Remove scan from active scans.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            bool: True if scan was removed successfully
        """
        if scan_id in self._active_scans:
            del self._active_scans[scan_id]
            return True
        return False


# Global engine instance
engine = XSSEngine()
