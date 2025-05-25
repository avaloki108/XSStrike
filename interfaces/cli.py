"""
Command-Line Interface for XSStrike.

This module provides the CLI implementation that handles command-line arguments,
user interaction, and output formatting while using the core engine for scanning.
"""

import sys
import json
import argparse
from typing import Dict, List, Any, Optional

from interfaces.base import BaseInterface
from core.engine import XSSEngine, ScanOptions, ScanResult, ScanMode
from core.colors import end, red, white, bad, info
from core.prompt import prompt
from core.utils import extractHeaders, reader
from core.updater import updater
from core.log import setup_logger
import core.config
import core.log


class CLIInterface(BaseInterface):
    """
    Command-Line Interface for XSStrike.
    
    This class handles all CLI-specific functionality including argument parsing,
    user interaction, and output formatting.
    """

    def __init__(self, engine: Optional[XSSEngine] = None):
        super().__init__(engine)
        self.logger = setup_logger(__name__)
        self.args = None
        self.parser = None

    def initialize(self) -> None:
        """Initialize the CLI interface."""
        self._print_banner()
        self._check_dependencies()
        self._setup_argument_parser()
        self._parse_arguments()
        self._setup_configuration()
        self._setup_logging()

    def run(self) -> None:
        """Run the CLI interface."""
        try:
            # Handle special cases first
            if self.args.update:
                updater()
                sys.exit(0)

            if not self.args.target and not self.args.args_seeds:
                self.display_error("No target URL or seeds file provided")
                print("\n" + self.parser.format_help().lower())
                sys.exit(1)

            # Create scan options from CLI arguments
            options = self._create_scan_options()

            # Execute scan
            scan_id = self.handle_scan_request(options)
            result = self.engine.get_scan_result(scan_id)

            if result and result.success:
                self.display_info(f"Scan completed successfully")
                self._display_scan_summary(result)
            elif result:
                self.display_error(f"Scan failed: {'; '.join(result.errors)}")
            else:
                self.display_error("Scan result not found")

        except KeyboardInterrupt:
            self.display_info("\nScan interrupted by user")
            sys.exit(0)
        except Exception as e:
            self.display_error(f"Unexpected error: {str(e)}", e)
            sys.exit(1)

    def shutdown(self) -> None:
        """Shutdown the CLI interface."""
        # Cleanup any resources if needed
        pass

    def handle_scan_request(self, options: ScanOptions) -> str:
        """Handle a scan request from CLI."""
        scan_id = self.engine.create_scan(options)
        result = self.engine.execute_scan(scan_id, options)
        return scan_id

    def handle_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """Handle scan status request."""
        return self.engine.get_scan_result(scan_id)

    def handle_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Handle scan results request."""
        result = self.engine.get_scan_result(scan_id)
        if result:
            return self.format_detailed_results(result)
        return None

    def handle_list_scans(self) -> List[Dict[str, Any]]:
        """Handle list scans request."""
        scans = self.engine.list_scans()
        return [self.format_scan_summary(scan) for scan in scans]

    def handle_cancel_scan(self, scan_id: str) -> bool:
        """Handle scan cancellation request."""
        return self.engine.cancel_scan(scan_id)

    def display_error(self, message: str, error: Optional[Exception] = None) -> None:
        """Display an error message."""
        print(f"{bad} {message}")
        if error and self.logger:
            self.logger.error(f"{message}: {str(error)}")

    def display_info(self, message: str) -> None:
        """Display an informational message."""
        print(f"{info} {message}")
        if self.logger:
            self.logger.info(message)

    def display_warning(self, message: str) -> None:
        """Display a warning message."""
        print(f"{info} Warning: {message}")
        if self.logger:
            self.logger.warning(message)

    def _print_banner(self) -> None:
        """Print the XSStrike banner."""
        print(f"""{red}
\tXSStrike {white}v3.1.5
{end}""")

    def _check_dependencies(self) -> None:
        """Check and install required dependencies."""
        try:
            import concurrent.futures
            from urllib.parse import urlparse

            try:
                import fuzzywuzzy
            except ImportError:
                import os
                print(f"{info} fuzzywuzzy isn't installed, installing now.")
                ret_code = os.system("pip3 install fuzzywuzzy")
                if ret_code != 0:
                    print(f"{bad} fuzzywuzzy installation failed.")
                    sys.exit(1)
                print(f"{info} fuzzywuzzy has been installed, restart XSStrike.")
                sys.exit(0)

        except ImportError:
            print(f"{bad} XSStrike isn't compatible with python2.\n Use python > 3.4 to run XSStrike.")
            sys.exit(1)

    def _setup_argument_parser(self) -> None:
        """Setup command-line argument parser with improved help and examples."""
        self.parser = argparse.ArgumentParser(
            description="""
XSStrike - Advanced XSS Detection Suite v3.1.5

A powerful tool for detecting Cross-Site Scripting (XSS) vulnerabilities with 
AI-enhanced scanning capabilities, intelligent payload selection, and comprehensive
crawling functionality.

Key Features:
  • Intelligent payload generation with machine learning
  • Advanced WAF bypass techniques  
  • Comprehensive crawling with DOM analysis
  • Multiple scanning modes (fuzzer, crawler, targeted)
  • AI-powered vulnerability pattern recognition
  • Customizable scanning parameters and headers
            """.strip(),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
EXAMPLES:

Basic Usage:
  python xsstrike.py -u "http://example.com/search?q=test"
    Simple XSS scan on a single URL with GET parameters

  python xsstrike.py -u "http://example.com/login" --data "user=admin&pass=123"  
    POST data scan with form parameters

Advanced Scanning:
  python xsstrike.py -u "http://example.com" --crawl -l 3 -t 10
    Comprehensive crawl scan with 3 levels deep using 10 threads

  python xsstrike.py -u "http://example.com" --fuzzer --ai-scan
    AI-enhanced fuzzer mode with intelligent payload selection

  python xsstrike.py -u "https://example.com" --verify-ssl --proxy
    Secure scan with SSL verification and proxy support

Blind XSS Testing:
  python xsstrike.py -u "http://example.com/contact" --blind 
    Enable blind XSS detection with default payload

  python xsstrike.py -u "http://example.com" --blind --blind-payload "custom_payload"
    Use custom blind XSS payload

File-based Operations:
  python xsstrike.py --seeds urls.txt --crawl -l 2
    Crawl multiple URLs from file with 2 levels deep

  python xsstrike.py -u "http://example.com" -f payloads.txt
    Use custom payloads from file

Advanced Configuration:
  python xsstrike.py -u "http://example.com" --headers "Cookie: session=abc123"
    Add custom headers to requests

  python xsstrike.py -u "http://example.com" --timeout 30 --delay 2
    Set custom timeout and delay between requests

  python xsstrike.py -u "http://example.com" --config custom.json
    Use custom configuration file

Logging and Output:
  python xsstrike.py -u "http://example.com" --console-log-level INFO
    Set console logging level to INFO

  python xsstrike.py -u "http://example.com" --log-file scan.log --file-log-level DEBUG
    Save detailed logs to file

AI/RAG Enhanced Scanning:
  python xsstrike.py -u "http://example.com" --ai-scan --ai-threshold 0.7
    Use AI with high confidence threshold for payload selection

  python xsstrike.py -u "http://example.com" --ai-scan --ai-no-learn
    Run AI scan without learning from results

System Operations:
  python xsstrike.py --update
    Update XSStrike to the latest version

For more information and advanced usage, visit: https://github.com/s0md3v/XSStrike
            """
        )

        # === TARGET OPTIONS ===
        target_group = self.parser.add_argument_group(
            "Target Options",
            "Specify the target URL and related parameters"
        )
        target_group.add_argument(
            "-u", "--url",
            help="Target URL to scan (required unless using --seeds)",
            dest="target",
            metavar="URL"
        )
        target_group.add_argument(
            "--data",
            help="POST data parameters (e.g., 'param1=value1&param2=value2')",
            dest="paramData",
            metavar="DATA"
        )
        target_group.add_argument(
            "--seeds",
            help="Load multiple target URLs from file (one URL per line)",
            dest="args_seeds",
            metavar="FILE"
        )

        # === SCANNING MODES ===
        mode_group = self.parser.add_argument_group(
            "Scanning Modes",
            "Choose the scanning approach and methodology"
        )
        mode_group.add_argument(
            "--fuzzer",
            help="Enable fuzzer mode for comprehensive payload testing",
            dest="fuzz",
            action="store_true"
        )
        mode_group.add_argument(
            "--crawl",
            help="Enable crawler mode to discover and test forms automatically",
            dest="recursive",
            action="store_true"
        )
        mode_group.add_argument(
            "-f", "--file",
            help="Load custom payloads from file (one payload per line)",
            dest="args_file",
            metavar="FILE"
        )

        # === DATA HANDLING ===
        data_group = self.parser.add_argument_group(
            "Data Handling",
            "Configure how data is processed and encoded"
        )
        data_group.add_argument(
            "-e", "--encode",
            help="Encode payloads using specified method (url, html, base64)",
            dest="encode",
            choices=["url", "html", "base64"],
            metavar="METHOD"
        )
        data_group.add_argument(
            "--json",
            help="Treat POST data as JSON format",
            dest="jsonData",
            action="store_true"
        )
        data_group.add_argument(
            "--path",
            help="Inject payloads in URL path instead of parameters",
            dest="path",
            action="store_true"
        )

        # === NETWORK OPTIONS ===
        network_group = self.parser.add_argument_group(
            "Network Configuration",
            "Control network behavior and security settings"
        )
        network_group.add_argument(
            "--timeout",
            help="Request timeout in seconds (default: %(default)s)",
            dest="timeout",
            type=int,
            default=core.config.timeout,
            metavar="SECONDS"
        )
        network_group.add_argument(
            "--proxy",
            help="Use system proxy settings for requests",
            dest="proxy",
            action="store_true"
        )
        network_group.add_argument(
            "--verify-ssl",
            help="Enable SSL certificate verification (default: disabled for testing)",
            dest="verify_ssl",
            action="store_true"
        )
        network_group.add_argument(
            "--ssl-cert",
            help="Path to custom SSL certificate file",
            dest="ssl_cert_path",
            metavar="PATH"
        )

        # === CRAWLING OPTIONS ===
        crawl_group = self.parser.add_argument_group(
            "Crawling Configuration",
            "Fine-tune the web crawling behavior"
        )
        crawl_group.add_argument(
            "-l", "--level",
            help="Crawling depth level (default: %(default)s)",
            dest="level",
            type=int,
            default=2,
            metavar="DEPTH"
        )
        crawl_group.add_argument(
            "-t", "--threads",
            help="Number of concurrent threads (default: %(default)s)",
            dest="threadCount",
            type=int,
            default=core.config.threadCount,
            metavar="COUNT"
        )
        crawl_group.add_argument(
            "-d", "--delay",
            help="Delay between requests in seconds (default: %(default)s)",
            dest="delay",
            type=int,
            default=core.config.delay,
            metavar="SECONDS"
        )

        # === BEHAVIOR OPTIONS ===
        behavior_group = self.parser.add_argument_group(
            "Behavior Control",
            "Modify scanning behavior and analysis options"
        )
        behavior_group.add_argument(
            "--skip",
            help="Skip confirmation prompts and run non-interactively",
            dest="skip",
            action="store_true"
        )
        behavior_group.add_argument(
            "--skip-dom",
            help="Skip DOM-based XSS analysis (faster but less thorough)",
            dest="skipDOM",
            action="store_true"
        )

        # === BLIND XSS OPTIONS ===
        blind_group = self.parser.add_argument_group(
            "Blind XSS Detection",
            "Configure blind/out-of-band XSS testing"
        )
        blind_group.add_argument(
            "--blind",
            help="Enable blind XSS detection with callback monitoring",
            dest="blindXSS",
            action="store_true"
        )
        blind_group.add_argument(
            "--blind-payload",
            help="Custom blind XSS payload with callback URL",
            dest="blind_payload",
            metavar="PAYLOAD"
        )

        # === HEADERS ===
        headers_group = self.parser.add_argument_group(
            "HTTP Headers",
            "Configure custom HTTP headers for requests"
        )
        headers_group.add_argument(
            "--headers",
            help="Add custom HTTP headers (format: 'Header1: value1\\nHeader2: value2')",
            dest="add_headers",
            nargs="?",
            const=True,
            metavar="HEADERS"
        )

        # === CONFIGURATION ===
        config_group = self.parser.add_argument_group(
            "Configuration",
            "Load external configuration and customize settings"
        )
        config_group.add_argument(
            "--config",
            help="Path to JSON configuration file",
            dest="config_file",
            metavar="FILE"
        )

        # === LOGGING ===
        log_group = self.parser.add_argument_group(
            "Logging Options",
            "Control output verbosity and log file generation"
        )
        log_group.add_argument(
            "--console-log-level",
            help="Console output verbosity level (default: %(default)s)",
            dest="console_log_level",
            default=core.log.console_log_level,
            choices=list(core.log.log_config.keys()),
            metavar="LEVEL"
        )
        log_group.add_argument(
            "--file-log-level",
            help="File logging verbosity level",
            dest="file_log_level",
            choices=list(core.log.log_config.keys()),
            metavar="LEVEL"
        )
        log_group.add_argument(
            "--log-file",
            help="Path to log file (default: %(default)s)",
            dest="log_file",
            default=core.log.log_file,
            metavar="FILE"
        )

        # === AI/RAG OPTIONS ===
        ai_group = self.parser.add_argument_group(
            "AI/RAG Enhancement",
            "Artificial Intelligence and Retrieval-Augmented Generation features"
        )
        ai_group.add_argument(
            "--ai-scan",
            help="Enable AI-enhanced scanning with intelligent payload selection",
            dest="ai_enabled",
            action="store_true"
        )
        ai_group.add_argument(
            "--ai-no-learn",
            help="Disable AI learning from this scan session",
            dest="ai_learning_mode",
            action="store_false"
        )
        ai_group.add_argument(
            "--ai-threshold",
            help="AI confidence threshold for payload selection (0.0-1.0, default: %(default)s)",
            dest="ai_confidence_threshold",
            type=float,
            default=0.5,
            metavar="FLOAT"
        )

        # === SYSTEM ===
        system_group = self.parser.add_argument_group(
            "System Operations",
            "System maintenance and update operations"
        )
        system_group.add_argument(
            "--update",
            help="Update XSStrike to the latest version from repository",
            dest="update",
            action="store_true"
        )

    def _parse_arguments(self) -> None:
        """Parse command-line arguments with improved error handling."""
        try:
            self.args = self.parser.parse_args()

            # Validate required arguments
            if not self.args.target and not self.args.args_seeds and not self.args.update:
                self.parser.error("At least one of --url, --seeds, or --update is required")

            # Validate AI threshold range
            if hasattr(self.args, 'ai_confidence_threshold'):
                if not 0.0 <= self.args.ai_confidence_threshold <= 1.0:
                    self.parser.error("AI confidence threshold must be between 0.0 and 1.0")

            # Validate numeric arguments
            if self.args.level < 1:
                self.parser.error("Crawling level must be at least 1")

            if self.args.threadCount < 1:
                self.parser.error("Thread count must be at least 1")

            if self.args.delay < 0:
                self.parser.error("Delay cannot be negative")

            if self.args.timeout < 1:
                self.parser.error("Timeout must be at least 1 second")

        except SystemExit:
            # Re-raise SystemExit to allow argparse to handle help/error display
            raise
        except Exception as e:
            self.display_error(f"Error parsing arguments: {str(e)}")
            sys.exit(1)

    def _setup_configuration(self) -> None:
        """Setup configuration from command-line arguments."""
        # Load custom config if provided
        if self.args.config_file:
            core.config.config_manager.load_config(self.args.config_file)

        # Update core config with CLI arguments
        core.config.globalVariables = vars(self.args)
        core.config.update_config_from_args(self.args)

        # Handle headers
        if isinstance(self.args.add_headers, bool) and self.args.add_headers:
            headers = extractHeaders(prompt())
        elif isinstance(self.args.add_headers, str):
            headers = extractHeaders(self.args.add_headers)
        else:
            from core.config import headers

        core.config.globalVariables["headers"] = headers

        # Handle proxy configuration
        if not self.args.proxy:
            core.config.proxies = {}

    def _setup_logging(self) -> None:
        """Setup logging configuration."""
        core.log.console_log_level = self.args.console_log_level
        if self.args.file_log_level:
            core.log.file_log_level = self.args.file_log_level
        core.log.log_file = self.args.log_file

        self.logger = core.log.setup_logger()

    def _create_scan_options(self) -> ScanOptions:
        """Create scan options from CLI arguments."""
        # Get headers
        headers = core.config.globalVariables.get("headers", {})

        options = ScanOptions(
            target=self.args.target,
            param_data=self.args.paramData,
            encode=self.args.encode,
            timeout=self.args.timeout,
            proxy=self.args.proxy,
            json_data=self.args.jsonData,
            path=self.args.path,
            seeds_file=self.args.args_seeds,
            payloads_file=self.args.args_file,
            level=self.args.level,
            headers=headers,
            thread_count=self.args.threadCount,
            delay=self.args.delay,
            skip=self.args.skip,
            skip_dom=self.args.skipDOM,
            blind_xss=self.args.blindXSS,
            blind_payload=self.args.blind_payload,
            verify_ssl=self.args.verify_ssl,
            ssl_cert_path=self.args.ssl_cert_path,
            ai_enabled=self.args.ai_enabled,  # AI INTEGRATION
            ai_learning_mode=self.args.ai_learning_mode,  # AI INTEGRATION
            ai_confidence_threshold=self.args.ai_confidence_threshold  # AI INTEGRATION
        )

        # Add fuzz option if present
        if hasattr(self.args, 'fuzz'):
            setattr(options, 'fuzz', self.args.fuzz)

        return options

    def _display_scan_summary(self, result: ScanResult) -> None:
        """Display scan summary."""
        print(f"\n{info} Scan Summary:")
        print(f"  Target: {result.target}")
        print(f"  Mode: {result.mode.value}")
        print(f"  Status: {result.status.value}")
        print(f"  Duration: {result.duration:.2f}s" if result.duration else "  Duration: N/A")
        print(f"  Vulnerabilities: {result.vulnerability_count}")
        print(f"  Forms found: {result.forms_found}")
        print(f"  URLs processed: {result.urls_processed}")
        print(f"  Requests made: {result.requests_made}")

        if result.errors:
            print(f"  Errors: {len(result.errors)}")
            for error in result.errors:
                print(f"    - {error}")

        if result.warnings:
            print(f"  Warnings: {len(result.warnings)}")
            for warning in result.warnings:
                print(f"    - {warning}")


def main():
    """Main entry point for CLI interface."""
    cli = CLIInterface()
    try:
        cli.initialize()
        cli.run()
    finally:
        cli.shutdown()


if __name__ == "__main__":
    main()
