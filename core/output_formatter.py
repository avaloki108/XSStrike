"""
User-friendly output formatter for XSStrike.

This module provides enhanced output formatting with better visual organization,
progress indicators, colored output, and structured information display.
"""

import time
import sys
import threading
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from enum import Enum

from core.colors import (
    white, green, red, yellow, end, back, info, que, bad, good, run, colors
)
from core.log import setup_logger

logger = setup_logger(__name__)


class MessageType(Enum):
    """Types of messages for consistent formatting."""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    QUESTION = "question"
    RUNNING = "running"
    VULNERABILITY = "vulnerability"
    HEADER = "header"
    SUBHEADER = "subheader"
    RESULT = "result"


class ProgressBar:
    """Enhanced progress bar with ETA and detailed status."""

    def __init__(self, total: int, description: str = "", width: int = 50):
        self.total = total
        self.current = 0
        self.description = description
        self.width = width
        self.start_time = time.time()
        self.last_update = 0
        self._lock = threading.Lock()

    def update(self, increment: int = 1, status: str = "") -> None:
        """Update progress bar."""
        with self._lock:
            self.current += increment
            current_time = time.time()

            # Limit update frequency to avoid performance issues
            if current_time - self.last_update < 0.1 and self.current < self.total:
                return

            self.last_update = current_time
            self._render(status)

    def set_description(self, description: str) -> None:
        """Update progress bar description."""
        with self._lock:
            self.description = description
            self._render()

    def _render(self, status: str = "") -> None:
        """Render the progress bar."""
        if not colors:
            # Simple text progress for non-color terminals
            percent = (self.current / self.total) * 100 if self.total > 0 else 0
            sys.stdout.write(f"\r{self.description}: {self.current}/{self.total} ({percent:.1f}%)")
            sys.stdout.flush()
            return

        # Calculate progress
        percent = (self.current / self.total) * 100 if self.total > 0 else 0
        filled_width = int(self.width * (self.current / self.total)) if self.total > 0 else 0

        # Create progress bar
        bar = "█" * filled_width + "░" * (self.width - filled_width)

        # Calculate ETA
        eta_str = ""
        if self.current > 0:
            elapsed = time.time() - self.start_time
            rate = self.current / elapsed
            if rate > 0 and self.current < self.total:
                eta_seconds = (self.total - self.current) / rate
                eta = timedelta(seconds=int(eta_seconds))
                eta_str = f" ETA: {eta}"

        # Status information
        status_info = f" | {status}" if status else ""

        # Render the complete progress bar
        progress_line = (
            f"\r{green}[{bar}]{end} "
            f"{white}{percent:5.1f}%{end} "
            f"({self.current}/{self.total})"
            f"{yellow}{status_info}{end}"
            f"{white}{eta_str}{end}"
        )

        # Add description if provided
        if self.description:
            progress_line = f"\r{run} {self.description}\n{progress_line}"

        sys.stdout.write(progress_line)
        sys.stdout.flush()

    def finish(self, final_message: str = "") -> None:
        """Finish progress bar with final message."""
        with self._lock:
            self.current = self.total
            elapsed = time.time() - self.start_time

            if final_message:
                print(f"\n{good} {final_message} (completed in {elapsed:.2f}s)")
            else:
                print(f"\n{good} Completed in {elapsed:.2f}s")


class OutputFormatter:
    """Enhanced output formatter with user-friendly features."""

    def __init__(self):
        self.indent_level = 0
        self.last_section = ""
        self._vulnerability_count = 0
        self._start_time = time.time()

    def print_header(self, title: str, subtitle: str = "") -> None:
        """Print a formatted header."""
        if not colors:
            print(f"\n{'=' * 60}")
            print(f" {title}")
            if subtitle:
                print(f" {subtitle}")
            print('=' * 60)
            return

        print(f"\n{white}{'=' * 60}{end}")
        print(f"{white} {back} {title} {end}")
        if subtitle:
            print(f"{white} {subtitle}{end}")
        print(f"{white}{'=' * 60}{end}")

    def print_section(self, title: str) -> None:
        """Print a section header."""
        if title == self.last_section:
            return

        self.last_section = title

        if not colors:
            print(f"\n--- {title} ---")
            return

        print(f"\n{yellow}▶ {title}{end}")
        print(f"{yellow}{'─' * (len(title) + 2)}{end}")

    def print_subsection(self, title: str) -> None:
        """Print a subsection header."""
        indent = "  " * self.indent_level

        if not colors:
            print(f"{indent}• {title}")
            return

        print(f"{indent}{white}• {title}{end}")

    def print_message(self, message: str, msg_type: MessageType = MessageType.INFO,
                      indent: bool = True) -> None:
        """Print a formatted message."""
        indent_str = "  " * self.indent_level if indent else ""

        # Choose appropriate prefix and color
        if msg_type == MessageType.SUCCESS:
            prefix = good
        elif msg_type == MessageType.ERROR:
            prefix = bad
        elif msg_type == MessageType.WARNING:
            prefix = info
        elif msg_type == MessageType.INFO:
            prefix = info
        elif msg_type == MessageType.QUESTION:
            prefix = que
        elif msg_type == MessageType.RUNNING:
            prefix = run
        elif msg_type == MessageType.VULNERABILITY:
            prefix = f"{red}[VULN]{end}"
            self._vulnerability_count += 1
        else:
            prefix = ""

        print(f"{indent_str}{prefix} {message}")

    def print_vulnerability(self, url: str, parameter: str, payload: str,
                            confidence: float = 0.0, vulnerability_type: str = "XSS") -> None:
        """Print a formatted vulnerability report."""
        self.print_section("Vulnerability Detected")

        details = [
            ("Type", vulnerability_type),
            ("URL", url),
            ("Parameter", parameter),
            ("Confidence", f"{confidence * 100:.1f}%" if confidence > 0 else "N/A"),
            ("Payload", payload)
        ]

        if not colors:
            for label, value in details:
                print(f"  {label}: {value}")
            print()
            return

        # Colored vulnerability report
        for label, value in details:
            if label == "Type":
                print(f"  {white}{label}:{end} {red}{value}{end}")
            elif label == "URL":
                print(f"  {white}{label}:{end} {yellow}{value}{end}")
            elif label == "Parameter":
                print(f"  {white}{label}:{end} {green}{value}{end}")
            elif label == "Confidence":
                color = green if confidence > 0.7 else yellow if confidence > 0.4 else red
                print(f"  {white}{label}:{end} {color}{value}{end}")
            else:
                print(f"  {white}{label}:{end} {value}")

        print()

    def print_summary(self, title: str, data: Dict[str, Any]) -> None:
        """Print a formatted summary."""
        self.print_section(title)

        for key, value in data.items():
            if isinstance(value, dict):
                self.print_subsection(key)
                self.indent_level += 1
                for sub_key, sub_value in value.items():
                    self.print_message(f"{sub_key}: {sub_value}")
                self.indent_level -= 1
            else:
                self.print_message(f"{key}: {value}")

    def print_scan_results(self, results: Dict[str, Any]) -> None:
        """Print comprehensive scan results."""
        elapsed = time.time() - self._start_time

        self.print_header("Scan Results Summary")

        # Basic statistics
        stats = {
            "Duration": f"{elapsed:.2f} seconds",
            "Vulnerabilities Found": self._vulnerability_count,
            "URLs Processed": results.get("urls_processed", 0),
            "Forms Found": results.get("forms_found", 0),
            "Requests Made": results.get("requests_made", 0)
        }

        self.print_summary("Statistics", stats)

        # Performance metrics
        if "performance" in results:
            self.print_summary("Performance", results["performance"])

        # Vulnerabilities details
        if "vulnerabilities" in results and results["vulnerabilities"]:
            self.print_section("Vulnerability Details")
            for vuln in results["vulnerabilities"]:
                self.print_vulnerability(
                    vuln.get("url", "N/A"),
                    vuln.get("parameter", "N/A"),
                    vuln.get("payload", "N/A"),
                    vuln.get("confidence", 0.0),
                    vuln.get("type", "XSS")
                )

        # Final status
        if self._vulnerability_count > 0:
            self.print_message(
                f"Scan completed with {self._vulnerability_count} vulnerabilities found!",
                MessageType.WARNING
            )
        else:
            self.print_message("Scan completed - no vulnerabilities detected.", MessageType.SUCCESS)

    def print_table(self, headers: List[str], rows: List[List[str]], title: str = "") -> None:
        """Print a formatted table."""
        if title:
            self.print_subsection(title)

        if not rows:
            self.print_message("No data to display", MessageType.INFO)
            return

        # Calculate column widths
        widths = [len(header) for header in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))

        # Print table
        indent = "  " * (self.indent_level + 1)

        # Headers
        if colors:
            header_line = indent + white + " | ".join(
                header.ljust(width) for header, width in zip(headers, widths)
            ) + end
            print(header_line)
            print(indent + "─" * (sum(widths) + 3 * (len(headers) - 1)))
        else:
            header_line = indent + " | ".join(
                header.ljust(width) for header, width in zip(headers, widths)
            )
            print(header_line)
            print(indent + "-" * (sum(widths) + 3 * (len(headers) - 1)))

        # Rows
        for row in rows:
            row_line = indent + " | ".join(
                str(cell).ljust(width) for cell, width in zip(row, widths)
            )
            print(row_line)

    def print_ai_insights(self, insights: Dict[str, Any]) -> None:
        """Print AI-generated insights and recommendations."""
        if not insights:
            return

        self.print_section("AI Insights & Recommendations")

        if "target_analysis" in insights:
            analysis = insights["target_analysis"]
            self.print_subsection("Target Analysis")
            self.indent_level += 1

            if "technologies" in analysis:
                self.print_message(f"Technologies: {', '.join(analysis['technologies'])}")
            if "cms" in analysis and analysis["cms"]:
                self.print_message(f"CMS: {analysis['cms']}")
            if "waf" in analysis and analysis["waf"]:
                self.print_message(f"WAF: {analysis['waf']}")
            if "risk_level" in analysis:
                risk_color = red if analysis["risk_level"] == "HIGH" else yellow if analysis[
                                                                                        "risk_level"] == "MEDIUM" else green
                if colors:
                    self.print_message(f"Risk Level: {risk_color}{analysis['risk_level']}{end}")
                else:
                    self.print_message(f"Risk Level: {analysis['risk_level']}")

            self.indent_level -= 1

        if "recommendations" in insights:
            recs = insights["recommendations"]
            self.print_subsection("AI Recommendations")
            self.indent_level += 1

            for rec in recs:
                self.print_message(f"• {rec}")

            self.indent_level -= 1

        if "payload_effectiveness" in insights:
            effectiveness = insights["payload_effectiveness"]
            self.print_subsection("Payload Effectiveness")
            self.print_message(f"Success Rate Prediction: {effectiveness * 100:.1f}%")

    def create_progress_bar(self, total: int, description: str = "") -> ProgressBar:
        """Create a new progress bar."""
        return ProgressBar(total, description)

    def indent(self) -> None:
        """Increase indentation level."""
        self.indent_level += 1

    def dedent(self) -> None:
        """Decrease indentation level."""
        self.indent_level = max(0, self.indent_level - 1)


# Global formatter instance
formatter = OutputFormatter()
