"""
REST API Interface for XSStrike.

This module provides a REST API implementation that exposes XSStrike functionality
through HTTP endpoints, using the same core engine as the CLI interface.
"""

import json
import threading
import time
from typing import Dict, List, Any, Optional
from dataclasses import asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

from interfaces.base import BaseInterface
from core.engine import XSSEngine, ScanOptions, ScanResult, ScanStatus
from core.log import setup_logger


class APIRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the XSStrike API."""

    def __init__(self, api_interface, *args, **kwargs):
        self.api_interface = api_interface
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        """Handle GET requests."""
        try:
            path, query = self._parse_request()

            if path == "/api/scans":
                self._handle_list_scans()
            elif path.startswith("/api/scans/") and path.endswith("/status"):
                scan_id = path.split("/")[3]
                self._handle_scan_status(scan_id)
            elif path.startswith("/api/scans/") and path.endswith("/results"):
                scan_id = path.split("/")[3]
                self._handle_scan_results(scan_id)
            elif path == "/api/health":
                self._handle_health_check()
            else:
                self._send_error(404, "Endpoint not found")

        except Exception as e:
            self._send_error(500, f"Internal server error: {str(e)}")

    def do_POST(self) -> None:
        """Handle POST requests."""
        try:
            path, _ = self._parse_request()

            if path == "/api/scans":
                self._handle_create_scan()
            elif path.startswith("/api/scans/") and path.endswith("/cancel"):
                scan_id = path.split("/")[3]
                self._handle_cancel_scan(scan_id)
            else:
                self._send_error(404, "Endpoint not found")

        except Exception as e:
            self._send_error(500, f"Internal server error: {str(e)}")

    def do_DELETE(self) -> None:
        """Handle DELETE requests."""
        try:
            path, _ = self._parse_request()

            if path.startswith("/api/scans/"):
                scan_id = path.split("/")[3]
                self._handle_delete_scan(scan_id)
            else:
                self._send_error(404, "Endpoint not found")

        except Exception as e:
            self._send_error(500, f"Internal server error: {str(e)}")

    def _parse_request(self):
        """Parse the request URL."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        return path, query

    def _get_request_body(self) -> Dict[str, Any]:
        """Get and parse JSON request body."""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}

        body = self.rfile.read(content_length).decode('utf-8')
        return json.loads(body)

    def _send_json_response(self, data: Any, status_code: int = 200) -> None:
        """Send JSON response."""
        response_body = json.dumps(data, indent=2, default=str)

        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response_body.encode('utf-8'))

    def _send_error(self, status_code: int, message: str) -> None:
        """Send error response."""
        error_data = {
            "error": message,
            "status_code": status_code,
            "timestamp": time.time()
        }
        self._send_json_response(error_data, status_code)

    def _handle_health_check(self) -> None:
        """Handle health check endpoint."""
        health_data = {
            "status": "healthy",
            "timestamp": time.time(),
            "version": "3.1.5"
        }
        self._send_json_response(health_data)

    def _handle_list_scans(self) -> None:
        """Handle list scans endpoint."""
        scans = self.api_interface.handle_list_scans()
        self._send_json_response({"scans": scans})

    def _handle_create_scan(self) -> None:
        """Handle create scan endpoint."""
        try:
            data = self._get_request_body()

            # Create scan options from request data
            options = ScanOptions(
                target=data.get('target'),
                param_data=data.get('param_data'),
                encode=data.get('encode'),
                timeout=data.get('timeout', 10),
                proxy=data.get('proxy', False),
                json_data=data.get('json_data', False),
                path=data.get('path', False),
                seeds_file=data.get('seeds_file'),
                payloads_file=data.get('payloads_file'),
                level=data.get('level', 2),
                headers=data.get('headers', {}),
                thread_count=data.get('thread_count', 10),
                delay=data.get('delay', 0),
                skip=data.get('skip', False),
                skip_dom=data.get('skip_dom', False),
                blind_xss=data.get('blind_xss', False),
                blind_payload=data.get('blind_payload'),
                verify_ssl=data.get('verify_ssl', False),
                ssl_cert_path=data.get('ssl_cert_path')
            )

            # Start scan asynchronously
            scan_id = self.api_interface.handle_scan_request(options)

            response_data = {
                "scan_id": scan_id,
                "status": "created",
                "message": "Scan created successfully"
            }
            self._send_json_response(response_data, 201)

        except ValueError as e:
            self._send_error(400, f"Invalid request data: {str(e)}")
        except Exception as e:
            self._send_error(500, f"Failed to create scan: {str(e)}")

    def _handle_scan_status(self, scan_id: str) -> None:
        """Handle scan status endpoint."""
        result = self.api_interface.handle_scan_status(scan_id)
        if result:
            status_data = self.api_interface.format_scan_summary(result)
            self._send_json_response(status_data)
        else:
            self._send_error(404, f"Scan {scan_id} not found")

    def _handle_scan_results(self, scan_id: str) -> None:
        """Handle scan results endpoint."""
        results = self.api_interface.handle_scan_results(scan_id)
        if results:
            self._send_json_response(results)
        else:
            self._send_error(404, f"Scan {scan_id} not found")

    def _handle_cancel_scan(self, scan_id: str) -> None:
        """Handle cancel scan endpoint."""
        success = self.api_interface.handle_cancel_scan(scan_id)
        if success:
            response_data = {"message": f"Scan {scan_id} cancelled successfully"}
            self._send_json_response(response_data)
        else:
            self._send_error(404, f"Scan {scan_id} not found or cannot be cancelled")

    def _handle_delete_scan(self, scan_id: str) -> None:
        """Handle delete scan endpoint."""
        success = self.api_interface.engine.cleanup_scan(scan_id)
        if success:
            response_data = {"message": f"Scan {scan_id} deleted successfully"}
            self._send_json_response(response_data)
        else:
            self._send_error(404, f"Scan {scan_id} not found")

    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        self.api_interface.logger.info(f"{self.address_string()} - {format % args}")


class APIInterface(BaseInterface):
    """
    REST API Interface for XSStrike.
    
    This class provides a REST API that exposes XSStrike functionality
    through HTTP endpoints.
    """

    def __init__(self, engine: Optional[XSSEngine] = None, host: str = "localhost", port: int = 8080):
        super().__init__(engine)
        self.logger = setup_logger(__name__)
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self._running = False

    def initialize(self) -> None:
        """Initialize the API interface."""
        self.logger.info(f"Initializing XSStrike API server on {self.host}:{self.port}")

        # Create request handler with reference to this interface
        def handler_factory(*args, **kwargs):
            return APIRequestHandler(self, *args, **kwargs)

        self.server = HTTPServer((self.host, self.port), handler_factory)
        self.logger.info("API server initialized successfully")

    def run(self) -> None:
        """Start the API server."""
        self._running = True
        self.logger.info(f"Starting XSStrike API server on http://{self.host}:{self.port}")

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("API server interrupted by user")
        except Exception as e:
            self.logger.error(f"API server error: {str(e)}")
        finally:
            self._running = False

    def start_async(self) -> None:
        """Start the API server in a separate thread."""
        self.server_thread = threading.Thread(target=self.run, daemon=True)
        self.server_thread.start()
        self.logger.info("API server started asynchronously")

    def shutdown(self) -> None:
        """Shutdown the API server."""
        if self.server:
            self.logger.info("Shutting down API server")
            self.server.shutdown()
            self.server.server_close()
            self._running = False

        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)

    def handle_scan_request(self, options: ScanOptions) -> str:
        """Handle a scan request via API."""
        scan_id = self.engine.create_scan(options)

        # Start scan in background thread
        def run_scan():
            try:
                self.engine.execute_scan(scan_id, options)
                self.logger.info(f"Background scan {scan_id} completed")
            except Exception as e:
                self.logger.error(f"Background scan {scan_id} failed: {str(e)}")

        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()

        return scan_id

    def handle_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """Handle scan status request via API."""
        return self.engine.get_scan_result(scan_id)

    def handle_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Handle scan results request via API."""
        result = self.engine.get_scan_result(scan_id)
        if result:
            return self.format_detailed_results(result)
        return None

    def handle_list_scans(self) -> List[Dict[str, Any]]:
        """Handle list scans request via API."""
        scans = self.engine.list_scans()
        return [self.format_scan_summary(scan) for scan in scans]

    def handle_cancel_scan(self, scan_id: str) -> bool:
        """Handle scan cancellation request via API."""
        return self.engine.cancel_scan(scan_id)

    def display_error(self, message: str, error: Optional[Exception] = None) -> None:
        """Display error message (logged for API)."""
        self.logger.error(message)
        if error:
            self.logger.error(f"Exception: {str(error)}")

    def display_info(self, message: str) -> None:
        """Display info message (logged for API)."""
        self.logger.info(message)

    def display_warning(self, message: str) -> None:
        """Display warning message (logged for API)."""
        self.logger.warning(message)

    @property
    def is_running(self) -> bool:
        """Check if the API server is running."""
        return self._running


def main():
    """Main entry point for API interface."""
    import argparse

    parser = argparse.ArgumentParser(description="XSStrike REST API Server")
    parser.add_argument("--host", default="localhost", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")

    args = parser.parse_args()

    api = APIInterface(host=args.host, port=args.port)
    try:
        api.initialize()
        api.run()
    except KeyboardInterrupt:
        print("\nShutting down API server...")
    finally:
        api.shutdown()


if __name__ == "__main__":
    main()
