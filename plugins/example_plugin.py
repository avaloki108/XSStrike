"""
Example Plugin for XSStrike.

This is a simple example plugin that demonstrates how to create new plugins
for the XSStrike plugin system. It logs information at different hook points.
"""

from typing import Dict, List, Any

from core.plugin_manager import BasePlugin, PluginType, PluginHook, PluginResult
from core.log import setup_logger

logger = setup_logger(__name__)


class ExamplePlugin(BasePlugin):
    """
    Example plugin that demonstrates the plugin system capabilities.
    
    This plugin logs information at various hook points during scanning
    to show how plugins can integrate with the XSStrike workflow.
    """

    def __init__(self):
        super().__init__(
            name="Example",
            version="1.0.0",
            description="Example plugin demonstrating the plugin system",
            author="XSStrike Development Team"
        )
        self.scan_count = 0
        self.request_count = 0

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.SCANNER

    @property
    def supported_hooks(self) -> List[PluginHook]:
        return [
            PluginHook.PRE_SCAN,
            PluginHook.POST_SCAN,
            PluginHook.PRE_REQUEST,
            PluginHook.POST_REQUEST,
            PluginHook.PRE_CRAWL,
            PluginHook.POST_CRAWL,
            PluginHook.VULNERABILITY_FOUND
        ]

    def validate_context(self, hook: PluginHook, context: Dict[str, Any]) -> bool:
        """Validate context for different hooks."""
        if hook in [PluginHook.PRE_REQUEST, PluginHook.POST_REQUEST]:
            return 'url' in context
        elif hook in [PluginHook.PRE_CRAWL, PluginHook.POST_CRAWL]:
            return 'target_url' in context or 'processed_urls' in context
        elif hook == PluginHook.VULNERABILITY_FOUND:
            return 'vulnerability' in context
        return True

    def execute(self, hook: PluginHook, context: Dict[str, Any]) -> PluginResult:
        """Execute the plugin for different hooks."""
        try:
            if hook == PluginHook.PRE_SCAN:
                return self._handle_pre_scan(context)
            elif hook == PluginHook.POST_SCAN:
                return self._handle_post_scan(context)
            elif hook == PluginHook.PRE_REQUEST:
                return self._handle_pre_request(context)
            elif hook == PluginHook.POST_REQUEST:
                return self._handle_post_request(context)
            elif hook == PluginHook.PRE_CRAWL:
                return self._handle_pre_crawl(context)
            elif hook == PluginHook.POST_CRAWL:
                return self._handle_post_crawl(context)
            elif hook == PluginHook.VULNERABILITY_FOUND:
                return self._handle_vulnerability_found(context)

            return PluginResult(False, message=f"Unsupported hook: {hook}")

        except Exception as e:
            self.logger.error(f"Example plugin execution error: {str(e)}")
            return PluginResult(False, message=str(e))

    def _handle_pre_scan(self, context: Dict[str, Any]) -> PluginResult:
        """Handle pre-scan hook."""
        self.scan_count += 1
        target = context.get('target', 'unknown')
        self.logger.info(f"Example Plugin: Starting scan #{self.scan_count} for target: {target}")

        return PluginResult(
            True,
            data={"scan_number": self.scan_count},
            message=f"Pre-scan processing completed for scan #{self.scan_count}"
        )

    def _handle_post_scan(self, context: Dict[str, Any]) -> PluginResult:
        """Handle post-scan hook."""
        target = context.get('target', 'unknown')
        vulnerabilities = context.get('vulnerabilities_found', 0)

        self.logger.info(f"Example Plugin: Completed scan for {target}")
        self.logger.info(f"Example Plugin: Found {vulnerabilities} vulnerabilities")
        self.logger.info(f"Example Plugin: Processed {self.request_count} requests total")

        return PluginResult(
            True,
            data={
                "scan_completed": True,
                "total_requests": self.request_count,
                "vulnerabilities": vulnerabilities
            },
            message="Post-scan processing completed"
        )

    def _handle_pre_request(self, context: Dict[str, Any]) -> PluginResult:
        """Handle pre-request hook."""
        url = context.get('url', 'unknown')
        self.logger.debug(f"Example Plugin: About to make request to {url}")

        return PluginResult(True, message="Pre-request processing completed")

    def _handle_post_request(self, context: Dict[str, Any]) -> PluginResult:
        """Handle post-request hook."""
        self.request_count += 1
        url = context.get('url', 'unknown')
        response = context.get('response', '')

        # Simple analysis: count forms and scripts
        form_count = response.count('<form') if response else 0
        script_count = response.count('<script') if response else 0

        self.logger.debug(f"Example Plugin: Request #{self.request_count} to {url}")
        self.logger.debug(f"Example Plugin: Found {form_count} forms, {script_count} scripts")

        return PluginResult(
            True,
            data={
                "request_number": self.request_count,
                "forms_found": form_count,
                "scripts_found": script_count
            },
            message="Post-request processing completed"
        )

    def _handle_pre_crawl(self, context: Dict[str, Any]) -> PluginResult:
        """Handle pre-crawl hook."""
        target_url = context.get('target_url', 'unknown')
        level = context.get('level', 1)

        self.logger.info(f"Example Plugin: Starting crawl of {target_url} (level {level})")

        return PluginResult(
            True,
            data={"crawl_started": True},
            message="Pre-crawl processing completed"
        )

    def _handle_post_crawl(self, context: Dict[str, Any]) -> PluginResult:
        """Handle post-crawl hook."""
        processed_urls = context.get('processed_urls', [])
        interrupted = context.get('interrupted', False)

        status = "interrupted" if interrupted else "completed"
        self.logger.info(f"Example Plugin: Crawl {status}")
        self.logger.info(f"Example Plugin: Processed {len(processed_urls)} URLs")

        return PluginResult(
            True,
            data={
                "crawl_completed": not interrupted,
                "urls_processed": len(processed_urls)
            },
            message="Post-crawl processing completed"
        )

    def _handle_vulnerability_found(self, context: Dict[str, Any]) -> PluginResult:
        """Handle vulnerability found hook."""
        vulnerability = context.get('vulnerability', {})
        url = context.get('url', 'unknown')

        vuln_type = vulnerability.get('type', 'unknown')
        severity = vulnerability.get('severity', 'unknown')

        self.logger.info(f"Example Plugin: Vulnerability detected!")
        self.logger.info(f"Example Plugin: Type: {vuln_type}, Severity: {severity}")
        self.logger.info(f"Example Plugin: URL: {url}")

        return PluginResult(
            True,
            data={
                "vulnerability_logged": True,
                "type": vuln_type,
                "severity": severity
            },
            message="Vulnerability logging completed"
        )


# Create plugin instance for registration
plugin_instance = ExamplePlugin()
