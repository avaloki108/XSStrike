"""
RetireJS Plugin for XSStrike.

This plugin scans JavaScript files for known vulnerabilities using the RetireJS
vulnerability database. It detects outdated JavaScript libraries and reports
their known security issues.
"""

import re
import json
import hashlib
from urllib.parse import urlparse
from typing import Dict, List, Any

from core.plugin_manager import BasePlugin, PluginType, PluginHook, PluginResult
from core.colors import green, end
from core.requester import requester
from core.utils import deJSON, js_extractor, handle_anchor, getVar, updateVar
from core.log import setup_logger

logger = setup_logger(__name__)


class RetireJSPlugin(BasePlugin):
    """
    Plugin for detecting vulnerable JavaScript libraries using RetireJS database.
    
    This plugin analyzes JavaScript files and identifies outdated libraries
    with known security vulnerabilities.
    """

    def __init__(self):
        super().__init__(
            name="RetireJS",
            version="2.0.0",
            description="Detects vulnerable JavaScript libraries using RetireJS database",
            author="XSStrike Team"
        )

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.ANALYZER

    @property
    def supported_hooks(self) -> List[PluginHook]:
        return [PluginHook.POST_REQUEST, PluginHook.POST_CRAWL]

    def validate_context(self, hook: PluginHook, context: Dict[str, Any]) -> bool:
        """Validate context contains required data."""
        if hook == PluginHook.POST_REQUEST:
            return all(key in context for key in ['url', 'response'])
        elif hook == PluginHook.POST_CRAWL:
            return 'processed_urls' in context
        return False

    def execute(self, hook: PluginHook, context: Dict[str, Any]) -> PluginResult:
        """Execute the RetireJS analysis."""
        try:
            if hook == PluginHook.POST_REQUEST:
                return self._analyze_response(context['url'], context['response'])
            elif hook == PluginHook.POST_CRAWL:
                return self._analyze_crawled_urls(context['processed_urls'])

            return PluginResult(False, message=f"Unsupported hook: {hook}")

        except Exception as e:
            self.logger.error(f"RetireJS execution error: {str(e)}")
            return PluginResult(False, message=str(e))

    def _analyze_response(self, url: str, response: str) -> PluginResult:
        """Analyze a single response for vulnerable JavaScript."""
        vulnerabilities = []

        # Extract and analyze JavaScript files
        scripts = js_extractor(response)
        for script in scripts:
            if script not in getVar("checkedScripts"):
                updateVar("checkedScripts", script, "add")
                script_url = handle_anchor(url, script)

                try:
                    script_response = requester(
                        script_url, "", getVar("headers"), True,
                        getVar("delay"), getVar("timeout")
                    ).text

                    result = self._scan_script(script_url, script_response)
                    if result:
                        vulnerabilities.append(result)
                        self._report_vulnerability(result, script_url)

                except Exception as e:
                    self.logger.debug(f"Failed to analyze script {script_url}: {str(e)}")

        if vulnerabilities:
            return PluginResult(
                True,
                data=vulnerabilities,
                message=f"Found {len(vulnerabilities)} vulnerable JavaScript components",
                metadata={"vulnerability_count": len(vulnerabilities)}
            )

        return PluginResult(True, message="No vulnerable JavaScript components found")

    def _analyze_crawled_urls(self, processed_urls: List[str]) -> PluginResult:
        """Analyze all crawled URLs for vulnerable JavaScript."""
        total_vulnerabilities = 0

        for url in processed_urls:
            try:
                response = requester(
                    url, "", getVar("headers"), True,
                    getVar("delay"), getVar("timeout")
                ).text

                result = self._analyze_response(url, response)
                if result.success and result.data:
                    total_vulnerabilities += len(result.data)

            except Exception as e:
                self.logger.debug(f"Failed to analyze crawled URL {url}: {str(e)}")

        return PluginResult(
            True,
            message=f"Completed analysis of {len(processed_urls)} URLs, found {total_vulnerabilities} vulnerabilities",
            metadata={"urls_analyzed": len(processed_urls), "vulnerabilities_found": total_vulnerabilities}
        )

    def _scan_script(self, uri: str, response: str) -> Dict[str, Any]:
        """Scan a single JavaScript file for vulnerabilities."""
        definitions = getVar("definitions")
        if not definitions:
            return None

        # Scan URI
        uri_scan_result = self._scan_uri(uri, definitions)

        # Scan file content
        filecontent_scan_result = self._scan_file_content(response, definitions)

        # Combine results
        uri_scan_result.extend(filecontent_scan_result)

        if not uri_scan_result:
            return None

        # Format result
        result = {
            "component": uri_scan_result[0]["component"],
            "version": uri_scan_result[0]["version"],
            "vulnerabilities": []
        }

        # Collect unique vulnerabilities
        vulnerabilities = set()
        for item in uri_scan_result:
            if "vulnerabilities" in item:
                for vuln in item["vulnerabilities"]:
                    vulnerabilities.add(str(vuln))

        for vulnerability in vulnerabilities:
            try:
                result["vulnerabilities"].append(
                    json.loads(vulnerability.replace("'", '"'))
                )
            except json.JSONDecodeError:
                self.logger.debug(f"Failed to parse vulnerability: {vulnerability}")

        return result if result["vulnerabilities"] else None

    def _scan_uri(self, uri: str, definitions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan URI for component detection."""
        result = self._scan(uri, "uri", definitions)
        return self._check_vulnerabilities(result, definitions)

    def _scan_file_content(self, content: str, definitions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan file content for component detection."""
        result = self._scan(content, "filecontent", definitions)

        if not result:
            result = self._scan(content, "filecontentreplace", definitions, self._replacement_match)

        if not result:
            hash_value = hashlib.sha1(content.encode("utf8")).hexdigest()
            result = self._scan_hash(hash_value, definitions)

        return self._check_vulnerabilities(result, definitions)

    def _scan(self, data: str, extractor: str, definitions: Dict[str, Any],
              matcher=None) -> List[Dict[str, Any]]:
        """Generic scan function."""
        matcher = matcher or self._simple_match
        detected = []

        for component in definitions:
            extractors = definitions[component].get("extractors", {}).get(extractor, [])
            if not extractors:
                continue

            for regex in extractors:
                match = matcher(regex, data)
                if match:
                    detected.append({
                        "version": match,
                        "component": component,
                        "detection": extractor
                    })

        return detected

    def _simple_match(self, regex: str, data: str) -> str:
        """Simple regex matching."""
        try:
            regex = deJSON(regex)
            match = re.search(regex, data)
            return match.group(1) if match else None
        except (AttributeError, re.error):
            return None

    def _replacement_match(self, regex: str, data: str) -> str:
        """Replacement-based regex matching."""
        try:
            regex = deJSON(regex)
            group_parts_of_regex = r"^\/(.*[^\\])\/([^\/]+)\/$"
            ar = re.search(group_parts_of_regex, regex)
            if not ar:
                return None

            search_for_regex = "(" + ar.group(1) + ")"
            match = re.search(search_for_regex, data)

            if match:
                return re.sub(ar.group(1), ar.group(2), match.group(0))

            return None
        except (AttributeError, re.error) as e:
            self.logger.debug(f"Regex parsing error in _replacement_match: {str(e)}")
            return None

    def _scan_hash(self, hash_value: str, definitions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan by hash value."""
        for component in definitions:
            hashes = definitions[component].get("extractors", {}).get("hashes", {})
            if hash_value in hashes:
                return [{
                    "version": hashes[hash_value],
                    "component": component,
                    "detection": "hash"
                }]
        return []

    def _check_vulnerabilities(self, results: List[Dict[str, Any]],
                               definitions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for vulnerabilities in detected components."""
        for result in results:
            component = result.get("component")
            version = result.get("version")

            if not component or component not in definitions:
                continue

            vulns = definitions[component].get("vulnerabilities", [])
            result["vulnerabilities"] = []

            for vuln in vulns:
                if not self._is_at_or_above(version, vuln.get("below")):
                    if (vuln.get("atOrAbove") and
                            not self._is_at_or_above(version, vuln.get("atOrAbove"))):
                        continue

                    vulnerability = {"info": vuln.get("info", [])}
                    if vuln.get("severity"):
                        vulnerability["severity"] = vuln.get("severity")
                    if vuln.get("identifiers"):
                        vulnerability["identifiers"] = vuln.get("identifiers")

                    result["vulnerabilities"].append(vulnerability)

        return results

    def _is_at_or_above(self, version1: str, version2: str) -> bool:
        """Compare version numbers."""
        if not version1 or not version2:
            return True

        v1 = re.split(r"[.-]", version1)
        v2 = re.split(r"[.-]", version2)

        max_len = max(len(v1), len(v2))
        for i in range(max_len):
            v1_c = self._to_comparable(v1[i] if i < len(v1) else None)
            v2_c = self._to_comparable(v2[i] if i < len(v2) else None)

            if not isinstance(v1_c, type(v2_c)):
                return isinstance(v1_c, int)
            if v1_c > v2_c:
                return True
            if v1_c < v2_c:
                return False

        return True

    def _to_comparable(self, n: str) -> Any:
        """Convert version component to comparable format."""
        if not n:
            return 0
        if re.search(r"^[0-9]+$", n):
            return int(n)
        return n

    def _report_vulnerability(self, result: Dict[str, Any], uri: str) -> None:
        """Report found vulnerability."""
        self.logger.red_line()
        self.logger.good(
            f"Vulnerable component: {result['component']} v{result['version']}"
        )
        self.logger.info(f"Component location: {uri}")

        details = result["vulnerabilities"]
        self.logger.info(f"Total vulnerabilities: {len(details)}")

        for detail in details:
            if "identifiers" in detail and "summary" in detail["identifiers"]:
                self.logger.info(
                    f"{green}Summary:{end} {detail['identifiers']['summary']}"
                )
            if "severity" in detail:
                self.logger.info(f"Severity: {detail['severity']}")
            if "identifiers" in detail and "CVE" in detail["identifiers"]:
                cves = detail["identifiers"]["CVE"]
                if cves:
                    self.logger.info(f"CVE: {cves[0]}")

        self.logger.red_line()


# Create plugin instance for registration
plugin_instance = RetireJSPlugin()
