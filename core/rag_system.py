"""
RAG (Retrieval-Augmented Generation) Learning System for XSStrike.

This module implements an intelligent learning system that analyzes previous
scan results to improve future scanning decisions through pattern recognition,
similarity matching, and adaptive payload selection.
"""

import re
import json
import time
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, Counter
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import KMeans
import joblib

from core.knowledge_base import knowledge_base, Target, Payload, Vulnerability, ScanSession
from core.log import setup_logger

logger = setup_logger(__name__)


class TargetAnalyzer:
    """Analyzes target characteristics for intelligent scanning decisions."""

    def __init__(self):
        self.logger = setup_logger(f"{__name__}.TargetAnalyzer")
        self.tech_patterns = {
            'php': [r'\.php', r'PHPSESSID', r'X-Powered-By.*PHP'],
            'asp': [r'\.aspx?', r'ASP\.NET', r'__VIEWSTATE'],
            'jsp': [r'\.jsp', r'JSESSIONID', r'X-Powered-By.*Servlet'],
            'python': [r'\.py', r'Django', r'Flask'],
            'ruby': [r'\.rb', r'Rails', r'Rack'],
            'node': [r'\.js', r'Express', r'X-Powered-By.*Express'],
        }

        self.cms_patterns = {
            'wordpress': [r'wp-content', r'wp-admin', r'wp-includes'],
            'drupal': [r'sites/default', r'drupal', r'misc/drupal'],
            'joomla': [r'components/com_', r'Joomla'],
            'magento': [r'skin/frontend', r'Mage'],
        }

        self.waf_signatures = {
            'cloudflare': [r'cf-ray', r'cloudflare', r'__cfduid'],
            'akamai': [r'akamai', r'ak-bmsc'],
            'incapsula': [r'incap_ses', r'visid_incap'],
            'sucuri': [r'sucuri', r'x-sucuri'],
            'modsecurity': [r'mod_security', r'ModSecurity'],
        }

    def analyze_target(self, url: str, response_headers: Dict[str, str],
                       response_body: str = "") -> Target:
        """
        Comprehensive target analysis.
        
        Args:
            url: Target URL
            response_headers: HTTP response headers
            response_body: Response body content
            
        Returns:
            Target: Analyzed target object
        """
        target = Target(url=url, response_headers=response_headers)

        # Detect technology stack
        target.technology_stack = self._detect_technologies(response_headers, response_body)

        # Detect CMS
        target.cms_detected = self._detect_cms(response_headers, response_body)

        # Detect framework
        target.framework_detected = self._detect_framework(response_headers, response_body)

        # Detect WAF
        target.waf_detected = self._detect_waf(response_headers, response_body)

        # Extract server signature
        target.server_signature = response_headers.get('Server', '')

        self.logger.info(f"Target analysis complete for {target.domain}")
        self.logger.debug(f"Technologies: {target.technology_stack}")
        self.logger.debug(f"CMS: {target.cms_detected}")
        self.logger.debug(f"WAF: {target.waf_detected}")

        return target

    def _detect_technologies(self, headers: Dict[str, str], body: str) -> List[str]:
        """Detect technology stack from headers and body."""
        technologies = []
        combined_text = " ".join(headers.values()) + " " + body

        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    technologies.append(tech)
                    break

        return list(set(technologies))

    def _detect_cms(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Detect CMS from headers and body."""
        combined_text = " ".join(headers.values()) + " " + body

        for cms, patterns in self.cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return cms

        return None

    def _detect_framework(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Detect web framework."""
        for header, value in headers.items():
            if 'powered-by' in header.lower():
                return value.split('/')[0] if '/' in value else value

        return None

    def _detect_waf(self, headers: Dict[str, str], body: str) -> Optional[str]:
        """Detect WAF from headers and body."""
        combined_text = " ".join(headers.values()) + " " + body

        for waf, patterns in self.waf_signatures.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return waf

        return None


class PayloadRecommendationEngine:
    """Recommends optimal payloads based on target characteristics and historical success."""

    def __init__(self):
        self.logger = setup_logger(f"{__name__}.PayloadRecommendationEngine")
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.model_path = "data/payload_model.joblib"

    def recommend_payloads(self, target: Target, context: str = "",
                           max_payloads: int = 50) -> List[Tuple[Payload, float]]:
        """
        Recommend payloads for a target based on historical success.
        
        Args:
            target: Target characteristics
            context: Injection context (html, script, attribute, etc.)
            max_payloads: Maximum number of payloads to recommend
            
        Returns:
            List[Tuple[Payload, float]]: List of (payload, confidence_score) tuples
        """
        recommendations = []

        # Get similar targets
        similar_targets = knowledge_base.get_similar_targets(target, limit=20)

        # Get successful payloads from similar targets
        if similar_targets:
            successful_payloads = self._get_payloads_from_similar_targets(similar_targets)
        else:
            successful_payloads = knowledge_base.get_successful_payloads(limit=100)

        # Filter by context if specified
        if context:
            context_payloads = knowledge_base.get_payloads_for_context(context)
            successful_payloads.extend(context_payloads)

        # Score payloads based on target characteristics
        for payload in successful_payloads:
            score = self._calculate_payload_score(payload, target, context)
            if score > 0.1:  # Minimum threshold
                recommendations.append((payload, score))

        # Sort by score and limit
        recommendations.sort(key=lambda x: x[1], reverse=True)
        recommendations = recommendations[:max_payloads]

        self.logger.info(f"Recommended {len(recommendations)} payloads for {target.domain}")

        return recommendations

    def _get_payloads_from_similar_targets(self, similar_targets: List[Target]) -> List[Payload]:
        """Get successful payloads from similar targets."""
        payloads = []

        for target in similar_targets:
            # This would require additional queries to get payloads used on similar targets
            # For now, we'll use the general successful payloads
            target_payloads = knowledge_base.get_successful_payloads(limit=20, min_success_rate=0.2)
            payloads.extend(target_payloads)

        # Remove duplicates
        seen_hashes = set()
        unique_payloads = []
        for payload in payloads:
            if payload.payload_hash not in seen_hashes:
                seen_hashes.add(payload.payload_hash)
                unique_payloads.append(payload)

        return unique_payloads

    def _calculate_payload_score(self, payload: Payload, target: Target, context: str) -> float:
        """Calculate payload recommendation score for a target."""
        score = payload.success_rate

        # Boost score for context match
        if context and context in payload.contexts:
            score *= 1.5

        # Adjust for WAF effectiveness
        if target.waf_detected and target.waf_detected in payload.waf_effectiveness:
            waf_effectiveness = payload.waf_effectiveness[target.waf_detected]
            score *= (1.0 + waf_effectiveness)

        # Boost for technology stack matches
        tech_match_bonus = 0
        for tech in target.technology_stack:
            if any(tech.lower() in technique.lower() for technique in payload.bypass_techniques):
                tech_match_bonus += 0.2

        score *= (1.0 + tech_match_bonus)

        # Penalty for old payloads (encourage diversity)
        if payload.last_used:
            days_since_used = (time.time() - payload.last_used) / (24 * 3600)
            if days_since_used > 30:
                score *= 0.9

        # Boost for recent successful attempts
        if payload.total_attempts > 0:
            recency_factor = min(payload.successful_attempts / payload.total_attempts, 1.0)
            score *= (0.8 + 0.2 * recency_factor)

        return min(score, 1.0)


class VulnerabilityPatternRecognizer:
    """Recognizes patterns in vulnerability discoveries for predictive analysis."""

    def __init__(self):
        self.logger = setup_logger(f"{__name__}.VulnerabilityPatternRecognizer")
        self.pattern_cache = {}
        self.last_analysis = 0
        self.cache_duration = 3600  # 1 hour

    def analyze_vulnerability_patterns(self, domain: str = None) -> Dict[str, Any]:
        """
        Analyze vulnerability patterns from historical data.
        
        Args:
            domain: Specific domain to analyze (optional)
            
        Returns:
            Dict[str, Any]: Analysis results with patterns and insights
        """
        cache_key = domain or "global"
        current_time = time.time()

        # Check cache
        if (cache_key in self.pattern_cache and
                current_time - self.last_analysis < self.cache_duration):
            return self.pattern_cache[cache_key]

        patterns = knowledge_base.get_vulnerability_patterns(domain)

        analysis = {
            'total_vulnerabilities': len(patterns),
            'vulnerability_types': self._analyze_vulnerability_types(patterns),
            'context_patterns': self._analyze_context_patterns(patterns),
            'severity_distribution': self._analyze_severity_distribution(patterns),
            'technology_correlations': self._analyze_technology_correlations(patterns),
            'waf_bypass_patterns': self._analyze_waf_bypass_patterns(patterns),
            'recommendations': self._generate_recommendations(patterns)
        }

        # Cache results
        self.pattern_cache[cache_key] = analysis
        self.last_analysis = current_time

        self.logger.info(f"Vulnerability pattern analysis complete for {cache_key}")

        return analysis

    def _analyze_vulnerability_types(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerability type distributions."""
        type_counts = Counter(p['vulnerability_type'] for p in patterns)
        type_confidence = defaultdict(list)

        for pattern in patterns:
            type_confidence[pattern['vulnerability_type']].append(pattern['avg_confidence'])

        return {
            'distribution': dict(type_counts.most_common()),
            'avg_confidence': {
                vtype: np.mean(confidences)
                for vtype, confidences in type_confidence.items()
            }
        }

    def _analyze_context_patterns(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze injection context patterns."""
        context_counts = Counter(p['context'] for p in patterns if p['context'])

        # Group by vulnerability type and context
        type_context = defaultdict(Counter)
        for pattern in patterns:
            if pattern['context']:
                type_context[pattern['vulnerability_type']][pattern['context']] += pattern['occurrence_count']

        return {
            'most_common_contexts': dict(context_counts.most_common(10)),
            'type_context_correlation': {
                vtype: dict(contexts.most_common(5))
                for vtype, contexts in type_context.items()
            }
        }

    def _analyze_severity_distribution(self, patterns: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze severity distribution."""
        severity_counts = Counter(p['severity'] for p in patterns if p['severity'])
        return dict(severity_counts.most_common())

    def _analyze_technology_correlations(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze correlations between technologies and vulnerabilities."""
        tech_vuln_correlation = defaultdict(Counter)

        for pattern in patterns:
            for tech in pattern['technology_stack']:
                tech_vuln_correlation[tech][pattern['vulnerability_type']] += pattern['occurrence_count']

        return {
            tech: dict(vulns.most_common(3))
            for tech, vulns in tech_vuln_correlation.items()
        }

    def _analyze_waf_bypass_patterns(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze WAF bypass patterns."""
        waf_patterns = defaultdict(list)

        for pattern in patterns:
            if pattern['waf_detected']:
                waf_patterns[pattern['waf_detected']].append({
                    'vulnerability_type': pattern['vulnerability_type'],
                    'context': pattern['context'],
                    'occurrence_count': pattern['occurrence_count']
                })

        return dict(waf_patterns)

    def _generate_recommendations(self, patterns: List[Dict[str, Any]]) -> List[str]:
        """Generate scanning recommendations based on patterns."""
        recommendations = []

        # Find most successful vulnerability types
        type_counts = Counter(p['vulnerability_type'] for p in patterns)
        top_types = type_counts.most_common(3)

        for vtype, count in top_types:
            recommendations.append(
                f"Focus on {vtype} vulnerabilities (found {count} times in similar targets)"
            )

        # Find most successful contexts
        context_counts = Counter(p['context'] for p in patterns if p['context'])
        top_contexts = context_counts.most_common(3)

        for context, count in top_contexts:
            recommendations.append(
                f"Test {context} injection context (successful {count} times)"
            )

        return recommendations


class AdaptiveScanningEngine:
    """Adaptive scanning engine that learns from WAF bypass techniques."""

    def __init__(self):
        self.logger = setup_logger(f"{__name__}.AdaptiveScanningEngine")
        self.bypass_strategies = defaultdict(list)
        self.learning_rate = 0.1

    def learn_from_scan_result(self, target: Target, payload: Payload,
                               success: bool, response: str = "") -> None:
        """
        Learn from scan results to improve future bypass strategies.
        
        Args:
            target: Target that was scanned
            payload: Payload that was used
            success: Whether the payload was successful
            response: Server response (for WAF detection)
        """
        # Update payload statistics
        knowledge_base.update_payload_stats(payload.payload_hash, success)

        # Learn WAF bypass techniques
        if target.waf_detected:
            self._learn_waf_bypass(target.waf_detected, payload, success, response)

        # Learn technology-specific techniques
        for tech in target.technology_stack:
            self._learn_technology_bypass(tech, payload, success)

    def _learn_waf_bypass(self, waf_name: str, payload: Payload,
                          success: bool, response: str = "") -> None:
        """Learn WAF-specific bypass techniques."""
        if success:
            # Extract bypass techniques from successful payload
            techniques = self._extract_bypass_techniques(payload.payload)

            for technique in techniques:
                if technique not in self.bypass_strategies[waf_name]:
                    self.bypass_strategies[waf_name].append(technique)
                    self.logger.info(f"Learned new bypass technique for {waf_name}: {technique}")

        # Update WAF effectiveness in payload
        if waf_name not in payload.waf_effectiveness:
            payload.waf_effectiveness[waf_name] = 0.0

        # Update effectiveness using exponential moving average
        current_effectiveness = payload.waf_effectiveness[waf_name]
        new_effectiveness = current_effectiveness + self.learning_rate * (
                (1.0 if success else 0.0) - current_effectiveness
        )
        payload.waf_effectiveness[waf_name] = new_effectiveness

    def _learn_technology_bypass(self, technology: str, payload: Payload, success: bool) -> None:
        """Learn technology-specific bypass techniques."""
        if success:
            techniques = self._extract_bypass_techniques(payload.payload)

            for technique in techniques:
                tech_technique = f"{technology}:{technique}"
                if tech_technique not in payload.bypass_techniques:
                    payload.bypass_techniques.append(tech_technique)

    def _extract_bypass_techniques(self, payload: str) -> List[str]:
        """Extract bypass techniques from payload."""
        techniques = []

        # Common bypass patterns
        patterns = {
            'encoding': [r'%[0-9a-fA-F]{2}', r'&#\d+;', r'&#x[0-9a-fA-F]+;'],
            'case_variation': [r'[A-Z]+.*[a-z]+|[a-z]+.*[A-Z]+'],
            'comment_insertion': [r'/\*.*?\*/', r'<!--.*?-->'],
            'whitespace_manipulation': [r'\s{2,}', r'\t', r'\n', r'\r'],
            'quote_variation': [r"'[^']*'", r'"[^"]*"', r'`[^`]*`'],
            'concatenation': [r'\+', r'\.concat\(', r'String\.fromCharCode'],
            'event_handlers': [r'on[a-z]+\s*=', r'javascript:'],
            'protocol_tricks': [r'data:', r'vbscript:', r'javascript:'],
        }

        for technique_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, payload, re.IGNORECASE):
                    techniques.append(technique_type)
                    break

        return techniques

    def get_adaptive_payloads(self, target: Target, base_payloads: List[Payload]) -> List[Payload]:
        """
        Generate adaptive payloads based on target characteristics and learned techniques.
        
        Args:
            target: Target to generate payloads for
            base_payloads: Base payloads to adapt
            
        Returns:
            List[Payload]: Adapted payloads
        """
        adaptive_payloads = []

        for base_payload in base_payloads:
            # Create variations based on learned techniques
            if target.waf_detected and target.waf_detected in self.bypass_strategies:
                techniques = self.bypass_strategies[target.waf_detected]

                for technique in techniques[:5]:  # Limit to top 5 techniques
                    adapted_payload = self._apply_bypass_technique(base_payload, technique)
                    if adapted_payload:
                        adaptive_payloads.append(adapted_payload)

            # Apply technology-specific adaptations
            for tech in target.technology_stack:
                tech_payloads = self._adapt_for_technology(base_payload, tech)
                adaptive_payloads.extend(tech_payloads)

        return adaptive_payloads

    def _apply_bypass_technique(self, payload: Payload, technique: str) -> Optional[Payload]:
        """Apply a specific bypass technique to a payload."""
        original = payload.payload
        adapted = original

        if technique == 'encoding':
            # URL encode some characters
            adapted = re.sub(r'[<>"\']', lambda m: f'%{ord(m.group(0)):02x}', adapted)
        elif technique == 'case_variation':
            # Mix case
            adapted = ''.join(c.upper() if i % 2 == 0 else c.lower()
                              for i, c in enumerate(adapted))
        elif technique == 'comment_insertion':
            # Insert HTML comments
            adapted = adapted.replace('<', '<!---->').replace('>', '<!---->')
        elif technique == 'whitespace_manipulation':
            # Add tabs and spaces
            adapted = adapted.replace(' ', '\t ')

        if adapted != original:
            new_payload = Payload(
                payload=adapted,
                payload_type=payload.payload_type,
                contexts=payload.contexts.copy(),
                bypass_techniques=payload.bypass_techniques + [technique]
            )
            return new_payload

        return None

    def _adapt_for_technology(self, payload: Payload, technology: str) -> List[Payload]:
        """Adapt payload for specific technology."""
        adaptations = []

        if technology == 'php':
            # PHP-specific adaptations
            if 'script' in payload.payload.lower():
                adapted = payload.payload.replace('<script', '<?php echo "<script"?>')
                adaptations.append(Payload(
                    payload=adapted,
                    payload_type=payload.payload_type,
                    contexts=['php'] + payload.contexts,
                    bypass_techniques=payload.bypass_techniques + ['php_injection']
                ))

        elif technology == 'asp':
            # ASP.NET-specific adaptations
            if 'script' in payload.payload.lower():
                adapted = payload.payload.replace('<script', '<%="<script"%>')
                adaptations.append(Payload(
                    payload=adapted,
                    payload_type=payload.payload_type,
                    contexts=['asp'] + payload.contexts,
                    bypass_techniques=payload.bypass_techniques + ['asp_injection']
                ))

        return adaptations


class SimilarityMatcher:
    """Matches similar scan results to avoid redundant testing."""

    def __init__(self):
        self.logger = setup_logger(f"{__name__}.SimilarityMatcher")
        self.vectorizer = TfidfVectorizer(max_features=500)
        self.similarity_threshold = 0.8

    def find_similar_results(self, current_target: Target,
                             current_payloads: List[str]) -> List[Dict[str, Any]]:
        """
        Find similar previous scan results to avoid redundant testing.
        
        Args:
            current_target: Target being scanned
            current_payloads: Payloads being tested
            
        Returns:
            List[Dict[str, Any]]: Similar scan results with recommendations
        """
        # Get similar targets
        similar_targets = knowledge_base.get_similar_targets(current_target)

        if not similar_targets:
            return []

        similar_results = []

        for target in similar_targets:
            # Calculate target similarity
            target_similarity = self._calculate_target_similarity(current_target, target)

            if target_similarity > self.similarity_threshold:
                # Get vulnerability patterns for this target
                patterns = knowledge_base.get_vulnerability_patterns(target.domain)

                similar_results.append({
                    'target': target,
                    'similarity_score': target_similarity,
                    'vulnerability_patterns': patterns,
                    'recommendations': self._generate_skip_recommendations(patterns, current_payloads)
                })

        return similar_results

    def _calculate_target_similarity(self, target1: Target, target2: Target) -> float:
        """Calculate similarity between two targets."""
        similarity_score = 0.0
        total_factors = 5

        # Technology stack similarity
        if target1.technology_stack and target2.technology_stack:
            common_tech = set(target1.technology_stack) & set(target2.technology_stack)
            tech_similarity = len(common_tech) / max(len(target1.technology_stack),
                                                     len(target2.technology_stack))
            similarity_score += tech_similarity

        # CMS similarity
        if target1.cms_detected == target2.cms_detected and target1.cms_detected:
            similarity_score += 1.0

        # Framework similarity
        if target1.framework_detected == target2.framework_detected and target1.framework_detected:
            similarity_score += 1.0

        # WAF similarity
        if target1.waf_detected == target2.waf_detected and target1.waf_detected:
            similarity_score += 1.0

        # Server signature similarity
        if target1.server_signature and target2.server_signature:
            if target1.server_signature.split('/')[0] == target2.server_signature.split('/')[0]:
                similarity_score += 1.0

        return similarity_score / total_factors

    def _generate_skip_recommendations(self, patterns: List[Dict[str, Any]],
                                       current_payloads: List[str]) -> List[str]:
        """Generate recommendations for skipping certain tests."""
        recommendations = []

        # If no vulnerabilities found in similar targets, recommend skipping
        if not patterns:
            recommendations.append("No vulnerabilities found in similar targets - consider reducing payload count")

        # If specific vulnerability types were unsuccessful, recommend skipping
        unsuccessful_types = []
        for pattern in patterns:
            if pattern['avg_confidence'] < 0.3:
                unsuccessful_types.append(pattern['vulnerability_type'])

        if unsuccessful_types:
            recommendations.append(f"Low success rate for: {', '.join(unsuccessful_types)}")

        return recommendations


class RAGSystem:
    """Main RAG system that coordinates all learning components."""

    def __init__(self):
        self.logger = setup_logger(f"{__name__}.RAGSystem")
        self.target_analyzer = TargetAnalyzer()
        self.payload_engine = PayloadRecommendationEngine()
        self.pattern_recognizer = VulnerabilityPatternRecognizer()
        self.adaptive_engine = AdaptiveScanningEngine()
        self.similarity_matcher = SimilarityMatcher()

    def analyze_and_recommend(self, url: str, response_headers: Dict[str, str],
                              response_body: str = "") -> Dict[str, Any]:
        """
        Complete RAG analysis and recommendations for a target.
        
        Args:
            url: Target URL
            response_headers: HTTP response headers
            response_body: Response body content
            
        Returns:
            Dict[str, Any]: Complete analysis and recommendations
        """
        self.logger.info(f"Starting RAG analysis for {url}")

        # Analyze target
        target = self.target_analyzer.analyze_target(url, response_headers, response_body)

        # Store target in knowledge base
        target_id = knowledge_base.store_target(target)
        target.id = target_id

        # Get payload recommendations
        payload_recommendations = self.payload_engine.recommend_payloads(target)

        # Analyze vulnerability patterns
        vuln_patterns = self.pattern_recognizer.analyze_vulnerability_patterns(target.domain)

        # Find similar results
        recommended_payloads = [p[0].payload for p in payload_recommendations[:20]]
        similar_results = self.similarity_matcher.find_similar_results(target, recommended_payloads)

        analysis = {
            'target': target,
            'payload_recommendations': payload_recommendations,
            'vulnerability_patterns': vuln_patterns,
            'similar_results': similar_results,
            'intelligence_summary': self._generate_intelligence_summary(
                target, payload_recommendations, vuln_patterns, similar_results
            )
        }

        self.logger.info(f"RAG analysis complete for {url}")

        return analysis

    def learn_from_scan(self, scan_session: ScanSession, results: List[Dict[str, Any]]) -> None:
        """
        Learn from completed scan results.
        
        Args:
            scan_session: Completed scan session
            results: Scan results with vulnerabilities and payload effectiveness
        """
        self.logger.info(f"Learning from scan session {scan_session.id}")

        # Store scan session
        knowledge_base.store_scan_session(scan_session)

        # Process each result
        for result in results:
            if 'payload' in result and 'success' in result:
                payload = result['payload']
                target = result.get('target')

                if target:
                    self.adaptive_engine.learn_from_scan_result(
                        target, payload, result['success'], result.get('response', '')
                    )

        self.logger.info("Learning from scan complete")

    def _generate_intelligence_summary(self, target: Target,
                                       payload_recommendations: List[Tuple[Payload, float]],
                                       vuln_patterns: Dict[str, Any],
                                       similar_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate human-readable intelligence summary."""
        summary = {
            'target_profile': {
                'technologies': target.technology_stack,
                'cms': target.cms_detected,
                'waf': target.waf_detected,
                'risk_level': self._assess_risk_level(target, vuln_patterns)
            },
            'recommendations': {
                'top_payloads': len(payload_recommendations),
                'similar_targets_found': len(similar_results),
                'predicted_success_rate': self._predict_success_rate(payload_recommendations)
            },
            'insights': []
        }

        # Generate insights
        if target.waf_detected:
            summary['insights'].append(f"WAF detected: {target.waf_detected} - using specialized bypass techniques")

        if vuln_patterns['total_vulnerabilities'] > 0:
            top_vuln = max(vuln_patterns['vulnerability_types']['distribution'].items(),
                           key=lambda x: x[1])
            summary['insights'].append(f"Most common vulnerability in similar targets: {top_vuln[0]}")

        if similar_results:
            summary['insights'].append(f"Found {len(similar_results)} similar targets with known patterns")

        return summary

    def _assess_risk_level(self, target: Target, vuln_patterns: Dict[str, Any]) -> str:
        """Assess risk level based on target characteristics and patterns."""
        risk_score = 0

        # Technology stack risks
        high_risk_tech = ['php', 'asp', 'jsp']
        for tech in target.technology_stack:
            if tech in high_risk_tech:
                risk_score += 2
            else:
                risk_score += 1

        # CMS risks
        if target.cms_detected:
            risk_score += 3

        # WAF presence (reduces risk)
        if target.waf_detected:
            risk_score -= 2

        # Historical vulnerability patterns
        if vuln_patterns['total_vulnerabilities'] > 10:
            risk_score += 3

        if risk_score <= 2:
            return "LOW"
        elif risk_score <= 5:
            return "MEDIUM"
        else:
            return "HIGH"

    def _predict_success_rate(self, payload_recommendations: List[Tuple[Payload, float]]) -> float:
        """Predict overall success rate based on recommended payloads."""
        if not payload_recommendations:
            return 0.0

        # Calculate weighted average of top payloads
        top_payloads = payload_recommendations[:10]
        total_weight = sum(score for _, score in top_payloads)

        if total_weight == 0:
            return 0.0

        weighted_success = sum(payload.success_rate * score
                               for payload, score in top_payloads)

        return weighted_success / total_weight


# Global RAG system instance
rag_system = RAGSystem()
