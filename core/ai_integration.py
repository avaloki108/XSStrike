"""
AI Integration Module for XSStrike.

This module integrates the AI/RAG system with the core scanning engine,
enabling intelligent decision-making, adaptive payload selection, and
continuous learning from scan results.
"""

import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

from core.knowledge_base import knowledge_base, Target, Payload, Vulnerability, ScanSession
from core.rag_system import rag_system
from core.payload_generator import payload_generator, InjectionContext
from core.smart_payload_selector import smart_selector  # ADD SMART SELECTOR
from core.engine import ScanOptions, ScanResult, ScanMode
from core.log import setup_logger

logger = setup_logger(__name__)


class IntelligentScanOrchestrator:
    """
    Orchestrates intelligent scanning using AI/RAG components.
    
    This class coordinates between the knowledge base, RAG system, payload generator,
    and scanning engine to provide intelligent, adaptive scanning capabilities.
    """

    def __init__(self):
        self.logger = setup_logger(__name__)
        self.learning_enabled = True
        self.min_confidence_threshold = 0.3
        self.max_adaptive_payloads = 100

    def prepare_intelligent_scan(self, scan_options: ScanOptions) -> Dict[str, Any]:
        """
        Prepare an intelligent scan using AI/RAG analysis.
        
        Args:
            scan_options: Basic scan options
            
        Returns:
            Dict[str, Any]: Enhanced scan configuration with AI recommendations
        """
        self.logger.info(f"Preparing intelligent scan for {scan_options.target}")

        # Perform initial target analysis
        target_analysis = self._analyze_target(scan_options.target, scan_options.headers or {})

        # Get RAG recommendations
        rag_analysis = rag_system.analyze_and_recommend(
            scan_options.target,
            scan_options.headers or {},
            ""  # We'll get the response body during scanning
        )

        # Generate intelligent payload recommendations
        intelligent_payloads = self._generate_intelligent_payloads(
            target_analysis, rag_analysis
        )

        # Optimize scan strategy based on intelligence
        scan_strategy = self._optimize_scan_strategy(
            scan_options, target_analysis, rag_analysis
        )

        return {
            'target_analysis': target_analysis,
            'rag_analysis': rag_analysis,
            'intelligent_payloads': intelligent_payloads,
            'scan_strategy': scan_strategy,
            'original_options': scan_options
        }

    def execute_intelligent_scan(self, intelligent_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an intelligent scan with AI-driven decision making.
        
        Args:
            intelligent_config: Configuration from prepare_intelligent_scan
            
        Returns:
            Dict[str, Any]: Comprehensive scan results with intelligence insights
        """
        target_analysis = intelligent_config['target_analysis']
        scan_strategy = intelligent_config['scan_strategy']
        intelligent_payloads = intelligent_config['intelligent_payloads']

        self.logger.info(f"Executing intelligent scan with {len(intelligent_payloads)} AI-selected payloads")

        # Initialize scan session
        scan_session = ScanSession(
            target_id=target_analysis.id,
            scan_type="ai_enhanced",
            total_payloads=len(intelligent_payloads),
            scan_config=scan_strategy
        )

        # Execute scan phases
        results = {
            'target': target_analysis,
            'vulnerabilities': [],
            'payload_results': [],
            'learning_data': [],
            'scan_statistics': {
                'total_payloads_tested': 0,
                'successful_payloads': 0,
                'vulnerabilities_found': 0,
                'scan_efficiency': 0.0
            }
        }

        # Phase 1: High-confidence payloads
        high_confidence_payloads = [
                                       p for p in intelligent_payloads
                                       if p.success_rate >= self.min_confidence_threshold
                                   ][:20]  # Limit to top 20

        phase1_results = self._execute_payload_phase(
            "high_confidence", high_confidence_payloads, target_analysis, scan_strategy
        )
        results['payload_results'].extend(phase1_results)

        # Phase 2: Adaptive payloads based on Phase 1 results
        if self._should_continue_scanning(phase1_results, scan_strategy):
            adaptive_payloads = self._generate_adaptive_payloads_from_results(
                phase1_results, target_analysis
            )

            phase2_results = self._execute_payload_phase(
                "adaptive", adaptive_payloads, target_analysis, scan_strategy
            )
            results['payload_results'].extend(phase2_results)

        # Process and learn from results
        self._process_scan_results(results, scan_session)

        # Update scan statistics
        results['scan_statistics'] = self._calculate_scan_statistics(results)

        self.logger.info(
            f"Intelligent scan completed with {results['scan_statistics']['vulnerabilities_found']} vulnerabilities")

        return results

    def _analyze_target(self, url: str, headers: Dict[str, str]) -> Target:
        """Analyze target and store in knowledge base."""
        # Use RAG system's target analyzer
        target = rag_system.target_analyzer.analyze_target(url, headers, "")

        # Store in knowledge base
        target_id = knowledge_base.store_target(target)
        target.id = target_id

        return target

    def _generate_intelligent_payloads(self, target: Target,
                                       rag_analysis: Dict[str, Any]) -> List[Payload]:
        """Generate intelligent payloads using all AI components."""
        payloads = []

        # Get RAG-recommended payloads
        rag_payloads = rag_analysis.get('payload_recommendations', [])
        payloads.extend([p[0] for p in rag_payloads[:30]])

        # Generate context-aware payloads for common contexts
        common_contexts = ['html', 'attribute', 'script', 'url']

        for context_type in common_contexts:
            context = InjectionContext(
                context_type=context_type,
                waf_present=bool(target.waf_detected),
                waf_type=target.waf_detected or ""
            )

            context_payloads = payload_generator.generate_payloads(
                target, context, max_payloads=15
            )
            payloads.extend(context_payloads)

        # Get adaptive payloads from learning engine
        if rag_payloads:
            base_payloads = [p[0] for p in rag_payloads[:10]]
            adaptive_payloads = rag_system.adaptive_engine.get_adaptive_payloads(
                target, base_payloads
            )
            payloads.extend(adaptive_payloads)

        # Use smart payload selector to optimize the payloads
        scored_payloads = smart_selector.select_optimal_payloads(target, max_payloads=self.max_adaptive_payloads)
        optimized_payloads = [sp.payload for sp in scored_payloads]

        # Deduplicate and sort by success rate
        unique_payloads = self._deduplicate_payloads(optimized_payloads)
        unique_payloads.sort(key=lambda p: p.success_rate, reverse=True)

        return unique_payloads[:self.max_adaptive_payloads]

    def _optimize_scan_strategy(self, scan_options: ScanOptions, target: Target,
                                rag_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize scan strategy based on intelligence."""
        strategy = {
            'priority_contexts': [],
            'waf_bypass_strategy': None,
            'technology_adaptations': [],
            'similarity_optimizations': [],
            'efficiency_settings': {}
        }

        # Determine priority contexts from vulnerability patterns
        vuln_patterns = rag_analysis.get('vulnerability_patterns', {})
        if vuln_patterns.get('context_patterns'):
            most_common_contexts = vuln_patterns['context_patterns'].get('most_common_contexts', {})
            strategy['priority_contexts'] = list(most_common_contexts.keys())[:3]

        # WAF bypass strategy
        if target.waf_detected:
            strategy['waf_bypass_strategy'] = {
                'waf_type': target.waf_detected,
                'bypass_techniques': self._get_waf_bypass_techniques(target.waf_detected),
                'payload_encoding': True
            }

        # Technology-specific adaptations
        for tech in target.technology_stack:
            strategy['technology_adaptations'].append({
                'technology': tech,
                'specific_payloads': True,
                'injection_points': self._get_tech_injection_points(tech)
            })

        # Similarity-based optimizations
        similar_results = rag_analysis.get('similar_results', [])
        if similar_results:
            strategy['similarity_optimizations'] = [
                {
                    'similar_target': result['target'].domain,
                    'similarity_score': result['similarity_score'],
                    'skip_recommendations': result.get('recommendations', [])
                }
                for result in similar_results[:3]
            ]

        # Efficiency settings based on risk assessment
        intelligence_summary = rag_analysis.get('intelligence_summary', {})
        risk_level = intelligence_summary.get('target_profile', {}).get('risk_level', 'MEDIUM')

        if risk_level == 'HIGH':
            strategy['efficiency_settings'] = {
                'max_payload_ratio': 1.0,
                'deep_scanning': True,
                'mutation_enabled': True
            }
        elif risk_level == 'LOW':
            strategy['efficiency_settings'] = {
                'max_payload_ratio': 0.3,
                'deep_scanning': False,
                'mutation_enabled': False
            }
        else:  # MEDIUM
            strategy['efficiency_settings'] = {
                'max_payload_ratio': 0.6,
                'deep_scanning': True,
                'mutation_enabled': True
            }

        return strategy

    def _execute_payload_phase(self, phase_name: str, payloads: List[Payload],
                               target: Target, strategy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute a phase of payload testing."""
        self.logger.info(f"Executing {phase_name} phase with {len(payloads)} payloads")

        results = []

        for i, payload in enumerate(payloads):
            # Simulate payload testing (in real implementation, this would use the actual scanner)
            success = self._test_payload(payload, target, strategy)

            result = {
                'payload': payload,
                'success': success,
                'phase': phase_name,
                'index': i,
                'target': target,
                'response': f"simulated_response_for_{payload.payload_hash}",
                'confidence': payload.success_rate
            }

            results.append(result)

            # Learn from immediate results
            if self.learning_enabled:
                rag_system.adaptive_engine.learn_from_scan_result(
                    target, payload, success, result['response']
                )

            # Early stopping if vulnerability found and strategy allows it
            if success and not strategy.get('efficiency_settings', {}).get('deep_scanning', True):
                self.logger.info(f"Early stopping after finding vulnerability in {phase_name} phase")
                break

        return results

    def _test_payload(self, payload: Payload, target: Target,
                      strategy: Dict[str, Any]) -> bool:
        """
        Simulate payload testing (placeholder for actual implementation).
        
        In a real implementation, this would:
        1. Send the payload to the target
        2. Analyze the response
        3. Determine if XSS vulnerability exists
        4. Return success/failure
        """
        # Simulate success based on payload success rate and target characteristics
        base_probability = payload.success_rate

        # Adjust based on WAF
        if target.waf_detected and target.waf_detected in payload.waf_effectiveness:
            waf_factor = payload.waf_effectiveness[target.waf_detected]
            base_probability *= (1.0 + waf_factor)

        # Random simulation
        import random
        return random.random() < base_probability

    def _should_continue_scanning(self, phase_results: List[Dict[str, Any]],
                                  strategy: Dict[str, Any]) -> bool:
        """Determine if scanning should continue to next phase."""
        successful_results = [r for r in phase_results if r['success']]

        # If we found vulnerabilities and deep scanning is disabled, stop
        if successful_results and not strategy.get('efficiency_settings', {}).get('deep_scanning', True):
            return False

        # If no vulnerabilities found, continue with adaptive phase
        if not successful_results:
            return True

        # If mutation is enabled and we have some success, continue
        if strategy.get('efficiency_settings', {}).get('mutation_enabled', False):
            return True

        return False

    def _generate_adaptive_payloads_from_results(self, phase_results: List[Dict[str, Any]],
                                                 target: Target) -> List[Payload]:
        """Generate adaptive payloads based on phase 1 results."""
        successful_payloads = [r['payload'] for r in phase_results if r['success']]
        failed_payloads = [r['payload'] for r in phase_results if not r['success']]

        adaptive_payloads = []

        # Generate mutations of successful payloads
        for payload in successful_payloads[:5]:  # Top 5 successful
            mutations = self._generate_payload_mutations(payload, target)
            adaptive_payloads.extend(mutations)

        # Generate variations that avoid failed patterns
        if failed_payloads:
            failed_patterns = self._extract_failure_patterns(failed_payloads)
            variation_payloads = self._generate_failure_avoiding_payloads(
                successful_payloads, failed_patterns, target
            )
            adaptive_payloads.extend(variation_payloads)

        return adaptive_payloads[:20]  # Limit adaptive payloads

    def _generate_payload_mutations(self, payload: Payload, target: Target) -> List[Payload]:
        """Generate mutations of a successful payload."""
        # Use the adaptive engine to generate mutations
        mutations = rag_system.adaptive_engine.get_adaptive_payloads(target, [payload])
        return mutations[:5]  # Limit mutations per payload

    def _extract_failure_patterns(self, failed_payloads: List[Payload]) -> List[str]:
        """Extract common patterns from failed payloads."""
        patterns = []

        for payload in failed_payloads:
            # Extract common failure patterns
            if 'script' in payload.payload.lower():
                patterns.append('script_tag')
            if 'alert' in payload.payload.lower():
                patterns.append('alert_function')
            if '<' in payload.payload and '>' in payload.payload:
                patterns.append('html_tags')

        return list(set(patterns))

    def _generate_failure_avoiding_payloads(self, successful_payloads: List[Payload],
                                            failed_patterns: List[str], target: Target) -> List[Payload]:
        """Generate payloads that avoid failed patterns."""
        avoiding_payloads = []

        for payload in successful_payloads[:3]:
            # Create variations that avoid failed patterns
            modified_payload = payload.payload

            if 'script_tag' in failed_patterns:
                modified_payload = modified_payload.replace('<script>', '<img onerror=')
            if 'alert_function' in failed_patterns:
                modified_payload = modified_payload.replace('alert', 'prompt')

            if modified_payload != payload.payload:
                new_payload = Payload(
                    payload=modified_payload,
                    payload_type=payload.payload_type,
                    contexts=payload.contexts.copy(),
                    bypass_techniques=payload.bypass_techniques + ['failure_avoidance'],
                    success_rate=payload.success_rate * 0.8
                )
                avoiding_payloads.append(new_payload)

        return avoiding_payloads

    def _process_scan_results(self, results: Dict[str, Any], scan_session: ScanSession) -> None:
        """Process and learn from scan results."""
        successful_results = [r for r in results['payload_results'] if r['success']]

        # Store vulnerabilities
        for result in successful_results:
            vulnerability = Vulnerability(
                target_id=results['target'].id,
                payload_id=self._store_payload_if_needed(result['payload']),
                vulnerability_type="xss",
                severity="medium",  # Would be determined by actual analysis
                context="unknown",  # Would be extracted from response
                confidence=result['confidence'],
                evidence=result['response'][:500]  # Truncate evidence
            )

            vuln_id = knowledge_base.store_vulnerability(vulnerability)
            results['vulnerabilities'].append(vulnerability)

        # Update scan session
        scan_session.successful_payloads = len(successful_results)
        scan_session.vulnerabilities_found = len(results['vulnerabilities'])
        scan_session.completed_at = time.time()
        scan_session.duration = scan_session.completed_at - scan_session.started_at

        knowledge_base.store_scan_session(scan_session)

        # Learn from the complete scan
        if self.learning_enabled:
            learning_data = [
                {
                    'payload': r['payload'],
                    'target': r['target'],
                    'success': r['success'],
                    'response': r['response']
                }
                for r in results['payload_results']
            ]

            rag_system.learn_from_scan(scan_session, learning_data)

    def _store_payload_if_needed(self, payload: Payload) -> int:
        """Store payload in knowledge base if not already stored."""
        if not payload.id:
            payload_id = knowledge_base.store_payload(payload)
            payload.id = payload_id
        return payload.id

    def _calculate_scan_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive scan statistics."""
        total_payloads = len(results['payload_results'])
        successful_payloads = len([r for r in results['payload_results'] if r['success']])
        vulnerabilities_found = len(results['vulnerabilities'])

        efficiency = (successful_payloads / total_payloads) if total_payloads > 0 else 0.0

        return {
            'total_payloads_tested': total_payloads,
            'successful_payloads': successful_payloads,
            'vulnerabilities_found': vulnerabilities_found,
            'scan_efficiency': efficiency,
            'success_rate': efficiency,
            'unique_vulnerabilities': len(set(v.vulnerability_type for v in results['vulnerabilities']))
        }

    def _deduplicate_payloads(self, payloads: List[Payload]) -> List[Payload]:
        """Remove duplicate payloads based on hash."""
        seen_hashes = set()
        unique_payloads = []

        for payload in payloads:
            if payload.payload_hash not in seen_hashes:
                seen_hashes.add(payload.payload_hash)
                unique_payloads.append(payload)

        return unique_payloads

    def _get_waf_bypass_techniques(self, waf_type: str) -> List[str]:
        """Get WAF-specific bypass techniques."""
        waf_techniques = {
            'cloudflare': ['unicode_bypass', 'case_variation', 'encoding'],
            'modsecurity': ['comment_insertion', 'concatenation', 'hex_encoding'],
            'incapsula': ['whitespace_manipulation', 'double_encoding'],
            'akamai': ['protocol_tricks', 'case_variation'],
        }

        return waf_techniques.get(waf_type.lower(), ['encoding', 'case_variation'])

    def _get_tech_injection_points(self, technology: str) -> List[str]:
        """Get technology-specific injection points."""
        tech_points = {
            'php': ['form_input', 'url_parameter', 'header_injection'],
            'asp': ['viewstate', 'form_input', 'url_parameter'],
            'jsp': ['request_parameter', 'session_attribute'],
            'python': ['template_injection', 'form_input'],
            'node': ['template_injection', 'json_input'],
        }

        return tech_points.get(technology.lower(), ['form_input', 'url_parameter'])


# Global intelligent scan orchestrator
intelligent_orchestrator = IntelligentScanOrchestrator()
