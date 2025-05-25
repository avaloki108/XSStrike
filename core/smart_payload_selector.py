"""
Smart Payload Selector for XSStrike.

This module implements intelligent payload selection to reduce the number
of requests while maximizing detection effectiveness based on target
characteristics, historical success rates, and context analysis.
"""

import time
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass
from enum import Enum

from core.knowledge_base import knowledge_base, Target, Payload
from core.rag_system import rag_system
from core.log import setup_logger

logger = setup_logger(__name__)


class PayloadCategory(Enum):
    """Categories of XSS payloads for intelligent selection."""
    BASIC = "basic"
    ADVANCED = "advanced"
    WAF_BYPASS = "waf_bypass"
    CONTEXT_SPECIFIC = "context_specific"
    POLYGLOT = "polyglot"
    DOM_BASED = "dom_based"


@dataclass
class PayloadScore:
    """Scoring information for payload selection."""
    payload: Payload
    base_score: float
    context_bonus: float
    waf_penalty: float
    recency_factor: float
    diversity_bonus: float
    final_score: float
    category: PayloadCategory
    estimated_success_probability: float


class SmartPayloadSelector:
    """
    Intelligent payload selector that optimizes scan efficiency.
    
    This selector uses multiple factors to choose the most effective payloads:
    - Historical success rates
    - Target characteristics
    - Context relevance
    - WAF bypass capabilities
    - Payload diversity
    - Request reduction strategies
    """

    def __init__(self):
        self.logger = setup_logger(__name__)
        self.category_weights = {
            PayloadCategory.BASIC: 1.0,
            PayloadCategory.ADVANCED: 0.8,
            PayloadCategory.WAF_BYPASS: 1.2,
            PayloadCategory.CONTEXT_SPECIFIC: 1.1,
            PayloadCategory.POLYGLOT: 0.9,
            PayloadCategory.DOM_BASED: 0.7
        }
        self.min_payloads = 5
        self.max_payloads = 50
        self.diversity_threshold = 0.7

    def select_optimal_payloads(self, target: Target, context: str = "",
                                max_payloads: int = 25) -> List[PayloadScore]:
        """
        Select optimal payloads for a target to minimize requests while maximizing success.
        
        Args:
            target: Target characteristics
            context: Injection context (html, script, attribute, etc.)
            max_payloads: Maximum number of payloads to select
            
        Returns:
            List[PayloadScore]: Optimally selected and scored payloads
        """
        self.logger.info(f"Selecting optimal payloads for {target.domain}")

        # Get candidate payloads from various sources
        candidates = self._gather_candidate_payloads(target, context)

        # Score all candidates
        scored_payloads = self._score_payloads(candidates, target, context)

        # Apply intelligent selection strategies
        selected = self._apply_selection_strategies(scored_payloads, target, max_payloads)

        # Final optimization
        optimized = self._optimize_payload_set(selected, target)

        self.logger.info(f"Selected {len(optimized)} optimal payloads from {len(candidates)} candidates")

        return optimized

    def _gather_candidate_payloads(self, target: Target, context: str) -> List[Payload]:
        """Gather candidate payloads from multiple sources."""
        candidates = []

        # Get historical successful payloads
        historical = knowledge_base.get_successful_payloads(limit=100, min_success_rate=0.1)
        candidates.extend(historical)

        # Get context-specific payloads
        if context:
            context_payloads = knowledge_base.get_payloads_for_context(context, limit=50)
            candidates.extend(context_payloads)

        # Get RAG recommendations
        try:
            rag_analysis = rag_system.analyze_and_recommend(target.url, target.response_headers, "")
            rag_payloads = [p[0] for p in rag_analysis.get('payload_recommendations', [])]
            candidates.extend(rag_payloads)
        except Exception as e:
            self.logger.warning(f"RAG recommendations failed: {e}")

        # Get similar target payloads
        similar_targets = knowledge_base.get_similar_targets(target, limit=10)
        for similar_target in similar_targets:
            # Get payloads that worked on similar targets
            similar_payloads = knowledge_base.get_successful_payloads(limit=20, min_success_rate=0.2)
            candidates.extend(similar_payloads)

        # Remove duplicates
        unique_candidates = []
        seen_hashes = set()
        for payload in candidates:
            if payload.payload_hash not in seen_hashes:
                seen_hashes.add(payload.payload_hash)
                unique_candidates.append(payload)

        return unique_candidates

    def _score_payloads(self, payloads: List[Payload], target: Target,
                        context: str) -> List[PayloadScore]:
        """Score payloads based on multiple factors."""
        scored_payloads = []

        for payload in payloads:
            # Base score from historical success rate
            base_score = payload.success_rate if payload.total_attempts > 0 else 0.5

            # Context relevance bonus
            context_bonus = 0.0
            if context and context in payload.contexts:
                context_bonus = 0.3
            elif payload.contexts:
                context_bonus = 0.1  # Some context is better than none

            # WAF penalty/bonus
            waf_penalty = 0.0
            if target.waf_detected:
                if target.waf_detected in payload.waf_effectiveness:
                    # Use WAF effectiveness data
                    effectiveness = payload.waf_effectiveness[target.waf_detected]
                    waf_penalty = effectiveness - 0.5  # Can be bonus or penalty
                else:
                    # Unknown WAF effectiveness - penalty
                    waf_penalty = -0.2

            # Recency factor
            recency_factor = 0.0
            if payload.last_used:
                days_since_used = (time.time() - payload.last_used) / (24 * 3600)
                if days_since_used < 7:
                    recency_factor = 0.1  # Recently successful
                elif days_since_used > 90:
                    recency_factor = -0.1  # Too old

            # Technology stack alignment
            tech_bonus = self._calculate_tech_alignment(payload, target)

            # Calculate final score
            final_score = (
                    base_score +
                    context_bonus +
                    waf_penalty +
                    recency_factor +
                    tech_bonus
            )
            final_score = max(0.0, min(1.0, final_score))  # Clamp to [0, 1]

            # Categorize payload
            category = self._categorize_payload(payload)

            # Estimate success probability
            success_prob = self._estimate_success_probability(payload, target, final_score)

            scored_payload = PayloadScore(
                payload=payload,
                base_score=base_score,
                context_bonus=context_bonus,
                waf_penalty=waf_penalty,
                recency_factor=recency_factor,
                diversity_bonus=0.0,  # Will be calculated later
                final_score=final_score,
                category=category,
                estimated_success_probability=success_prob
            )

            scored_payloads.append(scored_payload)

        return sorted(scored_payloads, key=lambda x: x.final_score, reverse=True)

    def _calculate_tech_alignment(self, payload: Payload, target: Target) -> float:
        """Calculate how well a payload aligns with target technology."""
        if not target.technology_stack:
            return 0.0

        alignment_score = 0.0

        # Check bypass techniques for technology-specific methods
        for tech in target.technology_stack:
            tech_lower = tech.lower()
            for technique in payload.bypass_techniques:
                if tech_lower in technique.lower():
                    alignment_score += 0.1

        # Check payload content for technology-specific patterns
        payload_lower = payload.payload.lower()
        for tech in target.technology_stack:
            if tech.lower() == 'php' and 'php' in payload_lower:
                alignment_score += 0.1
            elif tech.lower() == 'asp' and ('asp' in payload_lower or 'viewstate' in payload_lower):
                alignment_score += 0.1
            elif tech.lower() == 'jsp' and 'jsp' in payload_lower:
                alignment_score += 0.1

        return min(alignment_score, 0.3)  # Cap at 0.3

    def _categorize_payload(self, payload: Payload) -> PayloadCategory:
        """Categorize payload for selection strategy."""
        payload_lower = payload.payload.lower()

        # Check for advanced techniques
        advanced_patterns = ['fromcharcode', 'eval', 'string.', 'unescape', 'encodeur']
        if any(pattern in payload_lower for pattern in advanced_patterns):
            return PayloadCategory.ADVANCED

        # Check for WAF bypass techniques
        bypass_patterns = ['/*', '//', '\\x', '%', 'unicode', 'hex']
        if any(pattern in payload_lower for pattern in bypass_patterns):
            return PayloadCategory.WAF_BYPASS

        # Check for DOM-based patterns
        dom_patterns = ['document.', 'window.', 'location.', 'innerhtml']
        if any(pattern in payload_lower for pattern in dom_patterns):
            return PayloadCategory.DOM_BASED

        # Check for polyglot (works in multiple contexts)
        if len(payload.contexts) > 2:
            return PayloadCategory.POLYGLOT

        # Check for context-specific
        if len(payload.contexts) == 1:
            return PayloadCategory.CONTEXT_SPECIFIC

        return PayloadCategory.BASIC

    def _estimate_success_probability(self, payload: Payload, target: Target,
                                      score: float) -> float:
        """Estimate the probability of payload success."""
        # Start with the final score
        prob = score

        # Adjust based on target characteristics
        if target.waf_detected and not payload.waf_effectiveness:
            prob *= 0.5  # Significant penalty for unknown WAF effectiveness

        # Adjust based on payload attempts
        if payload.total_attempts > 0:
            confidence = min(payload.total_attempts / 10.0, 1.0)  # More attempts = more confidence
            prob = prob * confidence + payload.success_rate * (1 - confidence)

        # Adjust based on technology stack
        if target.technology_stack:
            tech_match = any(tech.lower() in payload.payload.lower()
                             for tech in target.technology_stack)
            if tech_match:
                prob *= 1.1

        return min(prob, 1.0)

    def _apply_selection_strategies(self, scored_payloads: List[PayloadScore],
                                    target: Target, max_payloads: int) -> List[PayloadScore]:
        """Apply intelligent selection strategies."""
        if len(scored_payloads) <= max_payloads:
            return scored_payloads

        selected = []

        # Strategy 1: Always include top performers
        top_count = min(max_payloads // 3, 10)
        selected.extend(scored_payloads[:top_count])

        # Strategy 2: Ensure category diversity
        remaining_slots = max_payloads - len(selected)
        category_selected = self._select_by_category_diversity(
            scored_payloads[top_count:], remaining_slots // 2
        )
        selected.extend(category_selected)

        # Strategy 3: Fill remaining slots with best remaining payloads
        remaining_slots = max_payloads - len(selected)
        if remaining_slots > 0:
            used_hashes = {p.payload.payload_hash for p in selected}
            remaining = [p for p in scored_payloads if p.payload.payload_hash not in used_hashes]
            selected.extend(remaining[:remaining_slots])

        return selected

    def _select_by_category_diversity(self, payloads: List[PayloadScore],
                                      count: int) -> List[PayloadScore]:
        """Select payloads ensuring category diversity."""
        category_groups = defaultdict(list)
        for payload in payloads:
            category_groups[payload.category].append(payload)

        # Sort categories by weight
        categories_by_weight = sorted(
            category_groups.keys(),
            key=lambda c: self.category_weights.get(c, 1.0),
            reverse=True
        )

        selected = []
        category_index = 0

        while len(selected) < count and category_groups:
            category = categories_by_weight[category_index % len(categories_by_weight)]

            if category_groups[category]:
                # Take the best payload from this category
                payload = category_groups[category].pop(0)
                selected.append(payload)

            # Remove empty categories
            if not category_groups[category]:
                del category_groups[category]
                categories_by_weight.remove(category)

            if categories_by_weight:
                category_index = (category_index + 1) % len(categories_by_weight)
            else:
                break

        return selected

    def _optimize_payload_set(self, selected: List[PayloadScore],
                              target: Target) -> List[PayloadScore]:
        """Final optimization of the payload set."""
        # Calculate diversity bonuses
        for i, payload_score in enumerate(selected):
            diversity_bonus = self._calculate_diversity_bonus(payload_score, selected[:i] + selected[i + 1:])
            payload_score.diversity_bonus = diversity_bonus
            payload_score.final_score += diversity_bonus

        # Re-sort by final score
        optimized = sorted(selected, key=lambda x: x.final_score, reverse=True)

        # Ensure minimum requirements
        if len(optimized) < self.min_payloads:
            self.logger.warning(f"Only {len(optimized)} payloads selected, below minimum of {self.min_payloads}")

        return optimized

    def _calculate_diversity_bonus(self, target_payload: PayloadScore,
                                   other_payloads: List[PayloadScore]) -> float:
        """Calculate diversity bonus for a payload."""
        if not other_payloads:
            return 0.1  # Bonus for being unique

        # Check for similarity with other payloads
        similarity_scores = []
        target_techniques = set(target_payload.payload.bypass_techniques)

        for other in other_payloads:
            other_techniques = set(other.payload.bypass_techniques)

            # Jaccard similarity
            if target_techniques or other_techniques:
                intersection = target_techniques & other_techniques
                union = target_techniques | other_techniques
                similarity = len(intersection) / len(union) if union else 0
                similarity_scores.append(similarity)

        if similarity_scores:
            avg_similarity = sum(similarity_scores) / len(similarity_scores)
            # More diverse payloads get higher bonus
            diversity_bonus = max(0, (1 - avg_similarity) * 0.2)
        else:
            diversity_bonus = 0.1

        return diversity_bonus

    def get_payload_selection_stats(self, selected: List[PayloadScore]) -> Dict[str, Any]:
        """Get statistics about the payload selection."""
        if not selected:
            return {}

        category_counts = Counter(p.category for p in selected)

        stats = {
            'total_payloads': len(selected),
            'avg_score': sum(p.final_score for p in selected) / len(selected),
            'avg_success_probability': sum(p.estimated_success_probability for p in selected) / len(selected),
            'category_distribution': dict(category_counts),
            'score_range': {
                'min': min(p.final_score for p in selected),
                'max': max(p.final_score for p in selected)
            },
            'top_categories': [cat.value for cat, _ in category_counts.most_common(3)]
        }

        return stats


# Global smart payload selector instance
smart_selector = SmartPayloadSelector()
