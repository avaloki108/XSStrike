"""
Knowledge Base System for XSStrike AI/RAG functionality.

This module provides a comprehensive knowledge base that stores scan results,
successful payloads, vulnerability patterns, and target characteristics
to enable intelligent decision-making and learning from past scans.
"""

import sqlite3
import json
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
from pathlib import Path

from core.log import setup_logger

logger = setup_logger(__name__)


@dataclass
class Target:
    """Represents a scan target with its characteristics."""
    id: Optional[int] = None
    url: str = ""
    domain: str = ""
    scheme: str = ""
    path: str = ""
    technology_stack: List[str] = None
    waf_detected: Optional[str] = None
    response_headers: Dict[str, str] = None
    server_signature: Optional[str] = None
    cms_detected: Optional[str] = None
    framework_detected: Optional[str] = None
    created_at: Optional[float] = None

    def __post_init__(self):
        if self.technology_stack is None:
            self.technology_stack = []
        if self.response_headers is None:
            self.response_headers = {}
        if self.created_at is None:
            self.created_at = time.time()

        # Parse URL components
        if self.url and not self.domain:
            parsed = urlparse(self.url)
            self.domain = parsed.netloc
            self.scheme = parsed.scheme
            self.path = parsed.path


@dataclass
class Payload:
    """Represents a XSS payload with its metadata."""
    id: Optional[int] = None
    payload: str = ""
    payload_type: str = ""  # reflected, stored, dom, blind
    payload_hash: str = ""
    success_rate: float = 0.0
    total_attempts: int = 0
    successful_attempts: int = 0
    contexts: List[str] = None  # html, script, attribute, etc.
    bypass_techniques: List[str] = None
    waf_effectiveness: Dict[str, float] = None  # waf_name -> bypass_rate
    created_at: Optional[float] = None
    last_used: Optional[float] = None

    def __post_init__(self):
        if self.contexts is None:
            self.contexts = []
        if self.bypass_techniques is None:
            self.bypass_techniques = []
        if self.waf_effectiveness is None:
            self.waf_effectiveness = {}
        if self.created_at is None:
            self.created_at = time.time()
        if not self.payload_hash and self.payload:
            self.payload_hash = hashlib.md5(self.payload.encode()).hexdigest()


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    id: Optional[int] = None
    target_id: int = 0
    payload_id: int = 0
    vulnerability_type: str = ""
    severity: str = ""
    context: str = ""
    parameter: str = ""
    method: str = ""
    evidence: str = ""
    confidence: float = 0.0
    exploitation_vector: str = ""
    mitigation_bypass: List[str] = None
    discovered_at: Optional[float] = None

    def __post_init__(self):
        if self.mitigation_bypass is None:
            self.mitigation_bypass = []
        if self.discovered_at is None:
            self.discovered_at = time.time()


@dataclass
class ScanSession:
    """Represents a complete scan session."""
    id: Optional[int] = None
    target_id: int = 0
    scan_type: str = ""
    total_payloads: int = 0
    successful_payloads: int = 0
    vulnerabilities_found: int = 0
    duration: float = 0.0
    user_agent: str = ""
    scan_config: Dict[str, Any] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def __post_init__(self):
        if self.scan_config is None:
            self.scan_config = {}
        if self.started_at is None:
            self.started_at = time.time()


class KnowledgeBase:
    """
    Core knowledge base system for storing and retrieving scan intelligence.
    
    This system stores scan results, payload effectiveness, target characteristics,
    and vulnerability patterns to enable AI-driven decision making.
    """

    def __init__(self, db_path: str = "data/knowledge_base.db"):
        self.db_path = Path(db_path)
        self.logger = setup_logger(__name__)
        self._ensure_db_directory()
        self._initialize_database()

    def _ensure_db_directory(self) -> None:
        """Ensure the database directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with optimizations."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def _initialize_database(self) -> None:
        """Initialize database tables."""
        with self._get_connection() as conn:
            # Targets table
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS targets
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             url
                             TEXT
                             NOT
                             NULL,
                             domain
                             TEXT
                             NOT
                             NULL,
                             scheme
                             TEXT,
                             path
                             TEXT,
                             technology_stack
                             TEXT,
                             waf_detected
                             TEXT,
                             response_headers
                             TEXT,
                             server_signature
                             TEXT,
                             cms_detected
                             TEXT,
                             framework_detected
                             TEXT,
                             created_at
                             REAL,
                             UNIQUE
                         (
                             url
                         )
                             )
            """)

            # Payloads table
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS payloads
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             payload
                             TEXT
                             NOT
                             NULL,
                             payload_type
                             TEXT,
                             payload_hash
                             TEXT
                             UNIQUE,
                             success_rate
                             REAL
                             DEFAULT
                             0.0,
                             total_attempts
                             INTEGER
                             DEFAULT
                             0,
                             successful_attempts
                             INTEGER
                             DEFAULT
                             0,
                             contexts
                             TEXT,
                             bypass_techniques
                             TEXT,
                             waf_effectiveness
                             TEXT,
                             created_at
                             REAL,
                             last_used
                             REAL
                         )
            """)

            # Vulnerabilities table
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS vulnerabilities
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             target_id
                             INTEGER,
                             payload_id
                             INTEGER,
                             vulnerability_type
                             TEXT,
                             severity
                             TEXT,
                             context
                             TEXT,
                             parameter
                             TEXT,
                             method
                             TEXT,
                             evidence
                             TEXT,
                             confidence
                             REAL,
                             exploitation_vector
                             TEXT,
                             mitigation_bypass
                             TEXT,
                             discovered_at
                             REAL,
                             FOREIGN
                             KEY
                         (
                             target_id
                         ) REFERENCES targets
                         (
                             id
                         ),
                             FOREIGN KEY
                         (
                             payload_id
                         ) REFERENCES payloads
                         (
                             id
                         )
                             )
            """)

            # Scan sessions table
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS scan_sessions
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             target_id
                             INTEGER,
                             scan_type
                             TEXT,
                             total_payloads
                             INTEGER,
                             successful_payloads
                             INTEGER,
                             vulnerabilities_found
                             INTEGER,
                             duration
                             REAL,
                             user_agent
                             TEXT,
                             scan_config
                             TEXT,
                             started_at
                             REAL,
                             completed_at
                             REAL,
                             FOREIGN
                             KEY
                         (
                             target_id
                         ) REFERENCES targets
                         (
                             id
                         )
                             )
            """)

            # WAF patterns table
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS waf_patterns
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             waf_name
                             TEXT,
                             detection_pattern
                             TEXT,
                             bypass_payloads
                             TEXT,
                             effectiveness_rating
                             REAL,
                             last_updated
                             REAL
                         )
            """)

            # Technology fingerprints table
            conn.execute("""
                         CREATE TABLE IF NOT EXISTS tech_fingerprints
                         (
                             id
                             INTEGER
                             PRIMARY
                             KEY
                             AUTOINCREMENT,
                             technology
                             TEXT,
                             version
                             TEXT,
                             detection_method
                             TEXT,
                             confidence
                             REAL,
                             vulnerable_payloads
                             TEXT,
                             created_at
                             REAL
                         )
            """)

            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_targets_domain ON targets(domain)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_payloads_hash ON payloads(payload_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_payloads_success_rate ON payloads(success_rate DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target ON vulnerabilities(target_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_type ON vulnerabilities(vulnerability_type)")

            conn.commit()
            self.logger.info("Knowledge base database initialized")

    def store_target(self, target: Target) -> int:
        """
        Store target information in the knowledge base.
        
        Args:
            target: Target object to store
            
        Returns:
            int: Target ID
        """
        with self._get_connection() as conn:
            try:
                cursor = conn.execute("""
                    INSERT OR REPLACE INTO targets 
                    (url, domain, scheme, path, technology_stack, waf_detected, 
                     response_headers, server_signature, cms_detected, framework_detected, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    target.url, target.domain, target.scheme, target.path,
                    json.dumps(target.technology_stack), target.waf_detected,
                    json.dumps(target.response_headers), target.server_signature,
                    target.cms_detected, target.framework_detected, target.created_at
                ))
                target_id = cursor.lastrowid
                conn.commit()
                self.logger.debug(f"Stored target: {target.url} (ID: {target_id})")
                return target_id
            except sqlite3.Error as e:
                self.logger.error(f"Error storing target: {e}")
                raise

    def store_payload(self, payload: Payload) -> int:
        """
        Store payload information in the knowledge base.
        
        Args:
            payload: Payload object to store
            
        Returns:
            int: Payload ID
        """
        with self._get_connection() as conn:
            try:
                cursor = conn.execute("""
                    INSERT OR REPLACE INTO payloads 
                    (payload, payload_type, payload_hash, success_rate, total_attempts,
                     successful_attempts, contexts, bypass_techniques, waf_effectiveness,
                     created_at, last_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    payload.payload, payload.payload_type, payload.payload_hash,
                    payload.success_rate, payload.total_attempts, payload.successful_attempts,
                    json.dumps(payload.contexts), json.dumps(payload.bypass_techniques),
                    json.dumps(payload.waf_effectiveness), payload.created_at, payload.last_used
                ))
                payload_id = cursor.lastrowid
                conn.commit()
                self.logger.debug(f"Stored payload: {payload.payload_hash} (ID: {payload_id})")
                return payload_id
            except sqlite3.Error as e:
                self.logger.error(f"Error storing payload: {e}")
                raise

    def store_vulnerability(self, vulnerability: Vulnerability) -> int:
        """
        Store vulnerability information in the knowledge base.
        
        Args:
            vulnerability: Vulnerability object to store
            
        Returns:
            int: Vulnerability ID
        """
        with self._get_connection() as conn:
            try:
                cursor = conn.execute("""
                                      INSERT INTO vulnerabilities
                                      (target_id, payload_id, vulnerability_type, severity, context,
                                       parameter, method, evidence, confidence, exploitation_vector,
                                       mitigation_bypass, discovered_at)
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                                          vulnerability.target_id, vulnerability.payload_id,
                                          vulnerability.vulnerability_type,
                                          vulnerability.severity, vulnerability.context, vulnerability.parameter,
                                          vulnerability.method, vulnerability.evidence, vulnerability.confidence,
                                          vulnerability.exploitation_vector,
                                          json.dumps(vulnerability.mitigation_bypass),
                                          vulnerability.discovered_at
                                      ))
                vuln_id = cursor.lastrowid
                conn.commit()
                self.logger.info(f"Stored vulnerability: {vulnerability.vulnerability_type} (ID: {vuln_id})")
                return vuln_id
            except sqlite3.Error as e:
                self.logger.error(f"Error storing vulnerability: {e}")
                raise

    def store_scan_session(self, session: ScanSession) -> int:
        """
        Store scan session information in the knowledge base.
        
        Args:
            session: ScanSession object to store
            
        Returns:
            int: Session ID
        """
        with self._get_connection() as conn:
            try:
                cursor = conn.execute("""
                                      INSERT INTO scan_sessions
                                      (target_id, scan_type, total_payloads, successful_payloads,
                                       vulnerabilities_found, duration, user_agent, scan_config,
                                       started_at, completed_at)
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                                          session.target_id, session.scan_type, session.total_payloads,
                                          session.successful_payloads, session.vulnerabilities_found,
                                          session.duration, session.user_agent, json.dumps(session.scan_config),
                                          session.started_at, session.completed_at
                                      ))
                session_id = cursor.lastrowid
                conn.commit()
                self.logger.debug(f"Stored scan session: {session.scan_type} (ID: {session_id})")
                return session_id
            except sqlite3.Error as e:
                self.logger.error(f"Error storing scan session: {e}")
                raise

    def get_target_by_url(self, url: str) -> Optional[Target]:
        """Get target by URL."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM targets WHERE url = ?", (url,)).fetchone()
            if row:
                return Target(
                    id=row['id'], url=row['url'], domain=row['domain'],
                    scheme=row['scheme'], path=row['path'],
                    technology_stack=json.loads(row['technology_stack'] or '[]'),
                    waf_detected=row['waf_detected'],
                    response_headers=json.loads(row['response_headers'] or '{}'),
                    server_signature=row['server_signature'],
                    cms_detected=row['cms_detected'],
                    framework_detected=row['framework_detected'],
                    created_at=row['created_at']
                )
        return None

    def get_successful_payloads(self, limit: int = 100, min_success_rate: float = 0.1) -> List[Payload]:
        """Get most successful payloads."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                                SELECT *
                                FROM payloads
                                WHERE success_rate >= ?
                                  AND total_attempts > 0
                                ORDER BY success_rate DESC, successful_attempts DESC LIMIT ?
            """, (min_success_rate, limit)).fetchall()

            payloads = []
            for row in rows:
                payloads.append(Payload(
                    id=row['id'], payload=row['payload'], payload_type=row['payload_type'],
                    payload_hash=row['payload_hash'], success_rate=row['success_rate'],
                    total_attempts=row['total_attempts'], successful_attempts=row['successful_attempts'],
                    contexts=json.loads(row['contexts'] or '[]'),
                    bypass_techniques=json.loads(row['bypass_techniques'] or '[]'),
                    waf_effectiveness=json.loads(row['waf_effectiveness'] or '{}'),
                    created_at=row['created_at'], last_used=row['last_used']
                ))
            return payloads

    def get_payloads_for_context(self, context: str, limit: int = 50) -> List[Payload]:
        """Get payloads effective for a specific context."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                                SELECT *
                                FROM payloads
                                WHERE contexts LIKE ?
                                  AND total_attempts > 0
                                ORDER BY success_rate DESC LIMIT ?
            """, (f'%"{context}"%', limit)).fetchall()

            payloads = []
            for row in rows:
                payloads.append(Payload(
                    id=row['id'], payload=row['payload'], payload_type=row['payload_type'],
                    payload_hash=row['payload_hash'], success_rate=row['success_rate'],
                    total_attempts=row['total_attempts'], successful_attempts=row['successful_attempts'],
                    contexts=json.loads(row['contexts'] or '[]'),
                    bypass_techniques=json.loads(row['bypass_techniques'] or '[]'),
                    waf_effectiveness=json.loads(row['waf_effectiveness'] or '{}'),
                    created_at=row['created_at'], last_used=row['last_used']
                ))
            return payloads

    def update_payload_stats(self, payload_hash: str, success: bool, context: str = "") -> None:
        """Update payload success statistics."""
        with self._get_connection() as conn:
            # Get current stats
            row = conn.execute("""
                               SELECT total_attempts, successful_attempts, contexts
                               FROM payloads
                               WHERE payload_hash = ?
            """, (payload_hash,)).fetchone()

            if row:
                total_attempts = row['total_attempts'] + 1
                successful_attempts = row['successful_attempts'] + (1 if success else 0)
                success_rate = successful_attempts / total_attempts

                # Update contexts
                contexts = json.loads(row['contexts'] or '[]')
                if context and context not in contexts:
                    contexts.append(context)

                conn.execute("""
                             UPDATE payloads
                             SET total_attempts      = ?,
                                 successful_attempts = ?,
                                 success_rate        = ?,
                                 contexts            = ?,
                                 last_used           = ?
                             WHERE payload_hash = ?
                """, (total_attempts, successful_attempts, success_rate,
                      json.dumps(contexts), time.time(), payload_hash))
                conn.commit()

    def get_vulnerability_patterns(self, target_domain: str = None) -> List[Dict[str, Any]]:
        """Get vulnerability patterns for analysis."""
        with self._get_connection() as conn:
            query = """ \
                    SELECT v.vulnerability_type, \
                           v.context, \
                           v.severity, \
                           COUNT(*)          as occurrence_count, \
                           AVG(v.confidence) as avg_confidence, \
                           t.domain, \
                           t.technology_stack, \
                           t.waf_detected \
                    FROM vulnerabilities v \
                             JOIN targets t ON v.target_id = t.id
            """
            params = []

            if target_domain:
                query += " WHERE t.domain LIKE ?"
                params.append(f"%{target_domain}%")

            query += """
                GROUP BY v.vulnerability_type, v.context, t.domain
                ORDER BY occurrence_count DESC
            """

            rows = conn.execute(query, params).fetchall()

            patterns = []
            for row in rows:
                patterns.append({
                    'vulnerability_type': row['vulnerability_type'],
                    'context': row['context'],
                    'severity': row['severity'],
                    'occurrence_count': row['occurrence_count'],
                    'avg_confidence': row['avg_confidence'],
                    'domain': row['domain'],
                    'technology_stack': json.loads(row['technology_stack'] or '[]'),
                    'waf_detected': row['waf_detected']
                })

            return patterns

    def get_similar_targets(self, target: Target, limit: int = 10) -> List[Target]:
        """Find similar targets based on characteristics."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                                SELECT *
                                FROM targets
                                WHERE domain != ?
                                  AND (
                                    cms_detected = ?
                                   OR
                                    framework_detected = ?
                                   OR
                                    waf_detected = ?
                                   OR
                                    server_signature LIKE ?
                                    )
                                ORDER BY created_at DESC
                                    LIMIT ?
            """, (target.domain, target.cms_detected, target.framework_detected,
                  target.waf_detected, f"%{target.server_signature or ''}%", limit)).fetchall()

            similar_targets = []
            for row in rows:
                similar_targets.append(Target(
                    id=row['id'], url=row['url'], domain=row['domain'],
                    scheme=row['scheme'], path=row['path'],
                    technology_stack=json.loads(row['technology_stack'] or '[]'),
                    waf_detected=row['waf_detected'],
                    response_headers=json.loads(row['response_headers'] or '{}'),
                    server_signature=row['server_signature'],
                    cms_detected=row['cms_detected'],
                    framework_detected=row['framework_detected'],
                    created_at=row['created_at']
                ))

            return similar_targets

    def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        with self._get_connection() as conn:
            stats = {}

            # Count records
            stats['targets'] = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            stats['payloads'] = conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
            stats['vulnerabilities'] = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            stats['scan_sessions'] = conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]

            # Success rates
            payload_stats = conn.execute("""
                                         SELECT AVG(success_rate)        as avg_success_rate,
                                                MAX(success_rate)        as max_success_rate,
                                                SUM(total_attempts)      as total_attempts,
                                                SUM(successful_attempts) as successful_attempts
                                         FROM payloads
                                         WHERE total_attempts > 0
            """).fetchone()

            if payload_stats:
                stats['avg_payload_success_rate'] = payload_stats['avg_success_rate'] or 0
                stats['max_payload_success_rate'] = payload_stats['max_success_rate'] or 0
                stats['total_payload_attempts'] = payload_stats['total_attempts'] or 0
                stats['total_successful_attempts'] = payload_stats['successful_attempts'] or 0

            # Most common vulnerability types
            vuln_types = conn.execute("""
                                      SELECT vulnerability_type, COUNT(*) as count
                                      FROM vulnerabilities
                                      GROUP BY vulnerability_type
                                      ORDER BY count DESC
                                          LIMIT 5
            """).fetchall()

            stats['common_vulnerability_types'] = [
                {'type': row['vulnerability_type'], 'count': row['count']}
                for row in vuln_types
            ]

            return stats


# Global knowledge base instance
knowledge_base = KnowledgeBase()