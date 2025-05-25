# XSStrike AI/RAG Features Documentation

## Overview

XSStrike now includes advanced AI and RAG (Retrieval-Augmented Generation) capabilities that significantly enhance the
scanning process through intelligent decision-making, adaptive learning, and context-aware payload generation.

## Key Features

### 🧠 Knowledge Base System

- **SQLite-based storage** for scan results, payloads, and vulnerability patterns
- **Target fingerprinting** with technology stack, CMS, and WAF detection
- **Payload effectiveness tracking** with success rates and context information
- **Vulnerability pattern storage** for predictive analysis
- **Historical data aggregation** for improved decision-making

### 🎯 RAG-Based Learning System

- **Target analysis** with automatic technology detection
- **Payload recommendation engine** based on historical success rates
- **Vulnerability pattern recognition** using machine learning
- **Adaptive scanning** that learns from WAF bypass techniques
- **Similarity matching** to avoid redundant testing

### 🚀 Context-Aware Payload Generation

- **Injection context detection** (HTML, attribute, script, URL)
- **Technology-specific adaptations** (PHP, ASP.NET, JSP, etc.)
- **WAF bypass techniques** with dynamic adaptation
- **Payload mutation** based on target characteristics
- **Success rate optimization** using historical data

### 🤖 Intelligent Scan Orchestration

- **Multi-phase scanning** (high-confidence → adaptive payloads)
- **Real-time learning** from scan results
- **Strategy optimization** based on target characteristics
- **Efficiency improvements** through intelligent payload selection

## Usage

### Basic AI-Enhanced Scanning

```bash
# Enable AI-enhanced scanning
python xsstrike.py -u "https://example.com/search?q=test" --ai-scan

# Set AI confidence threshold
python xsstrike.py -u "https://example.com" --ai-scan --ai-threshold 0.7

# Disable learning for this scan
python xsstrike.py -u "https://example.com" --ai-scan --ai-no-learn
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ai-scan` | Enable AI-enhanced scanning | False |
| `--ai-threshold` | AI confidence threshold (0.0-1.0) | 0.5 |
| `--ai-no-learn` | Disable AI learning from this scan | False (learning enabled) |

## How It Works

### 1. Target Analysis

When AI scanning is enabled, XSStrike automatically:

- Analyzes HTTP headers and response content
- Detects technology stack (PHP, ASP.NET, Node.js, etc.)
- Identifies CMS platforms (WordPress, Drupal, Joomla, etc.)
- Detects WAF presence (Cloudflare, ModSecurity, Incapsula, etc.)
- Extracts server signatures and framework information

### 2. Intelligence Gathering

The RAG system:

- Retrieves similar targets from the knowledge base
- Analyzes vulnerability patterns from historical data
- Recommends payloads based on success rates
- Generates context-aware payload variations
- Optimizes scan strategy based on target characteristics

### 3. Adaptive Payload Generation

The payload generator:

- Creates context-specific payloads (HTML, attribute, script, URL)
- Applies WAF bypass techniques based on detected WAF
- Mutates payloads based on target technology stack
- Prioritizes payloads by predicted success rate
- Generates variations using proven bypass techniques

### 4. Learning and Adaptation

After each scan:

- Payload effectiveness is recorded
- WAF bypass techniques are learned
- Vulnerability patterns are updated
- Target characteristics are stored
- Success rates are recalculated

## Architecture

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Knowledge Base │    │   RAG System    │    │ Payload Generator│
│                 │    │                 │    │                 │
│ • Target Data   │◄───┤ • Target Analyzer│◄───┤ • Context Aware │
│ • Payload Stats │    │ • Pattern Recog. │    │ • WAF Bypasses  │
│ • Vuln Patterns │    │ • Similarity     │    │ • Mutations     │
│ • Scan Sessions │    │ • Adaptive Eng.  │    │ • Templates     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                       ▲                       ▲
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ AI Integration  │
                    │   Orchestrator  │
                    │                 │
                    │ • Scan Planning │
                    │ • Multi-phase   │
                    │ • Learning Loop │
                    │ • Strategy Opt. │
                    └─────────────────┘
                             │
                    ┌─────────────────┐
                    │  Scan Engine    │
                    │                 │
                    │ • HTTP Requests │
                    │ • Response Anal │
                    │ • Vuln Detection│
                    └─────────────────┘
```

### Data Models

#### Target

```python
@dataclass
class Target:
    url: str
    domain: str
    technology_stack: List[str]
    waf_detected: Optional[str]
    cms_detected: Optional[str]
    response_headers: Dict[str, str]
    server_signature: Optional[str]
```

#### Payload

```python
@dataclass
class Payload:
    payload: str
    payload_type: str
    success_rate: float
    contexts: List[str]
    bypass_techniques: List[str]
    waf_effectiveness: Dict[str, float]
```

#### Vulnerability

```python
@dataclass
class Vulnerability:
    target_id: int
    payload_id: int
    vulnerability_type: str
    severity: str
    confidence: float
    context: str
    parameter: str
```

## Performance Considerations

### Database Optimization

- SQLite WAL mode for concurrent access
- Indexed queries for fast lookups
- Periodic cleanup of old data
- Efficient similarity calculations

### Machine Learning

- TF-IDF vectorization for text analysis
- Cosine similarity for target matching
- K-means clustering for pattern recognition
- Incremental learning for real-time updates

### Memory Management

- Lazy loading of large datasets
- Caching of frequently accessed data
- Payload deduplication
- Efficient data structures

## Configuration

### AI Settings

The AI system can be configured through the configuration file:

```json
{
  "ai": {
    "enabled": false,
    "learning_mode": true,
    "confidence_threshold": 0.5,
    "max_payloads": 100,
    "cache_duration": 3600,
    "database_path": "data/knowledge_base.db"
  }
}
```

### Learning Parameters

```json
{
  "learning": {
    "learning_rate": 0.1,
    "similarity_threshold": 0.8,
    "pattern_cache_duration": 3600,
    "max_historical_payloads": 1000
  }
}
```

## Examples

### Example 1: Basic AI Scan

```bash
python xsstrike.py -u "https://testphp.vulnweb.com/search.php?test=query" --ai-scan
```

Output:

```
[!] AI-enhanced scanning enabled
[!] Target analysis complete for testphp.vulnweb.com
  - Technology Stack: php, apache
  - WAF Detected: None
  - Risk Level: MEDIUM
[!] Generated 47 intelligent payloads
[!] Executing high-confidence phase with 20 payloads
[!] Vulnerability found: XSS in parameter 'test'
[!] Learning from scan results...
```

### Example 2: High-Precision Scan

```bash
python xsstrike.py -u "https://example.com" --ai-scan --ai-threshold 0.8
```

This will only use payloads with >80% predicted success rate.

### Example 3: Research Mode (No Learning)

```bash
python xsstrike.py -u "https://example.com" --ai-scan --ai-no-learn
```

Perfect for testing without polluting the knowledge base.

## Troubleshooting

### Common Issues

**1. "Knowledge base not initialized"**

- Ensure the `data/` directory exists
- Check file permissions
- Verify SQLite is available

**2. "No AI recommendations available"**

- The knowledge base may be empty for new installations
- Run a few scans to build up historical data
- Check the confidence threshold setting

**3. "Slow AI analysis"**

- Reduce the number of historical payloads analyzed
- Clear old data from the knowledge base
- Optimize the similarity threshold

### Debug Mode

Enable debug logging to see detailed AI operations:

```bash
python xsstrike.py -u "https://example.com" --ai-scan --console-log-level DEBUG
```

## API Integration

The AI features are also available through the API:

```python
from core.engine import XSSEngine, ScanOptions

engine = XSSEngine()
options = ScanOptions(
    target="https://example.com",
    ai_enabled=True,
    ai_confidence_threshold=0.7
)

scan_id = engine.create_scan(options)
result = engine.execute_scan(scan_id, options)
```

## Future Enhancements

### Planned Features

- [ ] Deep learning models for vulnerability prediction
- [ ] Advanced WAF fingerprinting
- [ ] Distributed scanning coordination
- [ ] Real-time threat intelligence integration
- [ ] Custom payload training
- [ ] Advanced reporting with AI insights

### Research Areas

- Neural network-based payload generation
- Adversarial testing against WAFs
- Automated exploit generation
- Behavioral analysis of web applications
- Zero-day vulnerability prediction

## Contributing

To contribute to the AI features:

1. Understand the architecture
2. Add test cases for new features
3. Maintain backward compatibility
4. Document new parameters and methods
5. Test with various target types

## License

The AI/RAG features are part of XSStrike and follow the same license terms.

---

*For more information, see the main XSStrike documentation and the source code in the `core/` directory.*