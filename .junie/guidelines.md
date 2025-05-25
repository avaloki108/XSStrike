# XSStrike Development Guidelines

This document provides guidelines and information for developers working on the XSStrike project.

## Build/Configuration Instructions

### Environment Setup

1. **Python Version**: XSStrike requires Python 3.4 or higher. It is not compatible with Python 2.

2. **Installation**:
   ```bash
   git clone https://github.com/s0md3v/XSStrike
   cd XSStrike
   pip install -r requirements.txt
   ```

3. **Dependencies**:
   - tld: For domain name parsing
   - fuzzywuzzy: For fuzzy string matching
   - requests: For HTTP requests

4. **Configuration**:
   - Core configuration settings are stored in `core/config.py`
   - Global variables are initialized in `xsstrike.py` and stored in `core.config.globalVariables`

## Testing Information

### Running Tests

1. **Execute Tests**:
   ```bash
   python -m unittest discover tests
   ```
   
   Or run a specific test file:
   ```bash
   python tests/test_utils.py
   ```

### Adding New Tests

1. **Create Test Files**:
   - Place test files in the `tests` directory
   - Name test files with the prefix `test_` (e.g., `test_utils.py`)
   - Organize tests by module (e.g., `test_utils.py` for testing `core/utils.py`)

2. **Test Structure**:
   - Use the `unittest` framework
   - Create a class that inherits from `unittest.TestCase`
   - Write test methods with names starting with `test_`
   - Include docstrings explaining what each test does

3. **Example Test**:
   ```python
   import unittest
   import sys
   import os
   
   # Add the parent directory to the path so we can import the core modules
   sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
   
   from core.utils import counter
   
   class TestUtils(unittest.TestCase):
       
       def test_counter(self):
           """Test the counter function which counts non-alphanumeric characters."""
           self.assertEqual(counter("abc123"), 0)
           self.assertEqual(counter("abc!@#"), 3)
           self.assertEqual(counter("!@#$%^"), 6)
           self.assertEqual(counter(""), 0)
   
   if __name__ == "__main__":
       unittest.main()
   ```

### Test Environment

1. **Mock Servers**:
   - For testing XSS detection, create simple HTML files with known vulnerabilities
   - Use `test.html` as a reference for creating test cases

2. **Test Data**:
   - Store test payloads and expected results in separate files
   - Use the `core/utils.py` functions `reader()` and `writer()` to read and write test data

## Additional Development Information

### Code Structure

1. **Main Components**:
   - `xsstrike.py`: Entry point and command-line interface
   - `core/`: Core functionality modules
   - `modes/`: Different scanning modes (crawl, scan, bruteforce, etc.)
   - `plugins/`: Additional functionality (e.g., retireJS for outdated JS detection)
   - `db/`: Database files (definitions.json, wafSignatures.json)

2. **Key Modules**:
   - `core/utils.py`: Utility functions used throughout the codebase
   - `core/requester.py`: Handles HTTP requests
   - `core/scanner.py`: Core scanning functionality
   - `core/htmlParser.py`: HTML parsing for XSS detection
   - `core/jsContexter.py`: JavaScript context analysis

### Coding Style

1. **Naming Conventions**:
   - Use snake_case for variables and function names
   - Use CamelCase for class names
   - Use UPPERCASE for constants

2. **Documentation**:
   - Add docstrings to all functions and classes
   - Include parameter descriptions and return value information
   - Document complex algorithms and logic with inline comments

### Debugging

1. **Logging**:
   - Use the logging system in `core/log.py`
   - Set log levels using command-line arguments:
     - `--console-log-level`: Sets console logging level
     - `--file-log-level`: Sets file logging level
     - `--log-file`: Specifies the log file

2. **Debugging Techniques**:
   - Use the `--delay` option to slow down requests for easier debugging
   - Set verbose logging with `--console-log-level DEBUG`
   - Examine the request and response data in the logs

### Contributing

1. **Pull Requests**:
   - Ensure all tests pass before submitting a pull request
   - Add tests for new functionality
   - Follow the existing code style
   - Document changes in the CHANGELOG.md file

2. **Issue Reporting**:
   - Provide detailed steps to reproduce the issue
   - Include the command used, expected behavior, and actual behavior
   - Attach relevant logs and screenshots