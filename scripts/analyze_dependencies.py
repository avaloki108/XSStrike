#!/usr/bin/env python3
"""
Dependency analysis script for XSStrike.

This script analyzes which dependencies are actually used in the codebase
and identifies potentially unused dependencies.
"""

import os
import re
import ast
from typing import Set, Dict, List
from pathlib import Path


def extract_imports_from_file(file_path: str) -> Set[str]:
    """Extract all imports from a Python file."""
    imports = set()

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Parse the AST to extract imports
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split('.')[0])
        except SyntaxError:
            # If AST parsing fails, use regex fallback
            import_patterns = [
                r'import\s+([a-zA-Z_][a-zA-Z0-9_]*)',
                r'from\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            ]

            for pattern in import_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    imports.add(match)

    except Exception as e:
        print(f"Error processing {file_path}: {e}")

    return imports


def get_all_python_files(directory: str) -> List[str]:
    """Get all Python files in the directory recursively."""
    python_files = []

    for root, dirs, files in os.walk(directory):
        # Skip virtual environment directories
        dirs[:] = [d for d in dirs if not d.startswith('.venv') and d != '__pycache__']

        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))

    return python_files


def analyze_dependencies() -> Dict[str, Dict[str, List[str]]]:
    """Analyze dependencies used in the codebase."""

    # Get dependencies from requirements.txt
    declared_deps = set()
    requirements_file = "requirements.txt"

    if os.path.exists(requirements_file):
        with open(requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract package name (everything before >= or ==)
                    pkg_name = re.split(r'[><=!]', line)[0].strip()
                    declared_deps.add(pkg_name.lower())

    # Map common import names to package names
    import_to_package = {
        'requests': 'requests',
        'urllib3': 'urllib3',
        'fuzzywuzzy': 'fuzzywuzzy',
        'numpy': 'numpy',
        'np': 'numpy',
        'sklearn': 'scikit-learn',
        'joblib': 'joblib',
        'jinja2': 'jinja2',
        'packaging': 'packaging',
        'tld': 'tld',
        'Levenshtein': 'python-levenshtein',
    }

    # Analyze imports in source files
    source_dirs = ['core', 'modes', 'plugins', 'interfaces', 'tests']
    all_imports = set()
    file_imports = {}

    for source_dir in source_dirs:
        if os.path.exists(source_dir):
            files = get_all_python_files(source_dir)
            for file_path in files:
                imports = extract_imports_from_file(file_path)
                file_imports[file_path] = imports
                all_imports.update(imports)

    # Also check main script
    if os.path.exists('xsstrike.py'):
        imports = extract_imports_from_file('xsstrike.py')
        file_imports['xsstrike.py'] = imports
        all_imports.update(imports)

    # Map imports to packages
    used_packages = set()
    for import_name in all_imports:
        if import_name.lower() in import_to_package:
            used_packages.add(import_to_package[import_name.lower()])
        elif import_name.lower() in declared_deps:
            used_packages.add(import_name.lower())

    # Find unused dependencies
    unused_deps = declared_deps - used_packages
    missing_deps = used_packages - declared_deps

    # Find files using each dependency
    dependency_usage = {}
    for pkg in used_packages:
        dependency_usage[pkg] = []
        # Find reverse mapping from package to import names
        import_names = [k for k, v in import_to_package.items() if v == pkg]
        import_names.append(pkg)  # Also check direct package name

        for file_path, imports in file_imports.items():
            for import_name in import_names:
                if import_name in imports or import_name.lower() in imports:
                    if file_path not in dependency_usage[pkg]:
                        dependency_usage[pkg].append(file_path)

    return {
        'declared': list(declared_deps),
        'used': list(used_packages),
        'unused': list(unused_deps),
        'missing': list(missing_deps),
        'usage': dependency_usage
    }


def main():
    """Main function to run dependency analysis."""
    print("XSStrike Dependency Analysis")
    print("=" * 40)

    analysis = analyze_dependencies()

    print(f"\nDeclared dependencies ({len(analysis['declared'])}):")
    for dep in sorted(analysis['declared']):
        print(f"  - {dep}")

    print(f"\nUsed dependencies ({len(analysis['used'])}):")
    for dep in sorted(analysis['used']):
        print(f"  - {dep}")
        if dep in analysis['usage'] and analysis['usage'][dep]:
            files = analysis['usage'][dep][:3]  # Show first 3 files
            file_list = ', '.join(files)
            if len(analysis['usage'][dep]) > 3:
                file_list += f" (and {len(analysis['usage'][dep]) - 3} more)"
            print(f"    Used in: {file_list}")

    if analysis['unused']:
        print(f"\n⚠ Potentially unused dependencies ({len(analysis['unused'])}):")
        for dep in sorted(analysis['unused']):
            print(f"  - {dep}")
        print("\nThese dependencies could potentially be removed to reduce the footprint.")
    else:
        print("\n✓ All declared dependencies appear to be used!")

    if analysis['missing']:
        print(f"\n⚠ Missing from requirements.txt ({len(analysis['missing'])}):")
        for dep in sorted(analysis['missing']):
            print(f"  - {dep}")

    print("\nRecommendations:")

    if analysis['unused']:
        print("1. Consider removing unused dependencies:")
        print(f"   pip uninstall {' '.join(sorted(analysis['unused']))}")
        print("   Then remove them from requirements.txt")

    if analysis['missing']:
        print("2. Add missing dependencies to requirements.txt:")
        for dep in sorted(analysis['missing']):
            print(f"   {dep}")

    # Check for lighter alternatives
    print("\n3. Consider lighter alternatives for:")
    alternatives = {
        'scikit-learn': 'Consider if full sklearn is needed - maybe use specific components',
        'numpy': 'Could use built-in Python data structures for simple operations',
        'jinja2': 'For simple templating, consider string formatting alternatives',
    }

    for dep in analysis['used']:
        if dep in alternatives:
            print(f"   - {dep}: {alternatives[dep]}")


if __name__ == "__main__":
    main()
