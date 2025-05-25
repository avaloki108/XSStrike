#!/usr/bin/env python3
"""
Dependency management script for XSStrike.

This script helps maintain up-to-date and secure dependencies by:
1. Checking for known security vulnerabilities
2. Updating dependencies to latest secure versions
3. Verifying compatibility
"""

import subprocess
import sys
import json
from typing import List, Dict, Tuple
import re


def run_command(command: List[str]) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)


def check_security_vulnerabilities() -> bool:
    """Check for known security vulnerabilities using safety."""
    print("Checking for known security vulnerabilities...")

    # Install safety if not available
    code, _, _ = run_command([sys.executable, "-m", "pip", "show", "safety"])
    if code != 0:
        print("Installing safety for vulnerability checking...")
        code, _, err = run_command([sys.executable, "-m", "pip", "install", "safety"])
        if code != 0:
            print(f"Failed to install safety: {err}")
            return False

    # Run safety check
    code, output, err = run_command([sys.executable, "-m", "safety", "check", "--json"])

    if code == 0:
        print("✓ No known security vulnerabilities found!")
        return True
    elif code == 255:  # Safety found vulnerabilities
        try:
            vulns = json.loads(output)
            print(f"⚠ Found {len(vulns)} security vulnerabilities:")
            for vuln in vulns:
                print(f"  - {vuln['package']} {vuln['installed_version']}: {vuln['vulnerability']}")
            return False
        except json.JSONDecodeError:
            print(f"Failed to parse vulnerability report: {output}")
            return False
    else:
        print(f"Failed to check vulnerabilities: {err}")
        return False


def get_outdated_packages() -> List[Dict[str, str]]:
    """Get list of outdated packages."""
    print("Checking for outdated packages...")

    code, output, err = run_command([sys.executable, "-m", "pip", "list", "--outdated", "--format=json"])

    if code != 0:
        print(f"Failed to check outdated packages: {err}")
        return []

    try:
        outdated = json.loads(output)
        return outdated
    except json.JSONDecodeError:
        print(f"Failed to parse outdated packages list: {output}")
        return []


def update_requirements_file(outdated_packages: List[Dict[str, str]]) -> None:
    """Update requirements.txt with newer versions."""
    with open("requirements.txt", "r") as f:
        lines = f.readlines()

    updated_lines = []
    outdated_dict = {pkg["name"].lower(): pkg["latest_version"] for pkg in outdated_packages}

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            updated_lines.append(line)
            continue

        # Parse requirement line
        match = re.match(r"([a-zA-Z0-9_-]+)", line)
        if match:
            pkg_name = match.group(1).lower()
            if pkg_name in outdated_dict:
                new_version = outdated_dict[pkg_name]
                new_line = f"{match.group(1)}>={new_version}"
                print(f"  Updating {match.group(1)}: {line} -> {new_line}")
                updated_lines.append(new_line)
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)

    # Write updated requirements
    with open("requirements.txt", "w") as f:
        for line in updated_lines:
            f.write(line + "\n")


def main():
    """Main function to check and update dependencies."""
    print("XSStrike Dependency Update Script")
    print("=" * 35)

    # Check current vulnerabilities
    has_vulns = not check_security_vulnerabilities()

    # Check for outdated packages
    outdated = get_outdated_packages()

    if outdated:
        print(f"\nFound {len(outdated)} outdated packages:")
        for pkg in outdated:
            print(f"  - {pkg['name']}: {pkg['version']} -> {pkg['latest_version']}")

        # Ask user if they want to update
        response = input("\nUpdate requirements.txt with latest versions? (y/N): ")
        if response.lower() == 'y':
            update_requirements_file(outdated)
            print("\n✓ Updated requirements.txt")
            print("Run 'pip install -r requirements.txt' to install updates")
        else:
            print("Skipped updating requirements.txt")
    else:
        print("✓ All packages are up to date!")

    if has_vulns:
        print("\n⚠ Security vulnerabilities found! Please update affected packages.")
        sys.exit(1)
    else:
        print("\n✓ No security issues detected!")


if __name__ == "__main__":
    main()
