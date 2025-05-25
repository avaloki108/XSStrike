"""
XSStrike Interfaces Package.

This package contains different interface implementations for XSStrike,
allowing the same core functionality to be accessed through different means.
"""

from .base import BaseInterface
from .cli import CLIInterface
from .api import APIInterface

__all__ = ['BaseInterface', 'CLIInterface', 'APIInterface']
