"""Pytest configuration for relative imports from the package."""
import sys
from pathlib import Path

# add the parent package directory to sys.path so tests can use .. imports
pkg_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pkg_dir.parent))
