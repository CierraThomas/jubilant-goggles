"""
Entry point for running the security scanner as a module.

Usage:
    python -m securityscanner scan ./src
    python -m securityscanner --help
"""

import sys
from securityscanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
