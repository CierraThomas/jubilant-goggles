"""
Setup script for the Security Scanner package.
"""

from setuptools import setup, find_packages
import os

# Read the README
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()
else:
    long_description = "Multi-language security scanner for code vulnerability detection."

setup(
    name="securityscanner",
    version="1.0.0",
    author="Security Scanner Team",
    author_email="security@example.com",
    description="Multi-language security scanner for vulnerability detection and remediation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/securityscanner/securityscanner",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*"]),
    python_requires=">=3.8",
    install_requires=[
        # No required dependencies - uses standard library
    ],
    extras_require={
        "yaml": ["pyyaml>=6.0"],
        "rich": ["rich>=13.0"],
        "full": ["pyyaml>=6.0", "rich>=13.0"],
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "mypy>=1.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "securityscanner=securityscanner.cli:main",
            "secscan=securityscanner.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
    ],
    keywords="security, scanner, static-analysis, vulnerability, sast, code-quality",
    project_urls={
        "Bug Reports": "https://github.com/securityscanner/securityscanner/issues",
        "Documentation": "https://github.com/securityscanner/securityscanner#readme",
        "Source": "https://github.com/securityscanner/securityscanner",
    },
)
