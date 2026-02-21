#!/usr/bin/env python3
"""
SKSecurity Enterprise - Setup Script
The only security solution AI agents need.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version
VERSION = "1.2.0"

# Read README
README_PATH = Path(__file__).parent / "README.md"
LONG_DESCRIPTION = README_PATH.read_text(encoding="utf-8") if README_PATH.exists() else ""

# Read requirements
REQUIREMENTS_PATH = Path(__file__).parent / "requirements.txt"
if REQUIREMENTS_PATH.exists():
    with open(REQUIREMENTS_PATH, 'r') as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith('#') and not line.startswith('-')
        ]
else:
    requirements = [
        "click>=8.0.0",
        "pyyaml>=6.0",
        "flask>=2.3.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
        "sqlalchemy>=2.0.0",
        "psutil>=5.9.0"
    ]

# Filter out built-in modules
requirements = [req for req in requirements if not req.startswith('sqlite3')]

setup(
    name="sksecurity",
    version=VERSION,
    description="Enterprise-grade security for AI agent ecosystems",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    author="smilinTux Team",
    author_email="team@smilintux.org",
    url="https://github.com/smilinTux/SKSecurity",
    project_urls={
        "Homepage": "https://sksecurity.com",
        "Documentation": "https://docs.sksecurity.com",
        "Repository": "https://github.com/smilinTux/SKSecurity",
        "Bug Tracker": "https://github.com/smilinTux/SKSecurity/issues",
        "Community": "https://discord.gg/sksecurity",
        "Support": "mailto:support@smilintux.org",
        "Enterprise": "mailto:sales@smilintux.org",
        "Security": "mailto:security@smilintux.org",
    },
    packages=find_packages(exclude=["tests", "tests.*", "examples", "docs"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators", 
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment",
    ],
    keywords=[
        "security", "ai", "agents", "scanning", "threat-intelligence",
        "enterprise", "compliance", "monitoring", "quarantine", "soc",
        "openclaw", "autogpt", "langchain", "vulnerability", "cybersecurity"
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "docs": [
            "mkdocs>=1.5.0",
            "mkdocs-material>=9.2.0",
            "markdown>=3.4.0",
        ],
        "enterprise": [
            "watchdog>=3.0.0",
            "cryptography>=41.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "sksecurity=sksecurity.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "sksecurity": [
            "data/*.json",
            "data/*.yml", 
            "templates/*.html",
            "static/*",
        ],
    },
    zip_safe=False,
    platforms=["any"],
    license="Apache-2.0",
    license_files=["LICENSE"],
)