"""
Setup script for Heimdal real-time network monitoring system
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file) as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="heimdal-monitoring",
    version="1.0.0",
    description="Real-time network monitoring and anomaly detection system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Cortexa",
    author_email="support@cortexa.ai",
    url="https://github.com/cortexa/heimdal",
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "heimdal=heimdal.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="network monitoring, anomaly detection, security, real-time",
    project_urls={
        "Bug Reports": "https://github.com/cortexa/heimdal/issues",
        "Source": "https://github.com/cortexa/heimdal",
        "Documentation": "https://docs.cortexa.ai/heimdal",
    },
)