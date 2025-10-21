#!/usr/bin/env python3
"""
Test runner script for Heimdal real-time monitoring tests
"""

import sys
import subprocess
import argparse
from pathlib import Path


def run_unit_tests():
    """Run unit tests"""
    print("Running unit tests...")
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/unit/", 
        "-v", 
        "--tb=short",
        "-m", "not slow"
    ]
    return subprocess.run(cmd).returncode


def run_integration_tests():
    """Run integration tests"""
    print("Running integration tests...")
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/integration/", 
        "-v", 
        "--tb=short",
        "-m", "not performance"
    ]
    return subprocess.run(cmd).returncode


def run_performance_tests():
    """Run performance tests"""
    print("Running performance tests...")
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/integration/test_performance.py", 
        "-v", 
        "--tb=short",
        "-s"  # Don't capture output for performance metrics
    ]
    return subprocess.run(cmd).returncode


def run_all_tests():
    """Run all tests"""
    print("Running all tests...")
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-v", 
        "--tb=short"
    ]
    return subprocess.run(cmd).returncode


def run_coverage():
    """Run tests with coverage"""
    print("Running tests with coverage...")
    cmd = [
        sys.executable, "-m", "pytest", 
        "tests/", 
        "--cov=heimdal",
        "--cov-report=html",
        "--cov-report=term-missing",
        "-v"
    ]
    return subprocess.run(cmd).returncode


def main():
    parser = argparse.ArgumentParser(description="Run Heimdal tests")
    parser.add_argument(
        "test_type", 
        choices=["unit", "integration", "performance", "all", "coverage"],
        help="Type of tests to run"
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Ensure we're in the right directory
    project_root = Path(__file__).parent
    if project_root.name != "heimdal" and not (project_root / "heimdal").exists():
        print("Error: Please run this script from the project root directory")
        return 1
    
    # Run the specified tests
    if args.test_type == "unit":
        return run_unit_tests()
    elif args.test_type == "integration":
        return run_integration_tests()
    elif args.test_type == "performance":
        return run_performance_tests()
    elif args.test_type == "all":
        return run_all_tests()
    elif args.test_type == "coverage":
        return run_coverage()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())