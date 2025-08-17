"""
Test runner script for the Flask application test suite.
Provides utilities to run different types of tests with proper configuration.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def setup_test_environment():
    """Setup environment variables for testing."""
    test_env = {
        'FLASK_ENV': 'testing',
        'MONGO_DATABASE': 'elysian_db_test',
        'MONGO_URI': 'mongodb://localhost:27017/',
        'CORS_ORIGINS': '*',
        'BCRYPT_ROUNDS': '4',
        'FLASK_DEBUG': 'False',
        'FLASK_HOST': '127.0.0.1',
        'FLASK_PORT': '5000'
    }
    
    for key, value in test_env.items():
        os.environ[key] = value
    
    print("✓ Test environment configured")

def run_unit_tests():
    """Run unit tests only."""
    print("🧪 Running unit tests...")
    cmd = [
        'python', '-m', 'pytest',
        'tests/test_database.py',
        '--tb=short',
        '-v'
    ]
    return subprocess.run(cmd).returncode

def run_integration_tests():
    """Run integration tests only."""
    print("🔗 Running integration tests...")
    cmd = [
        'python', '-m', 'pytest',
        'tests/test_api_integration.py',
        '--tb=short',
        '-v'
    ]
    return subprocess.run(cmd).returncode

def run_mock_tests():
    """Run mock tests only."""
    print("🎭 Running mock tests...")
    cmd = [
        'python', '-m', 'pytest',
        'tests/test_mongodb_mocking.py',
        '--tb=short',
        '-v'
    ]
    return subprocess.run(cmd).returncode

def run_password_tests():
    """Run password security tests only."""
    print("🔐 Running password security tests...")
    cmd = [
        'python', '-m', 'pytest',
        'tests/test_password_security.py',
        '--tb=short',
        '-v'
    ]
    return subprocess.run(cmd).returncode

def run_all_tests():
    """Run all tests."""
    print("🚀 Running all tests...")
    cmd = [
        'python', '-m', 'pytest',
        'tests/',
        '--tb=short',
        '-v'
    ]
    return subprocess.run(cmd).returncode

def run_tests_with_coverage():
    """Run all tests with coverage report."""
    print("📊 Running tests with coverage...")
    cmd = [
        'python', '-m', 'pytest',
        'tests/',
        '--cov=.',
        '--cov-report=html:tests/coverage_html',
        '--cov-report=term-missing',
        '--cov-report=xml:tests/coverage.xml',
        '--tb=short',
        '-v'
    ]
    return subprocess.run(cmd).returncode

def check_test_dependencies():
    """Check if all test dependencies are installed."""
    print("🔍 Checking test dependencies...")
    
    required_packages = [
        'pytest',
        'pytest-cov', 
        'pytest-mock',
        'mongomock'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Install them with: pip install pytest pytest-cov pytest-mock mongomock")
        return False
    
    print("✓ All test dependencies are installed")
    return True

def run_linting():
    """Run code linting (if available)."""
    print("🧹 Running code linting...")
    
    # Try to run flake8 if available
    try:
        cmd = ['flake8', 'tests/', '--max-line-length=100', '--exclude=venv']
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Linting passed")
        else:
            print(f"⚠️  Linting issues found:\n{result.stdout}")
        return result.returncode
    except FileNotFoundError:
        print("⚠️  flake8 not available, skipping linting")
        return 0

def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description='Test runner for Flask application')
    parser.add_argument('--unit', action='store_true', help='Run unit tests only')
    parser.add_argument('--integration', action='store_true', help='Run integration tests only')
    parser.add_argument('--mock', action='store_true', help='Run mock tests only')
    parser.add_argument('--password', action='store_true', help='Run password tests only')
    parser.add_argument('--coverage', action='store_true', help='Run tests with coverage')
    parser.add_argument('--lint', action='store_true', help='Run linting only')
    parser.add_argument('--check-deps', action='store_true', help='Check test dependencies')
    parser.add_argument('--all', action='store_true', help='Run all tests (default)')
    
    args = parser.parse_args()
    
    # Change to the directory containing this script
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Setup test environment
    setup_test_environment()
    
    # Check dependencies first
    if args.check_deps or not check_test_dependencies():
        return 1
    
    # Run requested tests
    exit_code = 0
    
    if args.lint:
        exit_code = run_linting()
    elif args.unit:
        exit_code = run_unit_tests()
    elif args.integration:
        exit_code = run_integration_tests()
    elif args.mock:
        exit_code = run_mock_tests()
    elif args.password:
        exit_code = run_password_tests()
    elif args.coverage:
        exit_code = run_tests_with_coverage()
    elif args.all or not any([args.unit, args.integration, args.mock, args.password, args.coverage, args.lint]):
        exit_code = run_all_tests()
    
    # Summary
    if exit_code == 0:
        print("\n✅ All tests passed!")
    else:
        print(f"\n❌ Tests failed with exit code {exit_code}")
    
    return exit_code

if __name__ == '__main__':
    sys.exit(main())
