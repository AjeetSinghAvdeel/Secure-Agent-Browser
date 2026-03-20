#!/usr/bin/env python3
"""
SecureAgent Backend - Startup Verification & Health Check
=========================================================

This script verifies that all dependencies and modules are correctly loaded
before starting the uvicorn server.

Run this manually to check everything is ready:
    python3 verify_startup.py

Or the API will automatically check on startup.
"""

import sys
import os

def check_python_version():
    """Ensure Python 3.8+"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python 3.8+ required (you have {version.major}.{version.minor})")
        return False
    print(f"✓ Python {version.major}.{version.minor}.{version.micro}")
    return True


def check_dependencies():
    """Check if all required dependencies are installed"""
    required = [
        'fastapi',
        'uvicorn',
        'pydantic',
        'requests',
    ]
    
    optional = [
        'firebase_admin',  # Optional cloud persistence
    ]
    
    print("\nChecking dependencies...")
    all_ok = True
    
    for pkg in required:
        try:
            __import__(pkg)
            print(f"✓ {pkg}")
        except ImportError:
            print(f"❌ {pkg} (REQUIRED - install with: pip install {pkg})")
            all_ok = False
    
    for pkg in optional:
        try:
            __import__(pkg)
            print(f"✓ {pkg} (optional)")
        except ImportError:
            print(f"⊘ {pkg} (optional - install if needed)")
    
    return all_ok


def check_modules():
    """Check if all SecureAgent modules are importable"""
    print("\nChecking SecureAgent modules...")
    modules = [
        'api',
        'metrics',
        'task_success_harness',
        'firebase_metrics',
    ]
    
    all_ok = True
    
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module}.py")
        except ImportError as e:
            print(f"❌ {module}.py: {e}")
            all_ok = False
    
    return all_ok


def check_metrics_initialization():
    """Check if metrics tracker initializes"""
    print("\nInitializing metrics system...")
    try:
        from metrics import get_tracker
        tracker = get_tracker()
        print(f"✓ Metrics tracker ready")
        print(f"  - TP={tracker.tp}, FP={tracker.fp}, TN={tracker.tn}, FN={tracker.fn}")
        return True
    except Exception as e:
        print(f"❌ Metrics initialization failed: {e}")
        return False


def check_api_startup():
    """Try to create the FastAPI app"""
    print("\nChecking FastAPI app...")
    try:
        from api import app
        print(f"✓ FastAPI app created")
        
        # Check if routes are registered
        routes = len(app.routes)
        print(f"  - {routes} routes registered")
        
        # List key endpoints
        endpoint_names = [route.name for route in app.routes if hasattr(route, 'name')]
        metrics_endpoints = [e for e in endpoint_names if 'metric' in e.lower() or 'error' in e.lower()]
        if metrics_endpoints:
            print(f"  - Metrics endpoints: {', '.join(metrics_endpoints)}")
        
        return True
    except Exception as e:
        print(f"❌ FastAPI app initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all startup checks"""
    print("=" * 70)
    print("  SecureAgent Backend - Startup Verification".center(70))
    print("=" * 70)
    
    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("SecureAgent Modules", check_modules),
        ("Metrics System", check_metrics_initialization),
        ("FastAPI App", check_api_startup),
    ]
    
    results = []
    
    for name, check in checks:
        try:
            result = check()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ {name} check failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("  Summary".center(70))
    print("=" * 70)
    
    all_passed = all(result for _, result in results)
    
    for name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status:8} {name}")
    
    print("=" * 70)
    
    if all_passed:
        print("\n✅ All checks passed! Ready to run:")
        print("   python3 -m uvicorn api:app --reload")
        print("\n   Then visit: http://localhost:8000/docs")
        return 0
    else:
        print("\n❌ Some checks failed. Fix issues above before starting.")
        print("\nTo install missing dependencies:")
        print("   pip install -r requirements.txt")
        return 1


if __name__ == "__main__":
    sys.exit(main())
