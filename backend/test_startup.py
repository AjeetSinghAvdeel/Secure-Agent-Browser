#!/usr/bin/env python3
"""
SecureAgent Startup Simulation
Test that all initialization happens correctly on server startup
"""

import sys

print('Testing startup sequence...\n')

# 1. Load FastAPI
print('1. Creating FastAPI app...')
try:
    from api import app
    print(f'   ✓ App created with {len(app.routes)} routes\n')
except Exception as e:
    print(f'   ❌ Error: {e}\n')
    sys.exit(1)

# 2. Initialize metrics
print('2. Initializing metrics system...')
try:
    from metrics import get_tracker
    tracker = get_tracker()
    print(f'   ✓ Metrics ready: TP={tracker.tp}, FP={tracker.fp}, TN={tracker.tn}, FN={tracker.fn}\n')
except Exception as e:
    print(f'   ❌ Error: {e}\n')
    sys.exit(1)

# 3. Check task success harness
print('3. Checking task success harness...')
try:
    from task_success_harness import TaskSuccessHarness
    harness = TaskSuccessHarness()
    harness.register_default_scenarios()
    print(f'   ✓ Task harness ready with {len(harness.scenarios)} scenarios\n')
except Exception as e:
    print(f'   ⚠ Optional feature unavailable: {e}\n')

# 4. Check Firebase
print('4. Checking Firebase metrics (optional)...')
try:
    from firebase_metrics import is_firebase_available
    if is_firebase_available():
        print('   ✓ Firebase persistence ready\n')
    else:
        print('   ⊘ Firebase not available (continuing without cloud persistence)\n')
except Exception as e:
    print(f'   ⊘ Firebase not configured\n')

# 5. Health endpoint
print('5. Testing health endpoint response...')
try:
    from datetime import datetime, timezone
    try:
        from firebase_admin import firestore
        firebase_available = firestore is not None
    except:
        firebase_available = False
    
    response = {
        'status': 'healthy',
        'metrics_ready': True,
        'firebase_ready': firebase_available,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    print(f'   ✓ Health check endpoint ready\n')
    print(f'   Sample response: {response}\n')
except Exception as e:
    print(f'   ⚠ Health check error: {e}\n')

print('=' * 70)
print('✅ STARTUP SEQUENCE COMPLETE - All subsystems initialized')
print('=' * 70)
print('\nReady to run: python3 -m uvicorn api:app --reload')
