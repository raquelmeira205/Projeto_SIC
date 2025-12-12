import sys
import os

print("Checking imports...")

try:
    import common.constants
    print("[OK] common.constants")
    import common.ble_utils
    print("[OK] common.ble_utils")
    import node.gatt_server
    print("[OK] node.gatt_server")
    import node.ble_manager
    print("[OK] node.ble_manager")
    import sink.gatt_server
    print("[OK] sink.gatt_server")
    import sink.ble_manager
    print("[OK] sink.ble_manager")
    # import main files (checks syntax)
    import node.main
    print("[OK] node.main")
    import sink.main
    print("[OK] sink.main")
    
    print("All modules imported successfully.")
except Exception as e:
    print(f"[FAIL] Import Error: {e}")
    sys.exit(1)
