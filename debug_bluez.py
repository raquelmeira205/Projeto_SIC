import sys
from pydbus import SystemBus

bus = SystemBus()

print("Listing all BlueZ objects:")
try:
    manager = bus.get('org.bluez', '/')
    objects = manager.GetManagedObjects()
    
    found_adapter = False
    for path, interfaces in objects.items():
        print(f"\nPath: {path}")
        for iface, props in interfaces.items():
            print(f"  Interface: {iface}")
            if iface == 'org.bluez.Adapter1':
                found_adapter = True
                print(f"    Address: {props.get('Address')}")
                print(f"    Powered: {props.get('Powered')}")
                print(f"    Name: {props.get('Name')}")
    
    if not found_adapter:
        print("\n[!] No Bluetooth Adapter found!")
            
except Exception as e:
    print(f"Error inspecting BlueZ: {e}")
