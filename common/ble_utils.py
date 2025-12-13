import time
import simplepyble
from common.constants import MANUFACTURER_ID

# Cache adapters to avoid repeated enumeration
_ADAPTER = None

def get_adapter():
    global _ADAPTER
    if _ADAPTER:
        return _ADAPTER
    
    adapters = simplepyble.Adapter.get_adapters()
    if not adapters:
        print("[!] Nenhum adaptador Bluetooth encontrado (simplepyble).")
        return None
    
    # Select the first one by default
    _ADAPTER = adapters[0]
    print(f"[*] Adaptador selecionado: {_ADAPTER.identifier()} [{_ADAPTER.address()}]")
    return _ADAPTER

def scan_nearby_devices(duration=5):
    """
    Scans for devices using simplepyble.
    Returns a list of tuples: (mac, name, hop_count, rssi)
    """
    adapter = get_adapter()
    if not adapter:
        return []

    print(f"[*] A iniciar scan simplepyble por {duration}s...")
    
    # Ensure any previous scan is stopped to avoid "Operation already in progress"
    try:
        adapter.scan_stop()
    except Exception:
        pass # Ignore if not scanning
    
    try:
        adapter.scan_for(duration * 1000) # millseconds
    except RuntimeError as e:
        if "inprogress" in str(e).lower() or "in progress" in str(e).lower():
            print("[!] Scan already in progress. Attempting to stop and retry...")
            try:
                adapter.scan_stop()
                time.sleep(1)
                adapter.scan_for(duration * 1000)
            except Exception as e2:
                print(f"[!] Failed to retry scan: {e2}")
                return []
        else:
            print(f"[!] Critical error during scan: {e}")
            return []
    
    peripherals = adapter.scan_get_results()
    
    results = []
    for p in peripherals:
        mac = p.address()
        name = p.identifier()
        rssi = p.rssi()
        
        hop_count = -1
        
        # Check Manufacturer Data for Hop Count
        # simplepyble returns a dict {int: bytes}
        m_data = p.manufacturer_data()
        
        if MANUFACTURER_ID in m_data:
            data_bytes = m_data[MANUFACTURER_ID]
            if len(data_bytes) > 0:
                hop_count = data_bytes[0]
                
        # Only add relevant devices or all? 
        # The original code filtered later, but updated the list if found.
        # We will return all found, let the manager filter.
        
        results.append((mac, name, hop_count, rssi))
        
    return results

def get_simplepyble_device(mac_address):
    """
    Tries to find a peripheral with the given MAC in the latest scan results.
    Note: You must have scanned recently.
    """
    adapter = get_adapter()
    if not adapter:
        return None
        
    # getting results directly from cache without re-scanning
    peripherals = adapter.scan_get_results()
    for p in peripherals:
        if p.address() == mac_address:
            return p
    return None