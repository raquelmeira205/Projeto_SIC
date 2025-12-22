
import logging

class UplinkSelector:
    def __init__(self, ble_discovery):
        self.ble_discovery = ble_discovery
        self.current_uplink = None # (mac, hop_count)

    def select_best_uplink(self):
        """
        Scans and selects the best uplink based on Hop Count and RSSI.
        Returns: (connectable_peripheral, hop_count, nid) or None
        """
        candidates = self.ble_discovery.scan(duration_ms=4000)
        
        # Filter: Must define Hop Count >= 0 (meaning part of Sink tree)
        valid_candidates = [c for c in candidates if c['hop_count'] >= 0]
        
        if not valid_candidates:
            return None, candidates

        # Sort by:
        # 1. Hop Count (Low is better)
        # 2. RSSI (High is better) - Note: RSSI is negative, so max() works, but sort key needs negation for descending
        
        # We want smallest Hop Count, then Largest RSSI
        # Tuple sort: (hop_count, -rssi) if sorting Ascending.
        # RSSI -90 is smaller than -50. We want -50.
        # So we sort Ascending on Hop Count.
        # If Hop Count equal, we want larger RSSI.
        # Tuple comparison: (1, -90) vs (1, -50).
        # We want (1, -50) to be "smaller" or "first"? No, we want best.
        # Let's say we sort Ascending. (1, -(-90)) = (1, 90). (1, -(-50)) = (1, 50).
        # If we sort by (hop, -rssi), then (1, -(-50)=50) comes before (1, 90) NO.
        
        # Let's just use min with key.
        best = min(valid_candidates, key=lambda c: (c['hop_count'], -c['rssi']))
        
        logging.info(f"Selected Uplink: {best['name']} ({best['mac']}) Hop={best['hop_count']} RSSI={best['rssi']}")
        return best, candidates # Returns (best, all raw candidates)
