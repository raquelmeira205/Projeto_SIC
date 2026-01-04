import json
import os

class CRLManager:
    """
    Manages a Certificate Revocation List (CRL) stored in a JSON file.
    Tracks revoked X.509 Certificate Serial Numbers.
    """
    def __init__(self, crl_path="crl.json"):
        self.crl_path = crl_path
        self.revoked_serials = set()
        self._load()

    def _load(self):
        """Load CRL from file if it exists."""
        if os.path.exists(self.crl_path):
            try:
                with open(self.crl_path, 'r') as f:
                    data = json.load(f)
                    # Convert list back to set, ensuring integers
                    self.revoked_serials = set(int(s) for s in data.get('revoked', []))
                print(f"[CRL] Loaded {len(self.revoked_serials)} revoked certificates from {self.crl_path}")
            except Exception as e:
                print(f"[CRL] Failed to load CRL: {e}")
                self.revoked_serials = set()
        else:
            print(f"[CRL] No CRL file found at {self.crl_path}, initializing empty.")

    def save(self):
        """Save current CRL to file."""
        try:
            data = {
                'revoked': list(self.revoked_serials),
                'version': 1
            }
            with open(self.crl_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"[CRL] Saved {len(self.revoked_serials)} entries to {self.crl_path}")
        except Exception as e:
            print(f"[CRL] Failed to save CRL: {e}")

    def is_revoked(self, serial_number):
        """Check if a serial number is in the revocation list."""
        if not isinstance(serial_number, int):
            try:
                serial_number = int(serial_number)
            except:
                print(f"[CRL] Warning: invalid serial format {serial_number}")
                return False
                
        is_revoked = serial_number in self.revoked_serials
        if is_revoked:
             print(f"[CRL] DETECTED REVOKED CERTIFICATE: Serial {serial_number}")
        
        return is_revoked

    def revoke(self, serial_number):
        """Add a serial number to the revocation list."""
        if not isinstance(serial_number, int):
             try:
                 serial_number = int(serial_number)
             except:
                 raise ValueError("Serial number must be an integer")
                 
        if serial_number not in self.revoked_serials:
            self.revoked_serials.add(serial_number)
            self.save()
            print(f"[CRL] Revoked certificate serial: {serial_number}")

    def update_from_list(self, new_serials):
        """Update revocation list with multiple serials."""
        added_count = 0
        for s in new_serials:
            try:
                s_int = int(s)
                if s_int not in self.revoked_serials:
                    self.revoked_serials.add(s_int)
                    added_count += 1
            except:
                pass
        
        if added_count > 0:
            self.save()
            print(f"[CRL] Updated with {added_count} new revocations")
            return True
        return False

    def get_revoked_list(self):
        """Return list of revoked serials."""
        return list(self.revoked_serials)
