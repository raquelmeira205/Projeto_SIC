
import os

class NID:
    SIZE = 16

    def __init__(self, value):
        if isinstance(value, bytes):
            if len(value) != self.SIZE:
                raise ValueError(f"NID bytes must be {self.SIZE} bytes long, got {len(value)}")
            self._bytes = value
        elif isinstance(value, str):
            # Attempt 1: Try parsing as Integer (Decimal)
            try:
                val_int = int(value)
                self._bytes = val_int.to_bytes(self.SIZE, 'big')
                return
            except ValueError:
                pass

            # Attempt 2: Try parsing as Hex string
            try:
                # Remove 0x prefix if present
                clean_val = value.lower().replace('0x', '')
                # Pad if odd length (though NID should be 16 bytes = 32 hex chars)
                if len(clean_val) % 2 != 0:
                     clean_val = '0' + clean_val
                
                b = bytes.fromhex(clean_val)
                
                # If too short, pad with zeros (left)
                if len(b) < self.SIZE:
                    b = b.rjust(self.SIZE, b'\x00')
                
                if len(b) != self.SIZE:
                    raise ValueError(f"Hex result {len(b)} != {self.SIZE}")
                    
                self._bytes = b
            except ValueError:
                 raise ValueError(f"Invalid NID string format: {value}")
        else:
            raise TypeError("NID must be initialized with bytes or hex string")

    @property
    def bytes(self):
        return self._bytes

    @property
    def hex(self):
        return self._bytes.hex()

    def __str__(self):
        return self.hex

    def __repr__(self):
        return f"NID({self.hex})"

    def __eq__(self, other):
        if isinstance(other, NID):
            return self._bytes == other._bytes
        return False

    def __hash__(self):
        return hash(self._bytes)
