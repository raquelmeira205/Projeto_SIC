
from .constants import SIC_SERVICE_UUID, SIC_RX_CHAR_UUID

# We can add more specific GATT related constants here if needed.
# For now, it re-exports the main UUIDs and potentially flags.

GATT_CHARACTERISTIC_IFACE = 'org.bluez.GattCharacteristic1'
GATT_SERVICE_IFACE = 'org.bluez.GattService1'
GATT_DESC_IFACE = 'org.bluez.GattDescriptor1'

class GATTUtils:
    @staticmethod
    def is_sic_service(uuid):
        return uuid.lower() == SIC_SERVICE_UUID.lower()
