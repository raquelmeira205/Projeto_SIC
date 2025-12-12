# Constants for the SIC Project

# UUIDs
# Using a custom 128-bit UUID for the Service
# Generated for this project: 5349432d-5052-4f4a-4543-543030303031 (SIC-PROJECT00001 in hex-ish)
SERVICE_UUID = "5349432d-5052-4f4a-4543-543030303031"
CHARACTERISTIC_UUID = "5349432d-5052-4f4a-4543-543030303032"

# Manufacturer ID for Advertisements (Matches existing code)
MANUFACTURER_ID = 0xFFFE

# DBus Paths
BLUEZ_SERVICE_NAME = "org.bluez"
DBUS_OM_IFACE = "org.freedesktop.DBus.ObjectManager"
DBUS_PROP_IFACE = "org.freedesktop.DBus.Properties"

LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"

GATT_MANAGER_IFACE = "org.bluez.GattManager1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHRC_IFACE = "org.bluez.GattCharacteristic1"
GATT_DESC_IFACE = "org.bluez.GattDescriptor1"
