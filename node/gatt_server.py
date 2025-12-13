import sys
import dbus
import dbus.mainloop.glib
import dbus.service

from common.constants import (
    SERVICE_UUID, CHARACTERISTIC_UUID, MANUFACTURER_ID,
    BLUEZ_SERVICE_NAME, DBUS_OM_IFACE, DBUS_PROP_IFACE,
    LE_ADVERTISING_MANAGER_IFACE, LE_ADVERTISEMENT_IFACE,
    GATT_MANAGER_IFACE, GATT_SERVICE_IFACE, GATT_CHRC_IFACE,
    GATT_DESC_IFACE
)

class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/"
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_service(self, service):
        self.services.append(service)

    @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.get_path()] = service.get_properties()
            chrcs = service.get_characteristics()
            for chrc in chrcs:
                response[chrc.get_path()] = chrc.get_properties()
        return response

class Service(dbus.service.Object):
    PATH_BASE = "/org/bluez/example/service"

    def __init__(self, bus, index, uuid, primary):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_SERVICE_IFACE: {
                "UUID": self.uuid,
                "Primary": self.primary,
                "Characteristics": dbus.Array(
                    [c.get_path() for c in self.characteristics],
                    signature="o"
                ),
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, chrc):
        self.characteristics.append(chrc)

    def get_characteristics(self):
        return self.characteristics

class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + "/char" + str(index)
        self.bus = bus
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.descriptors = []
        dbus.service.Object.__init__(self, bus, self.path)

    def get_properties(self):
        return {
            GATT_CHRC_IFACE: {
                "Service": self.service.get_path(),
                "UUID": self.uuid,
                "Flags": self.flags,
                "Descriptors": dbus.Array(
                    [d.get_path() for d in self.descriptors],
                    signature="o"
                ),
            }
        }

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_descriptor(self, descriptor):
        self.descriptors.append(descriptor)

    def get_descriptors(self):
        return self.descriptors

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        # Default read: returns empty by default or could return status
        return []

    @dbus.service.method(GATT_CHRC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        # Extract source device MAC from options
        device_path = options.get('device')
        src_mac = None
        if device_path:
            # path format: .../dev_XX_XX_XX_XX_XX_XX
            try:
                base = str(device_path).split("dev_")[-1]
                src_mac = base.replace("_", ":")
            except:
                pass
        
        print(f"[GATT] Write received from {src_mac} ({len(value)} bytes)")
        
        # Notify listener
        if hasattr(self, 'on_write_callback') and self.on_write_callback:
            self.on_write_callback(bytes(value), src_mac)

    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, callback):
        Characteristic.__init__(
            self, bus, index,
            CHARACTERISTIC_UUID,
            ["write", "write-without-response", "notify"], 
            service,
        )
        self.on_write_callback = callback
        self.notifying = False

    def StartNotify(self):
        print(f"[GATT] Notifications started for {self.path}")
        self.notifying = True

    def StopNotify(self):
        print(f"[GATT] Notifications stopped for {self.path}")
        self.notifying = False
        
    def send_notification(self, value):
        # We assume value is bytes
        # Emit PropertiesChanged
        val_array = dbus.Array(value, signature="y")
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": val_array}, [])


class IoTAvertisement(dbus.service.Object):
    PATH_BASE = "/org/bluez/example/advertisement"

    def __init__(self, bus, index, advertising_type):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.ad_type = advertising_type
        self.service_uuids = [SERVICE_UUID] # Advertise our Service
        # self.manufacturer_data = dbus.Dictionary({}, signature="qay")
        self.hop_count = None
        self.solicit_uuids = None
        self.service_data = None
        self.local_name = "Node" # Shortened name
        self.include_tx_power = False # Disable TX Power to save bytes
        dbus.service.Object.__init__(self, bus, self.path)
        
        # Default Hop Count = -1 (not connected)
        self.set_hop_count(-1)

    def set_hop_count(self, hop_count):
        # Manufacturer ID 0xFFFE -> [hop_count]
        # hop_count should be a uint8 (byte)
        if hop_count < 0:
            # Maybe just don't advertise ID if not connected, or advertise 0xFF?
            # Existing code check: 'if len(adv_data) > 0: hop_count = adv_data[0]'
            # 'hop_count = -1 # default'
            # Let's use 0xFF to indicate -1 (255) if it fits in a byte, or just handle logic logic
            # Actually, the logic says 'if hop_count >= 0'.
            # So if we are not connected, maybe we shouldn't put manufacturer data?
            # Or put a special value.
            pass
        
        # We will use 0xFF for 'not connected' in the byte, but the scanner logic 
        # treats it as the value. 
        # Just store
        self.hop_count = hop_count

    def get_properties(self):
        properties = dict()
        properties["Type"] = self.ad_type
        if self.service_uuids:
            properties["ServiceUUIDs"] = dbus.Array(self.service_uuids, signature="s")
            
        if self.hop_count is not None:
            val = self.hop_count
            if val < 0: val = 255
            
            m_data = dbus.Dictionary({
                dbus.UInt16(MANUFACTURER_ID): dbus.Array([dbus.Byte(val)], signature="y")
            }, signature="qv")
            properties["ManufacturerData"] = m_data
            
        # properties["Includes"] = dbus.Array(["tx-power"], signature="s")
        
        if self.local_name:
            properties["LocalName"] = dbus.String(self.local_name)
            
        return {LE_ADVERTISEMENT_IFACE: properties}

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature='', out_signature='')
    def Release(self):
        print('%s: Released!' % self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != LE_ADVERTISEMENT_IFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface",
                "The object does not implement the 'GetAll' method for interface %s"
                % interface,
            )
        return self.get_properties()[LE_ADVERTISEMENT_IFACE]


class NodeGATTServer:
    def __init__(self, packet_handler_callback):
        self.bus = dbus.SystemBus()
        self.packet_handler = packet_handler_callback
        
        # Setup Application
        self.app = Application(self.bus)
        self.service = Service(self.bus, 0, SERVICE_UUID, True)
        self.app.add_service(self.service)
        
        # RX Characteristic (Other nodes write here)
        self.rx_char = RxCharacteristic(self.bus, 0, self.service, self._on_write)
        self.service.add_characteristic(self.rx_char)
        
        # Setup Advertisement
        self.advertisement = IoTAvertisement(self.bus, 0, "peripheral")

    def _on_write(self, value, src_mac):
        # value is bytes, src_mac is string
        if self.packet_handler:
            self.packet_handler(value, src_mac)
            
    def send_notification(self, data):
        self.rx_char.send_notification(data)

    def register_ad_cb(self):
        print("[Adv] Advertisement registered")
        self.adv_retry_count = 0

    def register_ad_error_cb(self, error):
        print("[Adv] Failed to register advertisement: " + str(error))
        if self.adv_retry_count < 3:
            self.adv_retry_count += 1
            print(f"[Adv] Retrying registration ({self.adv_retry_count}/3)...")
            import time
            time.sleep(2)
            self._register_adv()
        else:
            print("[Adv] Giving up on advertisement registration.")

    def register_app_cb(self):
        print("[GATT] GATT application registered")

    def register_app_error_cb(self, error):
        print("[GATT] Failed to register application: " + str(error))

    def start(self):
        self.adv_retry_count = 0
        self._register_app()
        self._register_adv()

    def _register_app(self):
        # Register Application
        try:
            service_manager = dbus.Interface(
                self.bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez/hci0"),
                GATT_MANAGER_IFACE)
            service_manager.RegisterApplication(
                self.app.get_path(), {},
                reply_handler=self.register_app_cb,
                error_handler=self.register_app_error_cb
            )
        except Exception as e:
            print(f"[GATT] Error accessing GattManager: {e}")

    def _register_adv(self):
        # Register Advertisement
        try:
            ad_manager = dbus.Interface(
                self.bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez/hci0"),
                LE_ADVERTISING_MANAGER_IFACE)
                
            print("[Adv] Registering advertisement...")
            ad_manager.RegisterAdvertisement(
                self.advertisement.get_path(), {},
                reply_handler=self.register_ad_cb,
                error_handler=self.register_ad_error_cb
            )
        except Exception as e:
             print(f"[Adv] Error accessing LEAdvertisingManager: {e}")

    def update_hop_count(self, hop_count):
        print(f"[Adv] Updating Hop Count to {hop_count}")
        # Note: Dynamic update of advertisement data might differ between BlueZ versions.
        # Often requires Unregister + Register or just PropertiesChanged if supported.
        # For simplicity, we update the object internal state. BlueZ polls properties.
        # A trigger to 'PropertiesChanged' signal might be needed.
        
        self.advertisement.set_hop_count(hop_count)
        pass
