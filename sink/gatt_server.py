import dbus
import dbus.mainloop.glib
import dbus.service

# Reuse the classes from node/gatt_server.py via imports if possible, 
# but they are in 'node' package.
# Better to copy-paste the base classes or move them to 'common' if used by both.
# Given 'common' is for base modules, let's assume we can't easily move 'GATTServer' core logic there 
# without refactoring 'Application', 'Service' etc classes.
# Plan says "Similar to Node's GATT Server". I'll duplicate the boilerplate to keep it self-contained
# or import if I moved it. I didn't move it to common.
# I will implement it specifically for Sink.

from common.constants import (
    SERVICE_UUID, CHARACTERISTIC_UUID, MANUFACTURER_ID,
    BLUEZ_SERVICE_NAME, LE_ADVERTISING_MANAGER_IFACE, LE_ADVERTISEMENT_IFACE,
    GATT_MANAGER_IFACE, DBUS_OM_IFACE, DBUS_PROP_IFACE,
    GATT_SERVICE_IFACE, GATT_CHRC_IFACE 
)

# --- Simplified DBus GATT Classes (Duplicated for independence/simplicity in this context) ---
# ideally these should be in common/dbus_utils.py

class Application(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/"
        self.services = []
        dbus.service.Object.__init__(self, bus, self.path)
    def get_path(self): return dbus.ObjectPath(self.path)
    def add_service(self, service): self.services.append(service)
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
    PATH_BASE = "/org/bluez/sink/service"
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
                "Characteristics": dbus.Array([c.get_path() for c in self.characteristics], signature="o"),
            }
        }
    def get_path(self): return dbus.ObjectPath(self.path)
    def add_characteristic(self, chrc): self.characteristics.append(chrc)
    def get_characteristics(self): return self.characteristics

class Characteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.path + "/char" + str(index)
        self.bus = bus
        self.uuid = uuid
        self.service = service
        self.flags = flags
        dbus.service.Object.__init__(self, bus, self.path)
    def get_properties(self):
        return {
            GATT_CHRC_IFACE: {
                "Service": self.service.get_path(),
                "UUID": self.uuid,
                "Flags": self.flags,
            }
        }
    def get_path(self): return dbus.ObjectPath(self.path)
    @dbus.service.method(GATT_CHRC_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        device_path = options.get('device')
        src_mac = None
        if device_path:
            try:
                base = str(device_path).split("dev_")[-1]
                src_mac = base.replace("_", ":")
            except:
                pass
        
        if self.on_write_callback:
            self.on_write_callback(bytes(value), src_mac)
    
    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, interface, changed, invalidated):
        pass

class RxCharacteristic(Characteristic):
    def __init__(self, bus, index, service, callback):
        Characteristic.__init__(self, bus, index, CHARACTERISTIC_UUID, ["write", "write-without-response", "notify"], service)
        self.on_write_callback = callback
    def WriteValue(self, value, options):
        # Override handled above
        pass
    
    def StartNotify(self): self.notifying = True
    def StopNotify(self): self.notifying = False
    
    def send_notification(self, value):
        val_array = dbus.Array(value, signature="y")
        self.PropertiesChanged(GATT_CHRC_IFACE, {"Value": val_array}, [])


class SinkAdvertisement(dbus.service.Object):
    PATH_BASE = "/org/bluez/sink/advertisement"

    def __init__(self, bus, index, advertising_type):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.ad_type = advertising_type
        self.service_uuids = [SERVICE_UUID]
        # self.manufacturer_data = dbus.Dictionary({}, signature="qay") # Removed
        self.hop_count = None
        self.local_name = "SIC-Sink"
        self.include_tx_power = True
        dbus.service.Object.__init__(self, bus, self.path)
        
        # REQUIRED: Hop Count = 0 for Sink
        self.set_hop_count(0)

    def set_hop_count(self, hop_count):
        # Just store the value
        self.hop_count = hop_count

    def get_properties(self):
        properties = dict()
        properties["Type"] = self.ad_type
        if self.service_uuids:
            properties["ServiceUUIDs"] = dbus.Array(self.service_uuids, signature="s")
        
        if self.hop_count is not None:
            val = self.hop_count
            if val < 0: val = 255 # Handle disconnected state
            
            # User suggested using 'qv' signature (uint16 -> Variant)
            # Wrapping key in UInt16 explicitly
            # Value is dbus.Array(bytes, signature='y') which fits inside Variant
            m_data = dbus.Dictionary({
                dbus.UInt16(MANUFACTURER_ID): dbus.Array([dbus.Byte(val)], signature="y")
            }, signature="qv")
            properties["ManufacturerData"] = m_data

        if self.local_name:
            properties["LocalName"] = dbus.String(self.local_name)
        return {LE_ADVERTISEMENT_IFACE: properties}

    def get_path(self): return dbus.ObjectPath(self.path)
    
    @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature='', out_signature='')
    def Release(self):
        print('%s: Released!' % self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != LE_ADVERTISEMENT_IFACE: raise dbus.exceptions.DBusException("UnknownInterface", "")
        return self.get_properties()[LE_ADVERTISEMENT_IFACE]

class SinkGATTServer:
    def __init__(self, packet_handler_callback):
        self.bus = dbus.SystemBus()
        self.packet_handler = packet_handler_callback
        
        self.app = Application(self.bus)
        self.service = Service(self.bus, 0, SERVICE_UUID, True)
        self.app.add_service(self.service)
        
        self.rx_char = RxCharacteristic(self.bus, 0, self.service, self._on_write)
        self.service.add_characteristic(self.rx_char)
        
        self.advertisement = SinkAdvertisement(self.bus, 0, "peripheral")

    def _on_write(self, value, src_mac):
        if self.packet_handler:
            self.packet_handler(value, src_mac)
            
    def send_notification(self, data):
        self.rx_char.send_notification(data)

    def start(self):
        service_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez/hci0"),
            GATT_MANAGER_IFACE)
        service_manager.RegisterApplication(
            self.app.get_path(), {},
            reply_handler=lambda: print("[Sink] App registered"),
            error_handler=lambda e: print(f"[Sink] App Error: {e}")
        )

        ad_manager = dbus.Interface(
            self.bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez/hci0"),
            LE_ADVERTISING_MANAGER_IFACE)
        ad_manager.RegisterAdvertisement(
            self.advertisement.get_path(), {},
            reply_handler=lambda: print("[Sink] Ad registered"),
            error_handler=lambda e: print(f"[Sink] Ad Error: {e}")
        )
