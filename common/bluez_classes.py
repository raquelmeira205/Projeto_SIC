import sys
from pydbus import SystemBus
from gi.repository import GLib
# Use absolute import logic or sys.path hack should be already present in main.py, 
# but inside this package we can use relative import if loaded as package, 
# or direct import if sys.path is set.
# Assuming sys.path is set correctly by main files.
from common.ble_utils import ADAPTER_PATH

# Constantes DBus
DBUS_OM_IFACE = 'org.freedesktop.DBus.ObjectManager'
DBUS_PROP_IFACE = 'org.freedesktop.DBus.Properties'

LE_ADVERTISEMENT_IFACE = 'org.bluez.LEAdvertisement1'
GATT_MANAGER_IFACE = 'org.bluez.GattManager1'
GATT_APP_IFACE = 'org.bluez.GattApplication1'
GATT_SERVICE_IFACE = 'org.bluez.GattService1'
GATT_CHRC_IFACE = 'org.bluez.GattCharacteristic1'
GATT_DESC_IFACE = 'org.bluez.GattDescriptor1'

BLUEZ_SERVICE_NAME = 'org.bluez'

from gi.repository import GLib

BLUEZ_SERVICE_NAME = 'org.bluez'
LE_ADVERTISEMENT_IFACE = 'org.bluez.LEAdvertisement1'


class Advertisement(object):
    """
    BlueZ LEAdvertisement1 (pydbus compatible, spec-correct)
    """
    dbus = f"""
    <node>
        <interface name="{LE_ADVERTISEMENT_IFACE}">
            <method name="Release"/>
            <property name="Type" type="s" access="read"/>
            <property name="ServiceUUIDs" type="as" access="read"/>
            <property name="ManufacturerData" type="a{{qv}}" access="read"/>
            <property name="SolicitUUIDs" type="as" access="read"/>
            <property name="ServiceData" type="a{{sv}}" access="read"/>
            <property name="LocalName" type="s" access="read"/>
            <property name="Appearance" type="q" access="read"/>
            <property name="Includes" type="as" access="read"/>
        </interface>
    </node>
    """

    def __init__(self, bus, index, advertising_type="peripheral"):
        self.bus = bus
        self.path = f"/org/bluez/example/advertisement{index}"

        self.ad_type = advertising_type
        self.service_uuids = []
        self.manufacturer_data = {}
        self.solicit_uuids = []
        self.service_data = {}

        self.local_name = None
        self.appearance = None
        self.include_tx_power = False

        self.registration = None

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------

    def get_path(self):
        return self.path

    def add_service_uuid(self, uuid):
        self.service_uuids.append(uuid)

    def add_local_name(self, name):
        self.local_name = name

    def add_manufacturer_data(self, company_id, data):
        if isinstance(data, list):
            data = bytes(data)
        self.manufacturer_data[company_id] = GLib.Variant('ay', data)

    def add_service_data(self, uuid, data):
        if isinstance(data, list):
            data = bytes(data)
        self.service_data[uuid] = GLib.Variant('ay', data)

    # ---------------------------------------------------------------------
    # DBus properties (exact BlueZ spec)
    # ---------------------------------------------------------------------

    @property
    def Type(self):
        return self.ad_type

    @property
    def ServiceUUIDs(self):
        return self.service_uuids

    @property
    def ManufacturerData(self):
        return self.manufacturer_data

    @property
    def SolicitUUIDs(self):
        return self.solicit_uuids

    @property
    def ServiceData(self):
        return self.service_data

    @property
    def LocalName(self):
        return self.local_name or ""

    @property
    def Appearance(self):
        return self.appearance if self.appearance is not None else 0

    @property
    def Includes(self):
        return ["tx-power"] if self.include_tx_power else []

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------

    def Release(self):
        print(f"{self.path}: Released by BlueZ")

    def register(self, adapter_path):
        # Ensure adapter is powered
        props = self.bus.get(BLUEZ_SERVICE_NAME, adapter_path)['org.freedesktop.DBus.Properties']
        props.Set('org.bluez.Adapter1', 'Powered', GLib.Variant('b', True))

        # Export object
        self.registration = self.bus.register_object(
            self.path,
            self,
            self.dbus      # <-- REQUIRED
        )

        print(f"Registering advertisement at {self.path}")
        lem = self.bus.get(BLUEZ_SERVICE_NAME, adapter_path)['org.bluez.LEAdvertisingManager1']
        lem.RegisterAdvertisement(self.path, {})

        print("Advertisement registered")

    def unregister(self, adapter_path):
        try:
            lem = self.bus.get(BLUEZ_SERVICE_NAME, adapter_path)['org.bluez.LEAdvertisingManager1']
            lem.UnregisterAdvertisement(self.path)
        finally:
            if self.registration:
                self.registration.unregister()
                self.registration = None
            print("Advertisement unregistered")



class Service(object):
    """
    GATT Service
    """
    dbus = f"""
    <node>
        <interface name="{GATT_SERVICE_IFACE}">
            <property name="UUID" type="s" access="read"/>
            <property name="Primary" type="b" access="read"/>
        </interface>
    </node>
    """

    def __init__(self, bus, index, uuid, primary):
        self.path = '/org/bluez/example/service' + str(index)
        self.bus = bus
        self.uuid = uuid
        self.primary = primary
        self.characteristics = []

    def get_path(self):
        return self.path

    def add_characteristic(self, characteristic):
        self.characteristics.append(characteristic)

    @property
    def UUID(self):
        return self.uuid

    @property
    def Primary(self):
        return self.primary


class Characteristic(object):
    """
    GATT Characteristic
    """
    dbus = f"""
    <node>
        <interface name="{GATT_CHRC_IFACE}">
            <method name="ReadValue">
                <arg name="options" type="a{{sv}}" direction="in"/>
                <arg name="value" type="ay" direction="out"/>
            </method>
            <method name="WriteValue">
                <arg name="value" type="ay" direction="in"/>
                <arg name="options" type="a{{sv}}" direction="in"/>
            </method>
            <method name="StartNotify"/>
            <method name="StopNotify"/>
            <property name="UUID" type="s" access="read"/>
            <property name="Service" type="o" access="read"/>
            <property name="Value" type="ay" access="read"/>
            <property name="Notifying" type="b" access="read"/>
            <property name="Flags" type="as" access="read"/>
        </interface>
    </node>
    """

    def __init__(self, bus, index, uuid, flags, service):
        self.path = service.get_path() + '/char' + str(index)
        self.bus = bus
        self.uuid = uuid
        self.service = service
        self.flags = flags
        self.value = []
        self.notifying = False
        
    def get_path(self):
        return self.path

    def ReadValue(self, options):
        # Default implementation
        return self.value

    def WriteValue(self, value, options):
        # Default implementation
        self.value = value

    def StartNotify(self):
        self.notifying = True

    def StopNotify(self):
        self.notifying = False

    @property
    def UUID(self):
        return self.uuid

    @property
    def Service(self):
        return self.service.get_path()

    @property
    def Value(self):
        return self.value

    @property
    def Notifying(self):
        return self.notifying

    @property
    def Flags(self):
        return self.flags

class Application(object):
    """
    GATT Application Manager.
    Exports the ObjectManager interface for BlueZ to discover services/characteristics.
    """
    dbus = f"""
    <node>
        <interface name="{DBUS_OM_IFACE}">
            <method name="GetManagedObjects">
                <arg name="objects" type="a{{oa{{sa{{sv}}}}}}" direction="out"/>
            </method>
        </interface>
    </node>
    """

    def __init__(self, bus):
        self.path = '/'
        self.bus = bus
        self.services = []

    def get_path(self):
        return self.path

    def add_service(self, service):
        self.services.append(service)

    def GetManagedObjects(self):
        response = {}
        for service in self.services:
            response[service.get_path()] = {
                GATT_SERVICE_IFACE: {
                    'UUID': GLib.Variant('s', service.UUID),
                    'Primary': GLib.Variant('b', service.Primary)
                }
            }
            for chrc in service.characteristics:
                response[chrc.get_path()] = {
                    GATT_CHRC_IFACE: {
                        'UUID': GLib.Variant('s', chrc.UUID),
                        'Service': GLib.Variant('o', chrc.Service),
                        'Flags': GLib.Variant('as', chrc.Flags)
                    }
                }
        return response

    def register(self):
        # Register App with GATT Manager
        gatt_manager = self.bus.get(BLUEZ_SERVICE_NAME, ADAPTER_PATH)['org.bluez.GattManager1']
        
        # Publish Object Manager (Application)
        self.registration = self.bus.register_object(self.path, self, None)
        
        # Publish children (Services/Chars)
        for service in self.services:
            self.bus.register_object(service.get_path(), service, None)
            for chrc in service.characteristics:
                self.bus.register_object(chrc.get_path(), chrc, None)
                
        print('Registering GATT Application...')
        gatt_manager.RegisterApplication(self.path, {})
        print('GATT Application registered.')

    def run(self):
        loop = GLib.MainLoop()
        try:
            loop.run()
        except KeyboardInterrupt:
            loop.quit()
