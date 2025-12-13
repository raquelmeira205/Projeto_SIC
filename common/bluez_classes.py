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

class Advertisement(object):
    """
    Encapsula o objeto org.bluez.LEAdvertisement1.
    """
    dbus = f"""
    <node>
        <interface name="{LE_ADVERTISEMENT_IFACE}">
            <method name="Release">
                <annotation name="org.freedesktop.DBus.Method.NoReply" value="true"/>
            </method>
            <property name="Type" type="s" access="read"/>
            <property name="ServiceUUIDs" type="as" access="read"/>
            <property name="ManufacturerData" type="a{{qv}}" access="read"/>
            <property name="SolicitUUIDs" type="as" access="read"/>
            <property name="ServiceData" type="a{{sv}}" access="read"/>
            <property name="IncludeTxPower" type="b" access="read"/>
            <property name="LocalName" type="s" access="read"/>
            <property name="Appearance" type="q" access="read"/>
        </interface>
    </node>
    """

    def __init__(self, bus, index, advertising_type):
        self.path = '/org/bluez/example/advertisement' + str(index)
        self.bus = bus
        self.ad_type = advertising_type
        self.service_uuids = []
        self.manufacturer_data = {}
        self.solicit_uuids = []
        self.service_data = {}
        self.include_tx_power = False
        self.local_name = None
        self.appearance = 0
        
    def get_path(self):
        return self.path
        
    def add_manufacturer_data(self, manuf_id, data):
        # pydbus expects variants, but usually automatic. 
        # data should be bytes or list of bytes.
        self.manufacturer_data[manuf_id] = GLib.Variant('ay', data)

    def add_service_uuid(self, uuid):
        self.service_uuids.append(uuid)

    def add_local_name(self, name):
        self.local_name = name

    # Properties
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
    def IncludeTxPower(self):
        return self.include_tx_power
        
    @property
    def LocalName(self):
        if self.local_name:
            return self.local_name
        return ""
        
    @property
    def Appearance(self):
        return self.appearance

    def Release(self):
        print(f'{self.path}: Released!')

    def register(self):
        adapter = self.bus.get(BLUEZ_SERVICE_NAME, ADAPTER_PATH)
        manager = self.bus.get(BLUEZ_SERVICE_NAME, ADAPTER_PATH) 
        # Note: In standard BlueZ, LEAdvertisingManager1 is on the adapter path
        # Assuming hci0.
        
        # Publish this object to DBus
        self.publication = self.bus.publish(self.path, self)
        
        print(f'Registering advertisement at {self.path}...')
        # Call RegisterAdvertisement on the adapter interface org.bluez.LEAdvertisingManager1
        # Use pydbus dynamic proxy which should expose RegisterAdvertisement
        try:
             # Interface might be accessed slightly differently depending on pydbus version/system
             # But usually accessing the object allows calling methods.
             # We need to ensure we call it on the right interface.
             # adapter object should have 'RegisterAdvertisement' if it has the interface.
             lem = self.bus.get(BLUEZ_SERVICE_NAME, ADAPTER_PATH)['org.bluez.LEAdvertisingManager1']
             lem.RegisterAdvertisement(self.path, {})
             print('Advertisement registered.')
        except Exception as e:
            print(f'Failed to register advertisement: {e}')
            self.publication.unpublish()

    def unregister(self):
         try:
             lem = self.bus.get(BLUEZ_SERVICE_NAME, ADAPTER_PATH)['org.bluez.LEAdvertisingManager1']
             lem.UnregisterAdvertisement(self.path)
             if hasattr(self, 'publication'):
                 self.publication.unpublish()
             print('Advertisement unregistered.')
         except Exception as e:
             print(f"Error unregistering advertisement: {e}")


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
                    'UUID': service.UUID,
                    'Primary': service.Primary
                }
            }
            for chrc in service.characteristics:
                response[chrc.get_path()] = {
                    GATT_CHRC_IFACE: {
                        'UUID': chrc.UUID,
                        'Service': chrc.Service,
                        'Flags': chrc.Flags
                    }
                }
        return response

    def register(self):
        # Register App with GATT Manager
        gatt_manager = self.bus.get(BLUEZ_SERVICE_NAME, ADAPTER_PATH)['org.bluez.GattManager1']
        
        # Publish Object Manager (Application)
        self.publication = self.bus.publish(self.path, self)
        
        # Also publish all services and characteristics?
        # Standard BlueZ GattManager1.RegisterApplication uses ObjectManager on the app path
        # to retrieve everything. So we usually only need to publish the app (Root) if it implements ObjectManager.
        # However, pydbus might need us to explicitely publish the children objects too if we want them to be accessible via DBus 
        # for other purposes, but the GetManagedObjects return is what matters for registration.
        # Wait, if BlueZ calls methods on Characteristics (like WriteValue), those objects need to be addressable on DBus!
        # So yes, we must publish services and characteristics.
        
        for service in self.services:
            self.bus.publish(service.get_path(), service)
            for chrc in service.characteristics:
                self.bus.publish(chrc.get_path(), chrc)
                
        print('Registering GATT Application...')
        gatt_manager.RegisterApplication(self.path, {})
        print('GATT Application registered.')

    def run(self):
        loop = GLib.MainLoop()
        try:
            loop.run()
        except KeyboardInterrupt:
            loop.quit()
