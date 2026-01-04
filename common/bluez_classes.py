import sys
from pydbus import SystemBus
from gi.repository import GLib
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
    Abstração D-Bus para Advertisement LEAdvertisement1 do BlueZ.
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
        
        self._discoverable = None
        self._discoverable_timeout = None

        self.registration = None
    
    def set_discoverable(self, discoverable=True, timeout=0):
        """Habilita o modo descobrível (útil para o Sink)."""
        self._discoverable = discoverable
        self._discoverable_timeout = timeout

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
        includes = []
        if self.include_tx_power:
            includes.append("tx-power")
        return includes
    
    @property
    def Discoverable(self):
        return self._discoverable if self._discoverable is not None else False
    
    @property
    def DiscoverableTimeout(self):
        return self._discoverable_timeout if self._discoverable_timeout is not None else 0

    def Release(self):
        print(f"{self.path}: Liberado pelo BlueZ")

    def register(self, adapter_path):
        """Registra o advertisement no BlueZ Manager."""
        props = self.bus.get(BLUEZ_SERVICE_NAME, adapter_path)['org.freedesktop.DBus.Properties']
        props.Set('org.bluez.Adapter1', 'Powered', GLib.Variant('b', True))

        self.registration = self.bus.register_object(
            self.path,
            self,
            self.dbus
        )

        print(f"Registrando advertisement em {self.path}")
        lem = self.bus.get(BLUEZ_SERVICE_NAME, adapter_path)['org.bluez.LEAdvertisingManager1']
        lem.RegisterAdvertisement(self.path, {})

        print("Advertisement registrado")

    def unregister(self, adapter_path):
        try:
            lem = self.bus.get(BLUEZ_SERVICE_NAME, adapter_path)['org.bluez.LEAdvertisingManager1']
            lem.UnregisterAdvertisement(self.path)
        finally:
            if self.registration:
                self.registration.unregister()
                self.registration = None
            print("Advertisement cancelado")


class Service(object):
    """
    Abstração D-Bus para Serviço GATT.
    """
    dbus = f"""
    <node>
        <interface name="{GATT_SERVICE_IFACE}">
            <property name="UUID" type="s" access="read"/>
            <property name="Primary" type="b" access="read"/>
            <property name="Characteristics" type="ao" access="read"/>
        </interface>
    </node>
    """

    def __init__(self, bus, index, uuid, primary):
        self.path = '/org/bluez/sic_node_app/service' + str(index)
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
        
    @property
    def Characteristics(self):
        return [c.get_path() for c in self.characteristics]


class Characteristic(object):
    """
    Abstração D-Bus para Característica GATT.
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
            <property name="Descriptors" type="ao" access="read"/>
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
        return self.value

    def WriteValue(self, value, options):
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
    Gerenciador de Aplicação GATT.
    Exporta a interface ObjectManager para o BlueZ descobrir serviços/características.
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
        self.path = '/org/bluez/sic_node_app'
        self.bus = bus
        self.services = []

    def get_path(self):
        return self.path

    def add_service(self, service):
        self.services.append(service)

    def GetManagedObjects(self):
        # print(f"DEBUG: GetManagedObjects called on {self.path}")
        response = {}
        for service in self.services:
            service_props = {
                'UUID': GLib.Variant('s', service.UUID),
                'Primary': GLib.Variant('b', service.Primary),
                'Characteristics': GLib.Variant('ao', [c.get_path() for c in service.characteristics])
            }
            response[service.get_path()] = {
                GATT_SERVICE_IFACE: service_props
            }
            
            for chrc in service.characteristics:
                chrc_props = {
                    'UUID': GLib.Variant('s', chrc.UUID),
                    'Service': GLib.Variant('o', chrc.Service),
                    'Flags': GLib.Variant('as', chrc.Flags),
                    'Descriptors': GLib.Variant('ao', []) 
                }
                response[chrc.get_path()] = {
                    GATT_CHRC_IFACE: chrc_props
                }
        return response

    def register(self):
        """Registra a Aplicação GATT no BlueZ."""
        gatt_manager = self.bus.get(BLUEZ_SERVICE_NAME, ADAPTER_PATH)['org.bluez.GattManager1']
        
        self.registration = self.bus.register_object(self.path, self, self.dbus)
        
        for service in self.services:
            self.bus.register_object(service.get_path(), service, service.dbus)
            for chrc in service.characteristics:
                self.bus.register_object(chrc.get_path(), chrc, chrc.dbus)
                
        print('Registrando Aplicação GATT...')
        gatt_manager.RegisterApplication(self.path, {})
        print('Aplicação GATT registrada.')

    def run(self):
        loop = GLib.MainLoop()
        try:
            loop.run()
        except KeyboardInterrupt:
            loop.quit()
