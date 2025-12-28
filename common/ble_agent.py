import sys
from pydbus import SystemBus
from gi.repository import GLib

AGENT_IFACE = 'org.bluez.Agent1'
AGENT_PATH = '/org/bluez/sic_agent'

class BLEAgent(object):
    """
    BlueZ Agent1 implementation for handling pairing/security requests.
    Configured for NoInputNoOutput to facilitate 'Just Works' pairing.
    """
    dbus = f"""
    <node>
        <interface name="{AGENT_IFACE}">
            <method name="Release"/>
            <method name="RequestPinCode">
                <arg name="device" type="o" direction="in"/>
                <arg name="pincode" type="s" direction="out"/>
            </method>
            <method name="DisplayPinCode">
                <arg name="device" type="o" direction="in"/>
                <arg name="pincode" type="s" direction="in"/>
            </method>
            <method name="RequestPasskey">
                <arg name="device" type="o" direction="in"/>
                <arg name="passkey" type="u" direction="out"/>
            </method>
            <method name="DisplayPasskey">
                <arg name="device" type="o" direction="in"/>
                <arg name="passkey" type="u" direction="in"/>
                <arg name="entered" type="q" direction="in"/>
            </method>
            <method name="RequestConfirmation">
                <arg name="device" type="o" direction="in"/>
                <arg name="passkey" type="u" direction="in"/>
            </method>
            <method name="RequestAuthorization">
                <arg name="device" type="o" direction="in"/>
            </method>
            <method name="AuthorizeService">
                <arg name="device" type="o" direction="in"/>
                <arg name="uuid" type="s" direction="in"/>
            </method>
            <method name="Cancel"/>
        </interface>
    </node>
    """

    def __init__(self, bus):
        self.bus = bus
        self.path = AGENT_PATH

    def Release(self):
        print("Agent Release")

    def RequestPinCode(self, device):
        print(f"RequestPinCode {device}")
        return "0000"

    def DisplayPinCode(self, device, pincode):
        print(f"DisplayPinCode {device} {pincode}")

    def RequestPasskey(self, device):
        print(f"RequestPasskey {device}")
        return 0

    def DisplayPasskey(self, device, passkey, entered):
        # print(f"DisplayPasskey {device} {passkey} reached={entered}")
        pass

    def RequestConfirmation(self, device, passkey):
        print(f"RequestConfirmation {device} {passkey}")
        # Auto-accept for Just Works
        return

    def RequestAuthorization(self, device):
        print(f"RequestAuthorization {device}")
        return

    def AuthorizeService(self, device, uuid):
        # print(f"AuthorizeService {device} {uuid}")
        return

    def Cancel(self):
        print("Agent Cancel")

    def register(self):
        # Register Agent Object on DBus
        self.bus.register_object(self.path, self, self.dbus)
        
        # Register with AgentManager
        manager = self.bus.get('org.bluez', '/org/bluez')['org.bluez.AgentManager1']
        manager.RegisterAgent(self.path, "NoInputNoOutput")
        manager.RequestDefaultAgent(self.path)
        print("BLE Agent registered and set as default")
