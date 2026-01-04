import sys
from pydbus import SystemBus
from gi.repository import GLib

AGENT_IFACE = 'org.bluez.Agent1'
AGENT_PATH = '/org/bluez/sic_agent'

class BLEAgent(object):
    """
    Implementação do Agente BlueZ (Agent1) para lidar com solicitações de pareamento/segurança.
    Configurado como 'NoInputNoOutput' para facilitar o pareamento 'Just Works'.
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
        print("[Agent] Release")

    def RequestPinCode(self, device):
        print(f"[Agent] RequestPinCode {device}")
        return "0000"

    def DisplayPinCode(self, device, pincode):
        print(f"[Agent] DisplayPinCode {device} {pincode}")

    def RequestPasskey(self, device):
        print(f"[Agent] RequestPasskey {device}")
        return 0

    def DisplayPasskey(self, device, passkey, entered):
        pass

    def RequestConfirmation(self, device, passkey):
        print(f"[Agent] RequestConfirmation {device} {passkey}")
        # Auto-aceitar para 'Just Works'
        return

    def RequestAuthorization(self, device):
        print(f"[Agent] RequestAuthorization {device}")
        return

    def AuthorizeService(self, device, uuid):
        return

    def Cancel(self):
        print("[Agent] Cancel")

    def register(self):
        """Registra o objeto Agent no D-Bus e no BlueZ AgentManager."""
        try:
            self.bus.register_object(self.path, self, self.dbus)
            
            manager = self.bus.get('org.bluez', '/org/bluez')['org.bluez.AgentManager1']
            
            print(f"[Agent] Registrando Agente em {self.path}")
            manager.RegisterAgent(self.path, "NoInputNoOutput")
            
            print("[Agent] Solicitando Agente Padrão")
            manager.RequestDefaultAgent(self.path)
            
            print("[Agent] Agente registrado com sucesso")
        except Exception as e:
            print(f"[!] Falha no registro do Agente: {e}")
