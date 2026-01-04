import sys
import os
import threading
import time
import argparse
from gi.repository import GLib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from common.bluez_classes import Application, Service, Characteristic
from common.ble_utils import BUS, SIC_SERVICE_UUID, SIC_RX_CHAR_UUID
from common.pki_utils import read_nid_from_cert
from common.ble_handshake_transport import handshake_receive_queue
from common.ble_agent import BLEAgent
from node.ble_manager import BLEManager
from common.packet_structs import PacketHeader
from node.router import Router
from node.cli_ui import NodeCLI
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class RealSecurity:
    """Módulo de segurança real que verifica assinaturas do Sink."""
    
    def __init__(self, sink_cert_path):
        """
        Carrega o certificado do Sink para verificação de assinaturas.
        
        :param sink_cert_path: Caminho para o certificado do Sink.
        """
        with open(sink_cert_path, 'rb') as f:
            self.sink_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        self.sink_public_key = self.sink_cert.public_key()
    
    def verify_sink_signature(self, data, signature):
        """
        Verifica a assinatura do Sink usando sua chave pública.
        
        :param data: Dados assinados.
        :param signature: Assinatura a verificar.
        :return: True se a assinatura for válida, False caso contrário.
        """
        try:
            self.sink_public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA512())
            )
            return True
        except Exception as e:
            print(f"[!] Verificação de assinatura falhou: {e}")
            return False

    def update_sink_cert(self, new_cert):
        """
        Atualiza o certificado do Sink confiável dinamicamente (ex: renovação).
        
        :param new_cert: Novo certificado X.509 do Sink.
        """
        self.sink_cert = new_cert
        self.sink_public_key = new_cert.public_key()
        print("[Security] Certificado do Sink atualizado.")


class RxCharacteristic(Characteristic):
    """
    Característica GATT de Recepção (Rx).
    Responsável por receber dados de outros nós, detectar handshakes de segurança
    e encaminhar pacotes para o Router.
    """
    
    def __init__(self, bus, index, service, router):
        super().__init__(bus, index, SIC_RX_CHAR_UUID, ['write', 'write-without-response'], service)
        self.router = router

    def WriteValue(self, value, options):
        """
        Callback chamado quando um dispositivo remoto escreve nesta característica.
        
        :param value: Valor escrito (bytes).
        :param options: Opções de escrita (inclui caminho do dispositivo).
        """
        data = bytes(value)
        mac = "unknown"

        device_path = options.get("device")
        if device_path and "dev_" in device_path:
            mac = device_path.split("dev_")[1].replace("_", ":")

        # Verifica se é dado de handshake (começa com marcador 0xFF)
        if len(data) >= 7 and data[0] == 0xFF:
            try:
                total_length = int.from_bytes(data[1:5], 'big')
                chunk_index = int.from_bytes(data[5:7], 'big')
                chunk_data = data[7:]
                
                # Se for o primeiro chunk de um MAC desconhecido, aciona o handshake de entrada
                if (chunk_index == 0 and 
                    mac not in self.router.link_keys and 
                    not handshake_receive_queue.has_transport(mac)):
                    self.router.handle_incoming_handshake(mac)
                    import time
                    time.sleep(0.1)
                
                if handshake_receive_queue.route_chunk(mac, total_length, chunk_index, chunk_data):
                    return
                else:
                    return
                    
            except Exception:
                pass  # Processar como dado normal se falhar parse

        try:
            src, dest, msg_type, payload, seq, mac_sig = PacketHeader.unpack(data)
            packet_changed = False

            if payload is None:
                payload = b''
                packet_changed = True
            elif isinstance(payload, str):
                payload = payload.encode('utf-8')
                packet_changed = True
            
            if packet_changed:
                data = PacketHeader.pack(src, dest, msg_type, payload, seq, mac_sig)
        except Exception:
            pass
            
        self.router.process_incoming_packet(data, mac)


class NodeApplication(Application):
    """
    Camada de Aplicação BLE (GATT Server).
    Define os serviços e características oferecidos pelo nó.
    """
    
    def __init__(self, bus, router):
        super().__init__(bus)
        service = Service(bus, 0, SIC_SERVICE_UUID, True)
        self.add_service(service)

        char = RxCharacteristic(bus, 0, service, router)
        service.add_characteristic(char)
        
        self.router = router

    def receive(self, src_nid, payload):
        """
        Callback para receber mensagens da camada de aplicação.
        
        :param src_nid: NID da origem.
        :param payload: Conteúdo da mensagem.
        """
        print(f"[App] Recebido de {src_nid.hex()}: {payload}")
        try:
            msg_text = payload.decode('utf-8')
        except:
             msg_text = payload.hex()
             
        self.router.stats["received_messages"].append((src_nid.hex(), msg_text))


class Node:
    """
    Classe principal que representa um Nó IoT.
    Coordena o BLE Manager, Router, Segurança e CLI.
    """
    
    def __init__(self, nid, cert_path, key_path, ca_cert_path, sink_cert_path):
        """
        Inicializa o Nó.
        
        :param nid: Network ID do nó.
        :param cert_path: Caminho do certificado.
        :param key_path: Caminho da chave privada.
        :param ca_cert_path: Caminho do certificado da CA.
        :param sink_cert_path: Caminho do certificado do Sink.
        """
        print(f"[*] Node iniciado: {nid.hex()}")

        self.node_nid = nid  

        self.ble_manager = BLEManager(nid)
        self.security = RealSecurity(sink_cert_path)
        self.router = Router(
            nid, 
            self.security, 
            self.ble_manager,
            cert_path=cert_path,
            key_path=key_path,
            ca_cert_path=ca_cert_path
        )

        self.ble_manager.set_router_callbacks(
            self.router.set_uplink,
            self.router.handle_disconnection
        )

        self.app = NodeApplication(BUS, self.router)
        self.router.app_layer = self.app
        self.app.register()

        self.agent = BLEAgent(BUS)
        self.agent.register()

        time.sleep(0.5)
        self.ble_manager.start_advertising()

        self.running = True

    def start_logic_loop(self):
        """Inicia o loop lógico em uma thread separada."""
        t = threading.Thread(target=self._logic_loop, daemon=True)
        t.start()

    def _logic_loop(self):
        """Loop principal de lógica de conexão (monitoramento)."""
        time.sleep(2)
        while self.running:
            self.ble_manager.monitor_connection_status()
            time.sleep(10)
    
    def scan_for_uplinks(self):
        """
        Aciona manualmente a varredura por uplinks.
        
        :return: Resultados da varredura.
        """
        return self.ble_manager.scan_for_devices()

    def send_to_sink(self, text):
        """
        Envia uma mensagem de texto para o Sink.
        
        :param text: Texto a enviar.
        :return: True se enviado (enfileirado), False caso contrário.
        """
        if not self.router.sink_nid:
            print("[!] Sink NID desconhecido")
            return False
            
        return self.router.send_app_data(self.router.sink_nid, text.encode('utf-8'))

    def force_connect(self, mac):
        """
        Força uma conexão manual a um dispositivo específico.
        
        :param mac: Endereço MAC do dispositivo.
        :return: True se conectado, False caso contrário.
        """
        
        curr = self.ble_manager.uplink_addr
        if curr:
             self.ble_manager.disconnect_from_device(curr)
        
        if self.ble_manager.connect_to_device(mac):
             
             self.ble_manager.uplink_addr = mac
             self.ble_manager.uplink_nid = b'\x00'*16 
             self.ble_manager.hop_count = 255
             self.ble_manager.update_advertisement()
             
             self.router.set_uplink(mac, 254)
             
             return True
        else:
             return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", default="certs/nodeA.crt", help="Node certificate path")
    parser.add_argument("--key", default="certs/nodeA.key", help="Node private key path")
    parser.add_argument("--ca", default="certs/ca.crt", help="CA certificate path")
    parser.add_argument("--sink-cert", default="certs/sink.crt", help="Sink certificate path")
    args = parser.parse_args()

    nid = read_nid_from_cert(args.cert)
    if not nid:
        sys.exit(1)
    
    for path in [args.cert, args.key, args.ca, args.sink_cert]:
        if not os.path.exists(path):
            print(f"[!] File not found: {path}")
            sys.exit(1)

    loop = GLib.MainLoop()
    threading.Thread(target=loop.run, daemon=True).start()

    node = Node(nid, args.cert, args.key, args.ca, args.sink_cert)
    node.start_logic_loop()

    cli = NodeCLI(node)
    
    try:
        cli.start()
    finally:
        node.running = False
        loop.quit()


if __name__ == "__main__":
    main()
