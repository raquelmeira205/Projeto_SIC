import os
import time
from enum import Enum
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from common.dtls_structs import DtlsRecord, DtlsHandshakeMessage, DtlsHandshakeType, ContentType
from common.dtls_utils import derive_key_material
from common.packet_structs import PacketHeader, MsgType


class DtlsState(Enum):
    """Estados da máquina de estados do DTLS."""
    CLOSED = 0
    HANDSHAKE_INITIATED = 1
    HANDSHAKE_WAIT_SERVER_HELLO = 2
    HANDSHAKE_WAIT_FINISHED = 3
    ESTABLISHED = 4


class DtlsSession:
    """
    Gerencia uma sessão DTLS Simplificada (Client-side).
    Realiza o handshake, derivação de chaves e cifragem/decifragem de registros.
    """

    def __init__(self, sink_nid, my_nid, cert_path, key_path, ca_cert_path, router):
        """
        Inicializa a sessão DTLS.

        :param sink_nid: NID do Sink (Servidor).
        :param my_nid: NID do próprio nó.
        :param cert_path: Caminho para o certificado do nó.
        :param key_path: Caminho para a chave privada do nó.
        :param ca_cert_path: Caminho para o certificado da CA.
        :param router: Referência para o roteador (para envio de pacotes).
        """
        self.sink_nid = sink_nid
        self.my_nid = my_nid
        self.router = router
        
        self.state = DtlsState.CLOSED
        
        with open(key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_path, 'rb') as f:
            self.cert_bytes = f.read()
            
        self.client_private_ecdh = ec.generate_private_key(ec.SECP256R1())
        self.client_public_ecdh = self.client_private_ecdh.public_key()
        
        self.client_random = os.urandom(32)
        self.server_random = None
        
        self.master_secret = None
        self.read_key = None
        self.write_key = None
        self.read_iv = None
        self.write_iv = None
        
        self.epoch_read = 0
        self.epoch_write = 0
        self.seq_read = 0
        self.seq_write = 0
        
        self.handshake_messages = b""

    def perform_handshake(self):
        """
        Inicia o handshake DTLS enviando o ClientHello.
        """
        self.state = DtlsState.HANDSHAKE_INITIATED
        
        payload = self.client_random
        
        hs_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.CLIENT_HELLO, 0, payload)
        self.handshake_messages += hs_msg
        
        record = DtlsRecord.pack(ContentType.HANDSHAKE, 0, 0, hs_msg)
        
        self.router.send_data_packet(self.sink_nid, record, MsgType.DTLS_HANDSHAKE)
        self.state = DtlsState.HANDSHAKE_WAIT_SERVER_HELLO

    def handle_handshake_message(self, record_payload):
        """
        Processa mensagens de handshake recebidas.
        Desempacota o registro, decifra se necessário e despacha para o tratador específico.

        :param record_payload: Payload do registro DTLS recebido.
        """
        try:
            c_type, epoch, seq, payload = DtlsRecord.unpack(record_payload)
            
            if epoch > 0:
                c_type, plaintext = self.recv(record_payload)
                payload = plaintext
                
        except ValueError:
            return
        except Exception as e:
            print(f"[!] Erro decifragem handshake: {e}")
            return

        if c_type == ContentType.HANDSHAKE:
             msg_type, msg_seq, hs_payload = DtlsHandshakeMessage.unpack(payload)
             
             if msg_type == DtlsHandshakeType.SERVER_HELLO:
                 self._handle_server_hello(hs_payload, payload)
                 
             elif msg_type == DtlsHandshakeType.FINISHED:
                 self._handle_finished(hs_payload, payload)
                 
    def _handle_server_hello(self, hs_payload, full_hs_msg):
        """
        Processa o ServerHello, deriva o segredo mestre e envia ClientKeyExchange + Finished.
        """
        self.handshake_messages += full_hs_msg
        
        self.server_random = hs_payload[:32]
        server_pub_pem = hs_payload[32:] 
        
        server_public_ecdh = serialization.load_pem_public_key(server_pub_pem)
        
        shared_key = self.client_private_ecdh.exchange(ec.ECDH(), server_public_ecdh)
        
        mck_hkdf = hashes.Hash(hashes.SHA256())
        mck_hkdf.update(shared_key)
        mck_hkdf.update(self.client_random)
        mck_hkdf.update(self.server_random)
        self.master_secret = mck_hkdf.finalize()
        
        self.write_key, self.read_key, self.write_iv, self.read_iv = derive_key_material(
            self.master_secret, self.server_random, self.client_random
        )
        
        self._send_client_key_exchange()

    def _send_client_key_exchange(self):
        """
        Envia a mensagem ClientKeyExchange e a mensagem Finished (cifrada).
        """
        pub_pem = self.client_public_ecdh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        cke_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.CLIENT_KEY_EXCHANGE, 1, pub_pem)
        self.handshake_messages += cke_msg
        
        cke_record = DtlsRecord.pack(ContentType.HANDSHAKE, 0, 1, cke_msg)
        self.router.send_data_packet(self.sink_nid, cke_record, MsgType.DTLS_HANDSHAKE)
        
        self.epoch_write = 1
        self.seq_write = 0
        
        verify_data = hmac.HMAC(self.master_secret, hashes.SHA256())
        verify_data.update(self.handshake_messages)
        fin_payload = verify_data.finalize()
        
        fin_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.FINISHED, 2, fin_payload)
        self.handshake_messages += fin_msg 
        
        fin_record = self.send(fin_msg, content_type=ContentType.HANDSHAKE)
        
        self.router.send_data_packet(self.sink_nid, fin_record, MsgType.DTLS_HANDSHAKE)
        self.state = DtlsState.HANDSHAKE_WAIT_FINISHED

    def _handle_finished(self, hs_payload, full_hs_msg):
        """
        Processa a mensagem Finished do servidor e estabelece a sessão.
        """
        self.state = DtlsState.ESTABLISHED
        self.epoch_read = 1
        self.seq_read = 0

    def send(self, payload, content_type=ContentType.APPLICATION_DATA):
        """
        Empacota e cifra um payload (AES-GCM) em um registro DTLS.

        :param payload: Dados a serem enviados.
        :param content_type: Tipo de conteúdo (Application Data ou Handshake).
        :return: Registro DTLS empacotado (bytes).
        """
        if self.state != DtlsState.ESTABLISHED and content_type == ContentType.APPLICATION_DATA:
            raise RuntimeError("DTLS não estabelecido")
            
        nonce = self.write_iv + self.seq_write.to_bytes(8, 'big')
        
        aesgcm = AESGCM(self.write_key)
        
        ciphertext = aesgcm.encrypt(nonce, payload, b"")
        
        record = DtlsRecord.pack(content_type, self.epoch_write, self.seq_write, ciphertext)
        self.seq_write += 1
        return record

    def recv(self, record_bytes):
        """
        Desempacota e decifra um registro DTLS.

        :param record_bytes: Bytes do registro recebido.
        :return: Tupla (ContentType, Plaintext/Payload).
        """
        c_type, epoch, seq, payload = DtlsRecord.unpack(record_bytes)
        
        if epoch == 0:
            return c_type, payload
        
        if epoch != self.epoch_read:
            pass
            
        nonce = self.read_iv + seq.to_bytes(8, 'big')
        aesgcm = AESGCM(self.read_key)
        
        try:
            plaintext = aesgcm.decrypt(nonce, payload, b"")
            return c_type, plaintext
        except Exception as e:
            print(f"[!] Falha decifragem DTLS: {e}")
            raise
