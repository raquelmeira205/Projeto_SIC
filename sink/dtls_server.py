import os
from enum import Enum
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from common.dtls_structs import DtlsRecord, DtlsHandshakeMessage, DtlsHandshakeType, ContentType
from common.dtls_utils import derive_key_material
from common.packet_structs import PacketHeader, MsgType


class DtlsServerSession:
    """
    Sessão DTLS do lado do Servidor (Sink).
    Gerencia o handshake, chaves de sessão e criptografia/descriptografia.
    """

    def __init__(self, client_nid, sink_nid, cert_path, key_path):
        """
        Inicializa a sessão DTLS do servidor.
        
        :param client_nid: NID do cliente.
        :param sink_nid: NID do Sink.
        :param cert_path: Caminho do certificado do Sink.
        :param key_path: Caminho da chave privada do Sink.
        """
        self.client_nid = client_nid
        self.sink_nid = sink_nid
        
        with open(key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            
        self.server_private_ecdh = ec.generate_private_key(ec.SECP256R1())
        self.server_public_ecdh = self.server_private_ecdh.public_key()
        
        self.server_random = os.urandom(32)
        self.client_random = None
        
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
        self.established = False

    def handle_client_hello(self, hs_payload, full_hs_msg):
        """
        Processa o ClientHello e gera o ServerHello.
        
        :param hs_payload: Payload do handshake (ClientRandom).
        :param full_hs_msg: Mensagem completa para o transcript hash.
        :return: Registro DTLS contendo o ServerHello.
        """
        self.handshake_messages += full_hs_msg
        
        self.client_random = hs_payload
        
        pub_pem = self.server_public_ecdh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        payload = self.server_random + pub_pem
        
        sh_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.SERVER_HELLO, 0, payload)
        self.handshake_messages += sh_msg
        
        record = DtlsRecord.pack(ContentType.HANDSHAKE, 0, 0, sh_msg)
        return record

    def handle_client_key_exchange(self, hs_payload, full_hs_msg):
        """
        Processa o ClientKeyExchange, deriva o segredo partilhado e as chaves de sessão.
        
        :param hs_payload: Chave pública do cliente (PEM).
        :param full_hs_msg: Mensagem completa para o transcript hash.
        """
        self.handshake_messages += full_hs_msg
        
        client_pub_pem = hs_payload
        client_public_ecdh = serialization.load_pem_public_key(client_pub_pem)
        
        shared_key = self.server_private_ecdh.exchange(ec.ECDH(), client_public_ecdh)
        
        mck_hkdf = hashes.Hash(hashes.SHA256())
        mck_hkdf.update(shared_key)
        mck_hkdf.update(self.client_random)
        mck_hkdf.update(self.server_random)
        self.master_secret = mck_hkdf.finalize()
        
        ck, sk, civ, siv = derive_key_material(self.master_secret, self.server_random, self.client_random)
        self.read_key = ck
        self.write_key = sk
        self.read_iv = civ
        self.write_iv = siv
        
        self.epoch_write = 1
        self.seq_write = 0

    def handle_finished_and_reply(self, hs_payload, full_hs_msg):
        """
        Verifica o Finished do cliente e responde com o Finished do servidor.
        Estabelece a sessão.
        
        :param hs_payload: Payload do Finished do cliente.
        :param full_hs_msg: Mensagem completa (decifrada).
        :return: Registro DTLS cifrado contendo o Finished do servidor.
        """
        self.handshake_messages += full_hs_msg
        
        verify_data = hmac.HMAC(self.master_secret, hashes.SHA256())
        verify_data.update(self.handshake_messages)
        fin_payload = verify_data.finalize()
        
        fin_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.FINISHED, 1, fin_payload)
        self.handshake_messages += fin_msg
        
        encrypted_record = self.encrypt(fin_msg, ContentType.HANDSHAKE)
        
        self.established = True
        self.epoch_read = 1
        self.seq_read = 0
        
        return encrypted_record

    def encrypt(self, payload, content_type=ContentType.APPLICATION_DATA):
        """
        Cifra um payload para envio.
        
        :param payload: Dados a cifrar.
        :param content_type: Tipo de conteúdo DTLS.
        :return: Registro DTLS empacotado.
        """
        nonce = self.write_iv + self.seq_write.to_bytes(8, 'big')
        aesgcm = AESGCM(self.write_key)
        ciphertext = aesgcm.encrypt(nonce, payload, b"")
        record = DtlsRecord.pack(content_type, self.epoch_write, self.seq_write, ciphertext)
        self.seq_write += 1
        return record

    def decrypt(self, record_bytes):
        """
        Decifra um registro recebido.
        
        :param record_bytes: Bytes do registro cifrado.
        :return: Tupla (ContentType, Plaintext).
        """
        c_type, epoch, seq, payload = DtlsRecord.unpack(record_bytes)
        
        if epoch == 0:
            return c_type, payload
            
        nonce = self.read_iv + seq.to_bytes(8, 'big')
        aesgcm = AESGCM(self.read_key)
        
        plaintext = aesgcm.decrypt(nonce, payload, b"")
        return c_type, plaintext


class DtlsServerManager:
    """
    Gerenciador de sessões DTLS no Sink.
    Mantém o estado de todos os clientes conectados.
    """
    
    def __init__(self, my_nid, cert_path, key_path, ca_cert_path):
        """
        Inicializa o gerenciador.
        """
        self.my_nid = my_nid
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        
        self.sessions = {} # client_nid -> DtlsServerSession

    def get_or_create_session(self, client_nid):
        """Retorna uma sessão existente ou cria uma nova para o NID especificado."""
        if client_nid not in self.sessions:
            self.sessions[client_nid] = DtlsServerSession(client_nid, self.my_nid, self.cert_path, self.key_path)
        return self.sessions[client_nid]
        
    def get_session(self, client_nid):
        """Retorna a sessão para o cliente, se existir."""
        return self.sessions.get(client_nid)

    def remove_session(self, client_nid):
        """Remove a sessão do cliente."""
        if client_nid in self.sessions:
            del self.sessions[client_nid]
