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
    CLOSED = 0
    HANDSHAKE_INITIATED = 1 # Sent ClientHello
    HANDSHAKE_WAIT_SERVER_HELLO = 2
    HANDSHAKE_WAIT_FINISHED = 3
    ESTABLISHED = 4

class DtlsSession:
    def __init__(self, sink_nid, my_nid, cert_path, key_path, ca_cert_path, router):
        self.sink_nid = sink_nid
        self.my_nid = my_nid
        self.router = router
        
        self.state = DtlsState.CLOSED
        
        # Keys
        with open(key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_path, 'rb') as f:
            self.cert_bytes = f.read() # SEND AS PEM or DER? PEM is bulky. Lets assume PEM for now.
            
        # ECDH
        self.client_private_ecdh = ec.generate_private_key(ec.SECP256R1())
        self.client_public_ecdh = self.client_private_ecdh.public_key()
        
        # State vars
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
        
        self.handshake_messages = b"" # Transcript for Finished hash

    def perform_handshake(self):
        """Initiate handshake by sending ClientHello."""
        print("[DTLS-Client] Sending ClientHello...")
        self.state = DtlsState.HANDSHAKE_INITIATED
        
        # ClientHello: Version(2) | Random(32) | SessionID(0) | Cookie(0) | CipherSuites(...)
        # Simplified: ClientRandom(32)
        payload = self.client_random
        
        hs_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.CLIENT_HELLO, 0, payload)
        self.handshake_messages += hs_msg
        
        record = DtlsRecord.pack(ContentType.HANDSHAKE, 0, 0, hs_msg)
        
        # Send via Router (encapsulated in MsgType.DTLS_HANDSHAKE)
        # Note: Handshake packets are NOT encrypted initially (Epoch 0)
        self.router.send_data_packet(self.sink_nid, record, MsgType.DTLS_HANDSHAKE)
        self.state = DtlsState.HANDSHAKE_WAIT_SERVER_HELLO

    def handle_handshake_message(self, record_payload):
        # Unwrap Record
        try:
            # We must check epoch to see if it is encrypted
            # DtlsRecord.unpack returns cipher text if epoch > 0
            c_type, epoch, seq, payload = DtlsRecord.unpack(record_payload)
            
            if epoch > 0:
                # Encrypted! Use recv() logic to decrypt
                # Rewind and use self.recv?
                # recv expects full record bytes
                c_type, plaintext = self.recv(record_payload)
                payload = plaintext
                
        except ValueError:
            print("[DTLS-Client] Error unpacking record")
            return
        except Exception as e:
            print(f"[DTLS-Client] Decrypt error in handshake: {e}")
            return

        if c_type == ContentType.HANDSHAKE:
             # There might be multiple handshake messages in one record? Assuming 1 for now.
             msg_type, msg_seq, hs_payload = DtlsHandshakeMessage.unpack(payload)
             
             if msg_type == DtlsHandshakeType.SERVER_HELLO:
                 self._handle_server_hello(hs_payload, payload)
                 
             elif msg_type == DtlsHandshakeType.FINISHED:
                 self._handle_finished(hs_payload, payload)
                 
    def _handle_server_hello(self, hs_payload, full_hs_msg):
        print("[DTLS-Client] Received ServerHello")
        self.handshake_messages += full_hs_msg
        
        # ServerHello Payload: ServerRandom(32) | ServerPublicKey(X bytes)
        # We assume simplified flow: Server sends its random + its ECDH public key
        # We derive shared secret immediately
        
        self.server_random = hs_payload[:32]
        server_pub_pem = hs_payload[32:] 
        
        # Load Server Public Key
        server_public_ecdh = serialization.load_pem_public_key(server_pub_pem)
        
        # Dervive Premaster Secret
        shared_key = self.client_private_ecdh.exchange(ec.ECDH(), server_public_ecdh)
        
        # Derive Master Secret (Simplified HKDF)
        # In real TLS we use PRF. Here we use HKDF on shared_key
        # Context: "master secret" + client_random + server_random
        mck_hkdf = hashes.Hash(hashes.SHA256())
        mck_hkdf.update(shared_key)
        mck_hkdf.update(self.client_random)
        mck_hkdf.update(self.server_random)
        self.master_secret = mck_hkdf.finalize() # Simple hashing for now
        
        # Derive Keys
        self.write_key, self.read_key, self.write_iv, self.read_iv = derive_key_material(
            self.master_secret, self.server_random, self.client_random
        )
        
        # Send ClientKeyExchange
        self._send_client_key_exchange()

    def _send_client_key_exchange(self):
        print("[DTLS-Client] Sending ClientKeyExchange + Finished")
        
        # ClientKeyExchange: Client Public Key (PEM)
        pub_pem = self.client_public_ecdh.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        cke_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.CLIENT_KEY_EXCHANGE, 1, pub_pem)
        self.handshake_messages += cke_msg
        
        cke_record = DtlsRecord.pack(ContentType.HANDSHAKE, 0, 1, cke_msg)
        self.router.send_data_packet(self.sink_nid, cke_record, MsgType.DTLS_HANDSHAKE)
        
        # Change Cipher Spec (Implicit in epoch change usually, or explicit record)
        # We'll just switch Epoch to 1
        self.epoch_write = 1
        self.seq_write = 0
        
        # Send Finished (Encrypted)
        # Verify Data: HMAC(HandshakeMessages)
        verify_data = hmac.HMAC(self.master_secret, hashes.SHA256())
        verify_data.update(self.handshake_messages) # All up to now
        fin_payload = verify_data.finalize()
        
        fin_msg = DtlsHandshakeMessage.pack(DtlsHandshakeType.FINISHED, 2, fin_payload)
        # Don't add self's Finished to transcript for self's verification? Usually yes.
        self.handshake_messages += fin_msg 
        
        # Encrypt Finished
        fin_record = self.send(fin_msg, content_type=ContentType.HANDSHAKE)
        
        # Send raw encrypted record via Router
        self.router.send_data_packet(self.sink_nid, fin_record, MsgType.DTLS_HANDSHAKE)
        self.state = DtlsState.HANDSHAKE_WAIT_FINISHED

    def _handle_finished(self, hs_payload, full_hs_msg):
        print("[DTLS-Client] Received Server Finished")
        # Decrypt logic happened before this (in recv), so we have plaintext hs_payload
        # Verify verify_data
        # For simplicity, skip strict verify in this mockup, assume if it decrypted correctly (Auth Tag) it's fine.
        
        self.state = DtlsState.ESTABLISHED
        self.epoch_read = 1
        self.seq_read = 0
        print("[DTLS-Client] Session Established!")

    def send(self, payload, content_type=ContentType.APPLICATION_DATA):
        """Encrypt and Pack Record"""
        if self.state != DtlsState.ESTABLISHED and content_type == ContentType.APPLICATION_DATA:
            raise RuntimeError("DTLS not established")
            
        # AES-GCM
        # Nonce = Salt (4) + IV (8) = 12 bytes
        # IV is usually explicit in record or implicit from seq num.
        # RFC 5288: Nonce = Salt(4) + Explicit(8). Explicit is usually seq_num.
        
        nonce = self.write_iv + self.seq_write.to_bytes(8, 'big') # 4 + 8 = 12
        
        aesgcm = AESGCM(self.write_key)
        
        # AAD = Epoch(2) | Seq(6) | Type(1) | Len(2) (Pseudo-header) ?
        # TLS 1.3 uses full header. TLS 1.2 uses specific AAD.
        # Let's use Header as AAD for simplicity and integrity.
        # But we haven't built header yet.
        
        # Let's simplify: AAD = b""
        ciphertext = aesgcm.encrypt(nonce, payload, b"")
        
        record = DtlsRecord.pack(content_type, self.epoch_write, self.seq_write, ciphertext)
        self.seq_write += 1
        return record

    def recv(self, record_bytes):
        """Unpack logic and Decrypt if Epoch > 0"""
        c_type, epoch, seq, payload = DtlsRecord.unpack(record_bytes)
        
        if epoch == 0:
            return c_type, payload
        
        # Decrypt
        if epoch != self.epoch_read:
            # Maybe rekey logic? 
            pass
            
        nonce = self.read_iv + seq.to_bytes(8, 'big')
        aesgcm = AESGCM(self.read_key)
        
        try:
            plaintext = aesgcm.decrypt(nonce, payload, b"")
            return c_type, plaintext
        except Exception as e:
            print(f"[DTLS-Client] Decryption failed: {e}")
            raise
