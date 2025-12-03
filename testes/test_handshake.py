import unittest
import sys
import os
from unittest.mock import MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import serialization

#Adicionar a root do projeto ao caminho (path)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#Importar a classe
from common.security_handshake import SecurityHandshake

class TestSecurityHandshake(unittest.TestCase):
    def setUp(self):
        #Calcular a localização com base na root
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.certs_dir = os.path.join(project_root, "certs")
        
        #atribuir localizações dos certificados 
        self.ca_cert = os.path.join(self.certs_dir, "ca.crt")
        self.node_a_cert = os.path.join(self.certs_dir, "nodeA.crt")
        self.node_a_key = os.path.join(self.certs_dir, "nodeA.key")
        self.node_b_cert = os.path.join(self.certs_dir, "nodeB.crt")
        self.node_b_key = os.path.join(self.certs_dir, "nodeB.key")

    def test_full_handshake(self):
        #Node A: inicializado
        handshake_a = SecurityHandshake(self.node_a_cert, self.node_a_key, self.ca_cert)
        
        #Node B: inicializado
        handshake_b = SecurityHandshake(self.node_b_cert, self.node_b_key, self.ca_cert)

        # Simulação do canal de comunicação
        class Channel:
            def __init__(self):
                #Simular canal bidirecional
                self.a_to_b = []
                self.b_to_a = []

            #Node A envia bytes armazenados numa fila
            def send_from_a(self, data):
                self.a_to_b.append(data)
            
            #Node B lê da fila
            def receive_at_b(self):
                return self.a_to_b.pop(0)
            
            #Node B envia
            def send_from_b(self, data):
                self.b_to_a.append(data)
            
            #Node A envia
            def receive_at_a(self):
                return self.b_to_a.pop(0)

        channel = Channel()         #instancia o canal
        
        #Usar MagicMock para testar sem depender da rede real
        conn_a = MagicMock()
        conn_a.send.side_effect = channel.send_from_a
        conn_a.receive.side_effect = channel.receive_at_a
        
        conn_b = MagicMock()
        conn_b.send.side_effect = channel.send_from_b
        conn_b.receive.side_effect = channel.receive_at_b

        #precisamos de executar o perform_handshake em paralelo ou intercalado.
        #Como o perform_handshake é bloqueante e sequencial, não conseguimos rodá-lo facilmente numa única thread, a menos que partimos o processo ou threads.
        #Neste teste unitário vamos executar cada passo manualmente para verificar a lógica do protocolo.
        
        ###############################################
        # --- Passo 1: Troca de Certificados ---
        #A envia o certificado
        a_cert_bytes = handshake_a.cert.public_bytes(serialization.Encoding.PEM)
        channel.send_from_a(a_cert_bytes)
        
        #B recebe o certificado de A
        #No código real, exchange_certificates faz: enviar e depois receber.
        #Aqui estamos a simular isso manualmente.
        
        #B recebe o certificado de A
        b_received_cert = channel.receive_at_b()
        handshake_b.peer_cert = x509.load_pem_x509_certificate(b_received_cert)
        
        #B envia o certificado dele
        b_cert_bytes = handshake_b.cert.public_bytes(serialization.Encoding.PEM)
        channel.send_from_b(b_cert_bytes)
        

        #A recebe o certificado de B
        a_received_cert = channel.receive_at_a()
        handshake_a.peer_cert = x509.load_pem_x509_certificate(a_received_cert)
        

        ########################################
        # --- Step 2: Verificar Certificados ---
        handshake_a.verify_peer_certificate()
        handshake_b.verify_peer_certificate()
        
        # Verifica se A confirmou corretamente que o certificado de B tem o CN esperado
        cn_attr = handshake_a.peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0]
        self.assertEqual(cn_attr.value, "Node B")
        
        #############################################
        # --- Step 3:troca de chaves efemeras ---
        #Ambos geram as suas chaves efêmeras (de curto prazo)
        handshake_a.generate_ephemeral_key()
        handshake_b.generate_ephemeral_key()
        
        #A assina a chave pública efêmera dele e envia para B
        a_pub, a_sig = handshake_a.sign_ephemeral_key()
        channel.send_from_a(a_pub)
        channel.send_from_a(a_sig)
        
        # B recebe e verifica a chave efêmera de A
        b_rx_pub = channel.receive_at_b()
        b_rx_sig = channel.receive_at_b()
        handshake_b.verify_peer_ephemeral_key(b_rx_pub, b_rx_sig)
        
        # B assina a chave pública efêmera dele e envia para A
        b_pub, b_sig = handshake_b.sign_ephemeral_key()
        channel.send_from_b(b_pub)
        channel.send_from_b(b_sig)
        

        # A recebe e verifica a chave efêmera de B
        a_rx_pub = channel.receive_at_a()
        a_rx_sig = channel.receive_at_a()
        handshake_a.verify_peer_ephemeral_key(a_rx_pub, a_rx_sig)
        
        # --- Step 4:Derivação de chaves de sessão ---
        #cada  lado deriva a chave de sessão com base nas chaves efêmeras trocadas
        key_a = handshake_a.derive_session_key()
        key_b = handshake_b.derive_session_key()
        
        # Garantia de que ambos os lados derivaram a mesma chave secreta final
        self.assertIsNotNone(key_a)
        self.assertIsNotNone(key_b)
        self.assertEqual(key_a, key_b)
        print(f"Session Key A: {key_a.hex()}")
        print(f"Session Key B: {key_b.hex()}")

if __name__ == "__main__":
    unittest.main()
