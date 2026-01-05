import os
import sys

#importar o módulo ca_utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pki_tools import ca_utils

def main():
    output_dir = "certs"

    #Cria a pasta dos certificados se ainda não existir
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # ----- CA -----
    print("A gerar CA...")
    ca_key, ca_cert = ca_utils.criar_ca()
    ca_utils.guardar_chave(ca_key, os.path.join(output_dir, "ca.key"))
    ca_utils.guardar_cert(ca_cert, os.path.join(output_dir, "ca.crt"))
    print("CA pronta.")


    # ----- Sink -----
    print("A gerar certificado Sink...")
    sink_key, sink_cert = ca_utils.emitir_certificado(
        ca_key, ca_cert, "Sink Node", is_sink=True, nid=0
    )
    ca_utils.guardar_chave(sink_key, os.path.join(output_dir, "sink.key"))
    ca_utils.guardar_cert(sink_cert, os.path.join(output_dir, "sink.crt"))
    print("Sink pronto.")


    # ----- Node A -----
    print("A gerar certificado Node A...")
    node_a_key, node_a_cert = ca_utils.emitir_certificado(
        ca_key, ca_cert, "Node A", is_sink=False, nid=1
    )
    ca_utils.guardar_chave(node_a_key, os.path.join(output_dir, "nodeA.key"))
    ca_utils.guardar_cert(node_a_cert, os.path.join(output_dir, "nodeA.crt"))
    print("Node A pronto.")


    # ----- Node B -----
    print("A gerar certificado Node B...")
    node_b_key, node_b_cert = ca_utils.emitir_certificado(
        ca_key, ca_cert, "Node B", is_sink=False, nid=2
    )
    ca_utils.guardar_chave(node_b_key, os.path.join(output_dir, "nodeB.key"))
    ca_utils.guardar_cert(node_b_cert, os.path.join(output_dir, "nodeB.crt"))
    print("Node B pronto.")

    # ----- Node C -----
    print("A gerar certificado Node C...")
    node_c_key, node_c_cert = ca_utils.emitir_certificado(
        ca_key, ca_cert, "Node C", is_sink=False, nid=3
    )
    ca_utils.guardar_chave(node_c_key, os.path.join(output_dir, "nodeC.key"))
    ca_utils.guardar_cert(node_c_cert, os.path.join(output_dir, "nodeC.crt"))
    print("Node C pronto.")

    # ----- Node D -----
    print("A gerar certificado Node D...")
    node_d_key, node_d_cert = ca_utils.emitir_certificado(
        ca_key, ca_cert, "Node D", is_sink=False, nid=4
    )
    ca_utils.guardar_chave(node_d_key, os.path.join(output_dir, "nodeD.key"))
    ca_utils.guardar_cert(node_d_cert, os.path.join(output_dir, "nodeD.crt"))
    print("Node D pronto.")

    # ----- Node E -----
    print("A gerar certificado Node E...")
    node_e_key, node_e_cert = ca_utils.emitir_certificado(
        ca_key, ca_cert, "Node E", is_sink=False, nid=5
    )
    ca_utils.guardar_chave(node_e_key, os.path.join(output_dir, "nodeE.key"))
    ca_utils.guardar_cert(node_e_cert, os.path.join(output_dir, "nodeE.crt"))
    print("Node E pronto.")

if __name__ == "__main__":
    main()
