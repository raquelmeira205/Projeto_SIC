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
    ca_key, ca_cert = ca_utils.create_ca()
    ca_utils.save_key(ca_key, os.path.join(output_dir, "ca.key"))
    ca_utils.save_cert(ca_cert, os.path.join(output_dir, "ca.crt"))
    print("CA pronta.")


    # ----- Sink -----
    print("A gerar certificado Sink...")
    sink_key, sink_cert = ca_utils.issue_certificate(
        ca_key, ca_cert, "Sink Node", is_sink=True, nid=0
    )
    ca_utils.save_key(sink_key, os.path.join(output_dir, "sink.key"))
    ca_utils.save_cert(sink_cert, os.path.join(output_dir, "sink.crt"))
    print("Sink pronto.")


    # ----- Node A -----
    print("A gerar certificado Node A...")
    node_a_key, node_a_cert = ca_utils.issue_certificate(
        ca_key, ca_cert, "Node A", is_sink=False, nid=1
    )
    ca_utils.save_key(node_a_key, os.path.join(output_dir, "nodeA.key"))
    ca_utils.save_cert(node_a_cert, os.path.join(output_dir, "nodeA.crt"))
    print("Node A pronto.")


    # ----- Node B -----
    print("A gerar certificado Node B...")
    node_b_key, node_b_cert = ca_utils.issue_certificate(
        ca_key, ca_cert, "Node B", is_sink=False, nid=2
    )
    ca_utils.save_key(node_b_key, os.path.join(output_dir, "nodeB.key"))
    ca_utils.save_cert(node_b_cert, os.path.join(output_dir, "nodeB.crt"))
    print("Node B pronto.")

if __name__ == "__main__":
    main()
