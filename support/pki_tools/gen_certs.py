import os
import sys
import secrets
import ca_utils

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
    sink_nid = secrets.randbits(128)
    sink_key, sink_cert = ca_utils.issue_certificate(
        ca_key, ca_cert, "Sink Node", is_sink=True, nid=sink_nid
    )
    ca_utils.save_key(sink_key, os.path.join(output_dir, "sink.key"))
    ca_utils.save_cert(sink_cert, os.path.join(output_dir, "sink.crt"))
    print(f"Sink pronto (NID: {sink_nid}).")


    # ----- Nodes A-E -----
    nodes = ["NodeA", "NodeB", "NodeC", "NodeD", "NodeE"]
    
    for node_name in nodes:
        print(f"A gerar certificado {node_name}...")
        nid = secrets.randbits(128)
        key, cert = ca_utils.issue_certificate(
            ca_key, ca_cert, node_name, is_sink=False, nid=nid
        )
        ca_utils.save_key(key, os.path.join(output_dir, f"{node_name}.key"))
        ca_utils.save_cert(cert, os.path.join(output_dir, f"{node_name}.crt"))
        print(f"{node_name} pronto (NID: {nid}).")

if __name__ == "__main__":
    main()
