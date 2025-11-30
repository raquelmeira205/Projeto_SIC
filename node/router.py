import time

class Router:
    def __init__(self, my_nid):
        self.my_nid = my_nid
        self.forwarding_table = {}
        self.uplink_connection = None
        self.downlink_connections = set()

    def add_route(self, source_nid, connection_handle):
        if source_nid not in self.forwarding_table:
            print(f"[Router] Nova rota aprendida: {source_nid.hex()} via {connection_handle}")
            self.forwarding_table[source_nid] = connection_handle
        elif self.forwarding_table[source_nid] != connection_handle:
            print(f"[Router] Rota atualizada: {source_nid.hex()} agora via {connection_handle}")
            self.forwarding_table[source_nid] = connection_handle

    def get_route(self, dest_nid):
        if dest_nid == self.my_nid:
            return "SELF"
            
        if dest_nid in self.forwarding_table:
            return self.forwarding_table[dest_nid]

        return self.uplink_connection

    def remove_connection(self, connection_handle):
        nids_to_remove = []
        for nid, conn in self.forwarding_table.items():
            if conn == connection_handle:
                nids_to_remove.append(nid)
        
        for nid in nids_to_remove:
            del self.forwarding_table[nid]
        
        if connection_handle == self.uplink_connection:
            self.uplink_connection = None
            print("[Router] UPLINK PERDIDO!")

        if connection_handle in self.downlink_connections:
            self.downlink_connections.remove(connection_handle)