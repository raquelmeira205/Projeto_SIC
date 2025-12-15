
from abc import ABC, abstractmethod

class ForwardingTable(ABC):
    @abstractmethod
    def add_route(self, dest_nid, next_hop, cost):
        pass

    @abstractmethod
    def get_route(self, dest_nid):
        """Returns next_hop for dest_nid"""
        pass

    @abstractmethod
    def remove_route(self, dest_nid):
        pass
        
    @abstractmethod
    def clear(self):
        pass
