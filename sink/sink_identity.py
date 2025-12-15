
import logging
from common.certificate_parser import read_nid_from_cert, load_cert, load_key

class SinkIdentity:
    def __init__(self, cert_path, key_path):
        self.cert_path = cert_path
        self.key_path = key_path
        self._nid = None
        self._cert = None
        self._key = None

    def load(self):
        logging.info(f"Loading identity from {self.cert_path}")
        try:
            self._cert = load_cert(self.cert_path)
            self._key = load_key(self.key_path)
            self._nid = read_nid_from_cert(self._cert)
            logging.info(f"Identity loaded. NID: {self._nid}")
            return True
        except Exception as e:
            logging.error(f"Failed to load identity: {e}")
            return False

    @property
    def nid(self):
        return self._nid

    @property
    def certificate(self):
        return self._cert

    @property
    def private_key(self):
        return self._key
