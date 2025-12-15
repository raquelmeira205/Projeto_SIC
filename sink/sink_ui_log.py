
import logging
import sys

def setup_logging(name="Sink"):
    logging.basicConfig(
        level=logging.INFO,
        format=f'[{name}] %(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

class SinkUI:
    def display_status(self, status):
        print(f"STATUS: {status}")

    def log(self, message):
        logging.info(message)
    
    def error(self, message):
        logging.error(message)
