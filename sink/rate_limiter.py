import time
from common.packet_structs import MsgType

class TokenBucket:
    """Implementação do algoritmo Token Bucket para limitação de taxa."""
    
    def __init__(self, capacity, refill_rate):
        """
        Inicializa o balde de tokens.
        
        :param capacity: Capacidade máxima de tokens.
        :param refill_rate: Taxa de reabastecimento (tokens por segundo).
        """
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate 
        self.last_update = time.time()

    def consume(self, tokens=1):
        """
        Tenta consumir tokens do balde.
        
        :param tokens: Quantidade de tokens a consumir.
        :return: True se houver tokens suficientes, False caso contrário.
        """
        now = time.time()
        elapsed = now - self.last_update
        
        added_tokens = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + added_tokens)
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        else:
            return False

class RateLimiter:
    """
    Controlador de taxa de mensagens (Rate Limiter).
    Limita o tráfego de entrada com base no tipo de mensagem e origem (NID).
    """
    
    def __init__(self):
        self.DEFAULT_LIMIT = (10, 5.0) 
        
        self.limits_config = {
             MsgType.DATA: (20, 10.0),      
             MsgType.HEARTBEAT: (5, 0.5),   
             MsgType.CONTROL: (5, 1.0),
             MsgType.DTLS_HANDSHAKE: (10, 2.0)
        }
        
        self.buckets = {} 
        
    def check_rate_limit(self, nid_bytes, msg_type):
        """
        Verifica se uma mensagem de um determinado NID e tipo pode passar.
        
        :param nid_bytes: NID da origem.
        :param msg_type: Tipo da mensagem.
        :return: True se permitida, False se bloqueada.
        """
        if not nid_bytes:
            return True 
            
        if nid_bytes not in self.buckets:
            self.buckets[nid_bytes] = {}
            
        node_buckets = self.buckets[nid_bytes]
        
        if msg_type not in node_buckets:
            capacity, rate = self.limits_config.get(msg_type, self.DEFAULT_LIMIT)
            node_buckets[msg_type] = TokenBucket(capacity, rate)
            
        return node_buckets[msg_type].consume(1)

    def cleanup(self, max_idle_time=300):
        pass
