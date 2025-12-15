
import struct
from enum import IntEnum
from .constants import NID_SIZE

class MsgType(IntEnum):
    DATA = 1
    HEARTBEAT = 2
    CONTROL = 3

class PacketHeader:
    # NID_SIZE bytes Source, NID_SIZE bytes Dest, 1 byte Type, 2 bytes Payload Len
    FORMAT = f'!{NID_SIZE}s{NID_SIZE}sBH'
    SIZE = struct.calcsize(FORMAT)

    @staticmethod
    def pack(source_nid: bytes, dest_nid: bytes, msg_type: int, payload: bytes) -> bytes:
        payload_len = len(payload)
        header = struct.pack(
            PacketHeader.FORMAT,
            source_nid,
            dest_nid,
            msg_type,
            payload_len
        )
        return header + payload
    
    @staticmethod
    def unpack(data: bytes):
        if len(data) < PacketHeader.SIZE:
            raise ValueError("Packet too short to contain header")
        
        header_bytes = data[:PacketHeader.SIZE]
        payload_bytes = data[PacketHeader.SIZE:]

        src_nid, dest_nid, msg_type, payload_len = struct.unpack(PacketHeader.FORMAT, header_bytes)

        if len(payload_bytes) < payload_len:
             # It might be a partial read in some contexts, but here we expect full frame or check length
             # For now just warn or return what we have, logic depends on transport
             pass

        return src_nid, dest_nid, msg_type, payload_bytes[:payload_len]

class HeartbeatPayload:
    # 4 bytes sequence number, rest is signature
    @staticmethod
    def pack(sequence_number, signature):
        return struct.pack('!I', sequence_number) + signature

    @staticmethod
    def unpack(payload):
        if len(payload) < 4:
             raise ValueError("Heartbeat payload too short")
        seq_num = struct.unpack('!I', payload[:4])[0]
        signature = payload[4:]
        return seq_num, signature
