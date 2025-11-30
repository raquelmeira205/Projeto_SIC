import struct
from enum import IntEnum

class MsgType(IntEnum):
    DATA = 1
    HEARTBEAT = 2
    CONTROL = 3

NID_SIZE = 16

class PacketHeader:
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
            raise ValueError("Pacote demasiado curto")
        
        header_bytes = data[:PacketHeader.SIZE]
        payload_bytes = data[PacketHeader.SIZE:]

        src_nid, dest_nid, msg_type, payload_len = struct.unpack(PacketHeader.FORMAT, header_bytes)

        if len(payload_bytes) != payload_len:
            print(f"Aviso: Tamanho do payload ({len(payload_bytes)}) difere do declarado ({payload_len})")

        return src_nid, dest_nid, msg_type, payload_bytes