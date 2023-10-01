"""
A DAG-CBOR parser for the Authenticated Transfer Protocol (atproto)
"""

# h/t https://gist.github.com/DavidBuchanan314/972266864b54fc9343148b47ed5ee2c2

from base64 import b32encode
from enum import Enum

CID_TAG = 42

class MajorType(Enum):
    UNSIGNED_INT = 0
    NEGATIVE_INT = 1
    BYTE_STRING = 2
    TEXT_STRING = 3
    ARRAY = 4
    MAP = 5
    TAG = 6

def decode_head(stream):
    (stream_head,) = stream.read(1)
    major_type = MajorType(stream_head >> 5)
    additional_info = stream_head & 0x1F

    if additional_info < 24:
        if major_type == MajorType.NEGATIVE_INT:
            return major_type, -1 - additional_info
        else:
            return major_type, additional_info

    byte_lengths = {24: 1, 25: 2, 26: 4, 27: 8}
    if additional_info in byte_lengths:
        byte_value = stream.read(byte_lengths[additional_info])
        if major_type == MajorType.NEGATIVE_INT:
            return major_type, -1 - int.from_bytes(byte_value, 'big')
        else:
            return major_type, int.from_bytes(byte_value, 'big')

def decode_body(stream):
    major_type, info = decode_head(stream)

    if major_type in {MajorType.UNSIGNED_INT, MajorType.NEGATIVE_INT}:
        return info

    elif major_type in {MajorType.BYTE_STRING, MajorType.TEXT_STRING}:
        value = stream.read(info)
        if len(value) != info:
            raise EOFError()

        if major_type == MajorType.BYTE_STRING:
            return value
        elif major_type == MajorType.TEXT_STRING:
            return value.decode('utf-8')

    elif major_type == MajorType.ARRAY:
        values = []
        for _ in range(info):
            values.append(decode_body(stream))
        return values

    elif major_type == MajorType.MAP:
        values = {}
        for _ in range(info):
            key = decode_body(stream)
            value = decode_body(stream)
            values.update({key: value})
        return values

    elif major_type == MajorType.TAG:
        assert(info == CID_TAG), 'only CID (42) tags are supported'
        cid_bytes = decode_body(stream)
        assert(type(cid_bytes) is bytes), 'CID is not a byte string'
        assert(len(cid_bytes) == 37), 'invalid CID byte length found'
        assert(cid_bytes.startswith(b'\x00\x01\x71\x12\x20')), 'malformed CID found' # Multibase Identity, CIDv1, DAG-CBOR, SHA256
        return 'b' + b32encode(cid_bytes[1:]).decode().lower().rstrip('=')

def decode_varint(stream):
    n = 0
    shift = 0
    while True:
        (val,) = stream.read(1)
        n |= (val & 0b0111_1111) << shift
        if val & 0b1000_0000 == 0:
            return n
        shift += 7
