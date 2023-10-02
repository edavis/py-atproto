"""
A DAG-CBOR parser for the Authenticated Transfer Protocol (atproto)
"""

# h/t https://gist.github.com/DavidBuchanan314/972266864b54fc9343148b47ed5ee2c2

from io import BytesIO
from base64 import b32encode
from enum import Enum
import hashlib

CID_TAG = 42

class MajorType(Enum):
    UNSIGNED_INT = 0
    NEGATIVE_INT = 1
    BYTE_STRING = 2
    TEXT_STRING = 3
    ARRAY = 4
    MAP = 5
    TAG = 6
    SIMPLE = 7

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
        assert(cid_bytes.startswith((
            b'\x00\x01\x71\x12\x20', # Identity, CIDv1, DAG-CBOR, SHA-256
            b'\x00\x01\x55\x12\x20' # Identity, CIDv1, Raw, SHA-256
        ))), 'malformed CID found'
        return encode_cid(cid_bytes[1:])

    elif major_type == MajorType.SIMPLE:
        return {20: False, 21: True, 22: None}[info]

def encode_cid(val):
    return 'b' + b32encode(val).decode().lower().rstrip('=')

def decode_varint(stream):
    n = 0
    shift = 0
    while True:
        (val,) = stream.read(1)
        n |= (val & 0b0111_1111) << shift
        if val & 0b1000_0000 == 0:
            return n
        shift += 7

def decode_car(stream):
    header_len = decode_varint(stream)
    header_raw = stream.read(header_len)
    car_header = decode_body(BytesIO(header_raw))
    roots = car_header['roots']
    nodes = {}

    while True:
        if not stream.peek(1):
            break

        # Read the block
        block_len = decode_varint(stream)
        block_raw = BytesIO(stream.read(block_len))

        # Make sure we're dealing with CIDv1 (0x01) - DAG-CBOR (0x71) - SHA-256 (0x12 0x20)
        cid_header = block_raw.read(4)
        assert(cid_header.startswith(b'\x01\x71\x12\x20')), 'only CIDv1 - DAG-CBOR - SHA-256 is supported by this implementation'

        # Read the SHA-256 digest bytes and encode as a CID
        cid_raw = b'\x01\x71\x12\x20' + block_raw.read(32)
        cid_safe = encode_cid(cid_raw)

        # Make sure the raw CID SHA-256 bytes match the SHA-256 bytes of the IPLD block
        block_data = block_raw.read()
        content_digest = hashlib.sha256(block_data).digest()
        assert(cid_raw.endswith(content_digest))

        # Parse the block, add to nodes
        block_parsed = decode_body(BytesIO(block_data))
        nodes[cid_safe] = block_parsed

    return roots, nodes

if __name__ == '__main__':
    with open('../test/edavis.car', 'rb') as fp:
        root, nodes = decode_car(fp)
        print(root)
        for k, v in nodes.items():
            print((k, v))
