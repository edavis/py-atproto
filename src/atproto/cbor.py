from enum import Enum

class MajorType(Enum):
    UNSIGNED_INT = 0
    NEGATIVE_INT = 1
    BYTE_STRING = 2

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
        return major_type, int.from_bytes(byte_value, 'big')

def decode_body(stream):
    major_type, info = decode_head(stream)

    if major_type in {MajorType.UNSIGNED_INT, MajorType.NEGATIVE_INT}:
        return info

    elif major_type == MajorType.BYTE_STRING:
        value = stream.read(info)
        if len(value) != info:
            raise EOFError()
        return value
