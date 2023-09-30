import unittest
from io import BytesIO
from atproto.cbor import (
    decode_head,
    decode_body,
    MajorType
)

class TestCBOR(unittest.TestCase):
    def test_unsigned_int(self):
        test_table = [
            ('0A', 10),
            ('18 80', 128),
            ('19 01F4', 500),
            ('1A 80000000', 2147483648),
            ('1B 80000000 00000000', 9223372036854775808),
        ]
        for hex_input, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.UNSIGNED_INT, expected))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

    def test_negative_int(self):
        test_table = [
            ('37', -24),
            ('38 80', -129),
            ('39 01F3', -500),
            ('3A 80000000', -2147483649),
            ('3B 80000000 00000000', -9223372036854775809),
        ]
        for hex_input, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.NEGATIVE_INT, expected))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

    def test_decode_head_byte_string(self):
        test_table = [
            ('40', 0),
            ('58 80', 128),
            ('59 8000', 32768),
            ('5A 80000000', 2147483648),
            ('5B 80000000 00000000', 9223372036854775808),
        ]
        for hex_input, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.BYTE_STRING, expected))

    def test_decode_body_byte_string(self):
        test_table = [
            ('40', b''),
            ('44 DEADBEEF', b'\xde\xad\xbe\xef'),
            ('58 FF' + '00'*255, b'\x00'*255),
        ]
        for hex_input, expected in test_table:
            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

        # raise EOFError if we haven't read argument number of bytes
        with self.assertRaises(EOFError):
            bs = BytesIO(bytes.fromhex('58 80'))
            decode_body(bs)
