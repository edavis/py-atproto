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
            ('00', 0),
            ('01', 1),
            ('0a', 10),
            ('17', 23),
            ('1818', 24),
            ('1819', 25),
            ('1864', 100),
            ('1903e8', 1000),
            ('1a000f4240', 1000000),
            ('1b000000e8d4a51000', 1000000000000),
            ('1bffffffffffffffff', 18446744073709551615),
        ]
        for hex_input, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.UNSIGNED_INT, expected))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

    def test_negative_int(self):
        test_table = [
            ('20', -1),
            ('29', -10),
            ('3863', -100),
            ('3903e7', -1000),
            ('3bffffffffffffffff', -18446744073709551616),
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
            ('59 01 F4', 500),
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
            ('59 01 F4' + '00'*500, b'\x00'*500),
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
