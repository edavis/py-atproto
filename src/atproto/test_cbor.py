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

    def test_byte_string(self):
        test_table = [
            ('40', 0, b''),
            ('4401020304', 4, b'\x01\x02\x03\x04'),
            ('59 01 F4' + '00'*500, 500, b'\x00'*500),
        ]
        for hex_input, length, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.BYTE_STRING, length))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

        # raise EOFError if we haven't read argument number of bytes
        with self.assertRaises(EOFError):
            bs = BytesIO(bytes.fromhex('58 80'))
            decode_body(bs)

    def test_text_string(self):
        test_table = [
            ('60', 0, ''),
            ('6161', 1, 'a'),
            ('6449455446', 4, 'IETF'),
            ('62225c', 2, "\"\\"),
            ('62c3bc', 2, '\u00fc'),
            ('63e6b0b4', 3, '\u6c34'),
            ('64f0908591', 4, '\U00010151'),
        ]
        for hex_input, length, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.TEXT_STRING, length))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

        with self.assertRaises(EOFError):
            bs = BytesIO(bytes.fromhex('61'))
            decode_body(bs)
