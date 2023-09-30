import unittest
from io import BytesIO
from atproto.cbor import decode_head, MajorType

class TestCBOR(unittest.TestCase):
    def test_decode_head_unsigned_int(self):
        test_table = [
            ('0A', 10),
            ('18 01', 1),
            ('19 01F4', 500),
            ('1A 00000001', 1),
            ('1B 00000000 00000001', 1),
        ]
        for hex_input, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.UNSIGNED_INT, expected))

    def test_decode_head_negative_int(self):
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
