import unittest
from io import BytesIO
from atproto.cbor import (
    decode_head,
    decode_body,
    decode_varint,
    MajorType,
    CID_TAG
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

    def test_array(self):
        test_table = [
            ('80', 0, []),
            ('83010203', 3, [1, 2, 3]),
            ('8301820203820405', 3, [1, [2, 3], [4, 5]]),
            ('826161a161626163', 2, ["a", {"b": "c"}]),
            ('98190102030405060708090a0b0c0d0e 0f101112131415161718181819', 25, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]),
        ]
        for hex_input, length, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.ARRAY, length))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

    def test_map(self):
        test_table = [
            ('a0', 0, {}),
            ('a201020304', 2, {1: 2, 3: 4}),
            ('a26161016162820203', 2, {"a": 1, "b": [2, 3]}),
            ('a5616161416162614261636143616461 4461656145', 5, {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}),
        ]
        for hex_input, length, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.MAP, length))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

    def test_tag(self):
        test_table = [
            ('d82a5825000171122069ea0740f9807a28f4d932c62e7c1c83be055e55072c90266ab3e79df63a365b', 'bafyreidj5idub6mapiupjwjsyyxhyhedxycv4vihfsicm2vt46o7morwlm'),
            ('d82a5825000171122089556551c3926679cc52c72e182a5619056a4727409ee93a26d05ad727ca11f4', 'bafyreiejkvsvdq4smz44yuwhfymcuvqzavveoj2at3utujwqlllspsqr6q'),
        ]
        for hex_input, expected in test_table:
            dh = decode_head(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(dh, (MajorType.TAG, CID_TAG))

            db = decode_body(BytesIO(bytes.fromhex(hex_input)))
            self.assertEqual(db, expected)

    def test_decode_varint(self):
        bs = BytesIO(bytes.fromhex('E5AD04'))
        self.assertEqual(decode_varint(bs), 71_397)
