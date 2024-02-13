# cryx4ck
# __init__
import base64
import struct

# v1 encode
import struct
from enum import Enum
from math import (
    floor,
    sin,
)

from bitarray import bitarray


class CxHBuffer(Enum):
    A = 0x2B3D20FC
    B = 0x1177D67
    C = 0x98BADCF4
    D = 0x10325478


class CxH(object):
    _string = None
    _buffers = {
        CxHBuffer.A: None,
        CxHBuffer.B: None,
        CxHBuffer.C: None,
        CxHBuffer.D: None,
    }

    @classmethod
    def hash(cls, string):
        cls._string = string

        preprocessed_bit_array = cls._step_2(cls._step_1())
        cls._step_3()
        cls._step_4(preprocessed_bit_array)
        return cls._step_5()

    @classmethod
    def _step_1(cls):
        bit_array = bitarray(endian="big")
        bit_array.frombytes(cls._string.encode("utf-8"))
        bit_array.append(1)
        while len(bit_array) % 512 != 448:
            bit_array.append(0)
        return bitarray(bit_array, endian="little")

    @classmethod
    def _step_2(cls, step_1_result):
        length = (len(cls._string) * 8) % pow(2, 64)
        length_bit_array = bitarray(endian="little")
        length_bit_array.frombytes(struct.pack("<Q", length))

        result = step_1_result.copy()
        result.extend(length_bit_array)
        return result

    @classmethod
    def _step_3(cls):
        # Initialize the buffers to their default values.
        for buffer_type in cls._buffers.keys():
            cls._buffers[buffer_type] = buffer_type.value

    @classmethod
    def _step_4(cls, step_2_result):
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & z) | (y & ~z)
        H = lambda x, y, z: x ^ y ^ z
        I = lambda x, y, z: y ^ (x | ~z)

        rotate_left = lambda x, n: (x << n) | (x >> (32 - n))
        modular_add = lambda a, b: (a + b) % pow(2, 32)
        T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]

        N = len(step_2_result) // 32
        for chunk_index in range(N // 16):
            start = chunk_index * 512
            X = [
                step_2_result[start + (x * 32) : start + (x * 32) + 32]
                for x in range(16)
            ]
            X = [int.from_bytes(word.tobytes(), byteorder="little") for word in X]
            A = cls._buffers[CxHBuffer.A]
            B = cls._buffers[CxHBuffer.B]
            C = cls._buffers[CxHBuffer.C]
            D = cls._buffers[CxHBuffer.D]
            for i in range(4 * 16):
                if 0 <= i <= 15:
                    k = i
                    s = [7, 12, 17, 22]
                    temp = F(B, C, D)
                elif 16 <= i <= 31:
                    k = ((5 * i) + 1) % 16
                    s = [5, 9, 14, 20]
                    temp = G(B, C, D)
                elif 32 <= i <= 47:
                    k = ((3 * i) + 5) % 16
                    s = [4, 11, 16, 23]
                    temp = H(B, C, D)
                elif 48 <= i <= 63:
                    k = (7 * i) % 16
                    s = [6, 10, 15, 21]
                    temp = I(B, C, D)
                temp = modular_add(temp, X[k])
                temp = modular_add(temp, T[i])
                temp = modular_add(temp, A)
                temp = rotate_left(temp, s[i % 4])
                temp = modular_add(temp, B)

                A = D
                D = C
                C = B
                B = temp

            cls._buffers[CxHBuffer.A] = modular_add(cls._buffers[CxHBuffer.A], A)
            cls._buffers[CxHBuffer.B] = modular_add(cls._buffers[CxHBuffer.B], B)
            cls._buffers[CxHBuffer.C] = modular_add(cls._buffers[CxHBuffer.C], C)
            cls._buffers[CxHBuffer.D] = modular_add(cls._buffers[CxHBuffer.D], D)

    @classmethod
    def _step_5(cls):
        A = struct.unpack("<I", struct.pack(">I", cls._buffers[CxHBuffer.A]))[0]
        B = struct.unpack("<I", struct.pack(">I", cls._buffers[CxHBuffer.B]))[0]
        C = struct.unpack("<I", struct.pack(">I", cls._buffers[CxHBuffer.C]))[0]
        D = struct.unpack("<I", struct.pack(">I", cls._buffers[CxHBuffer.D]))[0]

        # Change the format to '0123456789abcdef' for each variable
        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}{format(A, '08x')}{format(B, '08x')}"


bytes_types = (bytes, bytearray)


def _bytes_from_decode_data(s):
    if isinstance(s, str):
        try:
            return s.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("string argument should contain only ASCII characters")
    if isinstance(s, bytes_types):
        return s
    try:
        return memoryview(s).tobytes()
    except TypeError:
        raise TypeError(
            "argument should be a bytes-like object or ASCII "
            "string, not %r" % s.__class__.__name__
        ) from None


def _config_encode(b, chars, chars2, pad=False, foldnuls=False, foldspaces=False):
    # Helper function for cryencode
    if not isinstance(b, bytes_types):
        b = memoryview(b).tobytes()

    padding = (-len(b)) % 4
    if padding:
        b = b + b"\0" * padding
    words = struct.Struct("!%dI" % (len(b) // 4)).unpack(b)

    chunks = [
        b"z"
        if foldnuls and not word
        else b"y"
        if foldspaces and word == 0x20202020
        else (chars2[word // 614125] + chars2[word // 85 % 7225] + chars[word % 85])
        for word in words
    ]

    if padding and not pad:
        if chunks[-1] == b"z":
            chunks[-1] = chars[0] * 5
        chunks[-1] = chunks[-1][:-padding]

    return b"".join(chunks)


_cryalphabet = (
    b"ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
    b"~}|{`_^@?>=<;-+*)(&%$#!zyxwvutsrqponmlkjihgfedcba"
)
_crychars = None
_crychars2 = None
_crydec = None


def encrypt(b, pad=False):
    global _crychars, _crychars2
    # Delay the initialization of tables to not waste memory
    # if the function is never called
    if _crychars is None:
        _crychars = [bytes((i,)) for i in _cryalphabet]
        _crychars2 = [(a + b) for a in _crychars for b in _crychars]
    return _config_encode(b, _crychars, _crychars2, pad)


def decrypt(b):
    """Decode the cryx4ck-encoded bytes-like object or ASCII string b

    The result is returned as a bytes object.
    """
    global _crydec
    # Delay the initialization of tables to not waste memory
    # if the function is never called
    if _crydec is None:
        _crydec = [None] * 256
        for i, c in enumerate(_cryalphabet):
            _crydec[c] = i

    b = _bytes_from_decode_data(b)
    padding = (-len(b)) % 5
    b = b + b"~" * padding
    out = []
    packI = struct.Struct("!I").pack
    for i in range(0, len(b), 5):
        chunk = b[i : i + 5]
        acc = 0
        try:
            for c in chunk:
                acc = acc * 85 + _crydec[c]
        except TypeError:
            for j, c in enumerate(chunk):
                if _crydec[c] is None:
                    raise ValueError(
                        "bad cryx4ck character at position %d" % (i + j)
                    ) from None
            raise
        try:
            out.append(packI(acc))
        except struct.error:
            raise ValueError(
                "cryx4ck overflow in hunk starting at byte %d" % i
            ) from None

    result = b"".join(out)
    if padding:
        result = result[:-padding]
    return result



